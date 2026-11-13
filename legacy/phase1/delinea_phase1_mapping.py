#!/usr/bin/env python3
"""
Delinea Secret Server -> CyberArk Privilege Cloud migration
PHASE 1: Offline Mapping Generation

Reads a Delinea Secret Server CSV export (multi-template / multi-header format),
flattens it into one unified record set, works out a target CyberArk Safe for
every secret using administrator-defined access-group rules (RBAC flattening),
sanitizes Safe names to CyberArk limits, and writes review files for a human to
check before Phase 2 (online API execution).

No network calls are made. Standard library only (Python 3.8+).

Outputs (in --output-dir):
  Migration_Review.csv       one row per secret: target columns + original Delinea metadata
                             (no secret values; Phase 2 fetches them from the Delinea API)
  Safes_Review.csv           one row per target Safe: name validation, account counts
  Safe_Members_Review.csv    one row per Safe/member: Delinea permission -> CyberArk role

Usage:
  python delinea_phase1_mapping.py --write-default-config mapping_config.json
  python delinea_phase1_mapping.py --input export.csv --config mapping_config.json \
      [--permissions permissions.csv] [--output-dir out]
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

log = logging.getLogger("phase1")

# --------------------------------------------------------------------------- #
# Default configuration. Write it out with --write-default-config and edit it.
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {
    "safe_name": {
        "max_length": 28,
        # Characters CyberArk does not allow in Safe names.
        "invalid_chars": "\\/:*?\"<>|",
        "replacement": "-",
        # Optional prefix applied to every derived Safe name, e.g. "DL-".
        "prefix": "",
    },
    # RBAC flattening, evaluated in order; first match wins for each secret.
    # Match on the Delinea access groups that hold permissions on the secret
    # (from --permissions). "group" is an exact, case-insensitive match;
    # "group_pattern" is a regex and "{1}", "{2}" ... in "safe" insert capture groups.
    # "min_permission" (List|View|Edit|Owner) ignores groups with weaker access.
    "group_rules": [
        # {"group": "CORP\\Unix-Admins", "safe": "UNIX-Admins"},
        # {"group_pattern": "^CORP\\\\APP-(.+)-Owners$", "safe": "APP-{1}", "min_permission": "Owner"}
    ],
    # Optional: map a Delinea folder (and its subfolders) straight to a Safe.
    # Used only when no group rule matched.
    "folder_rules": [
        # {"folder_prefix": "\\Infrastructure\\Network", "safe": "NET-Devices"}
    ],
    # When neither a group nor a folder rule matches:
    #   "folder_leaf"  -> last folder segment          (\IT\Windows\Servers -> Servers)
    #   "folder_path"  -> all segments joined with "-" (\IT\Windows\Servers -> IT-Windows-Servers)
    #   "unmapped"     -> literal "UNMAPPED" (forces a decision)
    "fallback_strategy": "folder_leaf",
    # Delinea template name -> CyberArk Platform ID (case-insensitive).
    "platform_map": {
        "Active Directory Account": "WinDomain",
        "Windows Account": "WinServerLocal",
        "Unix Account (SSH)": "UnixSSH",
        "Unix Account (SSH Key Rotation)": "UnixSSHKeys",
        "SQL Server Account": "MSSql",
        "Oracle Account": "Oracle",
        "Web Password": "GenericWebApp",
        "Password": "GenericWebApp",
    },
    "default_platform": "UNMAPPED_PLATFORM",
    # Templates whose secret is an SSH key rather than a password.
    "key_templates": ["Unix Account (SSH Key Rotation)", "SSH Key", "Unix Account (SSH Key)"],
    # Column name aliases, tried in order (case-insensitive).
    "field_aliases": {
        "secret_name": ["Secret Name", "SecretName", "Name"],
        "folder": ["Folder Path", "Folder", "FolderPath"],
        "secret_id": ["Secret ID", "SecretId", "Id"],
        "template": ["Secret Template", "Template", "Template Name"],
        "address": ["Machine", "Server", "Host", "Hostname", "Host Name", "Domain",
                    "URL", "Address", "IP Address", "Resource"],
        "username": ["Username", "User Name", "UserName", "Login", "Account"],
        "password": ["Password", "Secret", "Passphrase"],
        "private_key": ["Private Key", "PrivateKey", "SSH Private Key"],
    },
    # Header cells that identify a header row in the multi-header export.
    "header_markers": ["Secret Name", "SecretName"],
    # File attachments are not migrated. Columns matching these regexes are dropped.
    "exclude_field_patterns": [r"\battach", r"\bfiles?\b", r"\.(ppk|pem|key|pfx|p12|crt|cer)$"],
    # Delinea field slug that holds the secret, per template (Phase 2 fetches it by API).
    # Slugs are visible in Secret Server under Admin > Secret Templates > Fields.
    "secret_field_slugs": {
        "Unix Account (SSH Key Rotation)": "private-key",
    },
    "default_secret_field": "password",
    "key_secret_field": "private-key",
    # Columns holding secret values. They are never written to any output.
    "secret_column_patterns": [r"password", r"passphrase", r"private ?key", r"^secret$", r"^pin$"],
    # Delinea permission -> CyberArk Safe member role (consumed by Phase 2).
    "permission_map": {
        "Owner": "Owner",
        "Edit": "Editor",
        "View": "User",
        "List": "Viewer",
    },
}

PERMISSION_RANK = {"list": 1, "view": 2, "edit": 3, "owner": 4}

# Characters CyberArk rejects in account names.
ACCOUNT_NAME_INVALID = re.compile(r'[\\/:*?"<>|\t]')


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path:
        with open(path, encoding="utf-8") as fh:
            user = json.load(fh)
        for key, value in user.items():
            if key.startswith("_"):
                continue
            if isinstance(value, dict) and isinstance(cfg.get(key), dict) and key != "platform_map":
                cfg[key].update(value)
            else:
                cfg[key] = value
    return cfg


def write_default_config(path):
    out = OrderedDict()
    out["_comment"] = ("Phase 1 mapping config. group_rules decide the target Safe from "
                       "the Delinea access groups on each secret; see script docstring.")
    out.update(DEFAULT_CONFIG)
    out["group_rules"] = [
        {"group": "CORP\\Unix-Admins", "safe": "UNIX-Admins"},
        {"group_pattern": "^CORP\\\\APP-(.+)-Owners$", "safe": "APP-{1}", "min_permission": "Owner"},
    ]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"Wrote default config to {path}")


# --------------------------------------------------------------------------- #
# Delinea multi-header CSV parsing
# --------------------------------------------------------------------------- #
def _is_blank(row):
    return not any(c.strip() for c in row)


def _dedupe_headers(headers):
    seen = defaultdict(int)
    out = []
    for h in headers:
        h = h.strip() or "Unnamed"
        seen[h.lower()] += 1
        out.append(h if seen[h.lower()] == 1 else f"{h}_{seen[h.lower()]}")
    return out


def parse_delinea_export(path, cfg, encoding="utf-8-sig"):
    """
    Flatten a Delinea export into a list of dicts.

    The export repeats a header row for each Secret Template, each with its own
    columns. A section may be preceded by a one-cell row holding the template
    name. Every record gets _section, _template and _source_line keys.
    """
    markers = {m.lower() for m in cfg["header_markers"]}
    records = []
    headers = None
    section = 0
    pending_title = None
    template = None

    with open(path, newline="", encoding=encoding) as fh:
        reader = csv.reader(fh)
        lines = [(reader.line_num, row) for row in reader]
    lines = [(n, r) for n, r in lines if not _is_blank(r)]

    def is_header(r):
        return bool(markers.intersection(c.strip().lower() for c in r))

    for idx, (line_no, row) in enumerate(lines):
        if is_header(row):
            headers = _dedupe_headers(row)
            section += 1
            template = pending_title
            pending_title = None
            log.debug("Section %d header at line %d (%s): %s", section, line_no, template, headers)
            continue

        non_empty = [c for c in row if c.strip()]
        next_is_header = idx + 1 < len(lines) and is_header(lines[idx + 1][1])
        if len(non_empty) == 1 and row[0].strip() and next_is_header:
            # Template title row preceding a header row.
            pending_title = non_empty[0].strip()
            continue

        if headers is None:
            log.warning("Line %d: data before any header row, skipped", line_no)
            continue

        if len(row) > len(headers):
            extra = row[len(headers):]
            if any(c.strip() for c in extra):
                log.warning("Line %d: %d more values than headers; extras kept as Extra_N",
                            line_no, len(extra))
            row_headers = headers + [f"Extra_{i + 1}" for i in range(len(extra))]
        else:
            row_headers = headers
            row = row + [""] * (len(headers) - len(row))

        rec = OrderedDict(zip(row_headers, row))
        rec["_section"] = section
        rec["_template"] = template
        rec["_source_line"] = line_no
        records.append(rec)

    log.info("Parsed %d secrets from %d template section(s)", len(records), section)
    return records


def get_field(rec, cfg, logical):
    """Return (column_name, value) for the first alias present with a value."""
    lower = {k.lower(): k for k in rec if not k.startswith("_")}
    first_present = None
    for alias in cfg["field_aliases"].get(logical, []):
        col = lower.get(alias.lower())
        if col is None:
            continue
        if first_present is None:
            first_present = col
        if str(rec[col]).strip():
            return col, rec[col]
    return first_present, ""


def is_excluded_field(name, patterns):
    return any(re.search(p, name, re.IGNORECASE) for p in patterns)


# --------------------------------------------------------------------------- #
# Permissions (Delinea OLAC) loading
# --------------------------------------------------------------------------- #
def normalize_folder(path):
    path = (path or "").strip()
    parts = [p for p in path.split("\\") if p.strip()]
    return "\\" + "\\".join(p.strip() for p in parts) if parts else "\\"


def load_permissions(path, encoding="utf-8-sig"):
    """
    Permissions CSV, one row per principal per object. Columns (case-insensitive):
      Folder Path, Secret Name, Secret ID, Group (or Principal), Permission
    Rows with a Secret ID or Secret Name are secret-level; others are folder-level
    and are inherited by subfolders.
    """
    secret_by_id = defaultdict(list)
    secret_by_key = defaultdict(list)
    folder_perms = defaultdict(list)
    if not path:
        return secret_by_id, secret_by_key, folder_perms

    with open(path, newline="", encoding=encoding) as fh:
        reader = csv.DictReader(fh)
        cols = {c.lower().strip(): c for c in reader.fieldnames or []}

        def col(row, *names):
            for n in names:
                c = cols.get(n.lower())
                if c and row.get(c, "").strip():
                    return row[c].strip()
            return ""

        for row in reader:
            group = col(row, "Group", "Principal", "Group Name", "User/Group")
            perm = col(row, "Permission", "Role", "Access")
            if not group or not perm:
                continue
            entry = (group, perm.title())
            sid = col(row, "Secret ID", "SecretId")
            sname = col(row, "Secret Name", "SecretName")
            folder = normalize_folder(col(row, "Folder Path", "Folder"))
            if sid:
                secret_by_id[sid].append(entry)
            elif sname:
                secret_by_key[(folder.lower(), sname.lower())].append(entry)
            else:
                folder_perms[folder.lower()].append(entry)
    log.info("Loaded permissions: %d secret-level, %d folder-level objects",
             len(secret_by_id) + len(secret_by_key), len(folder_perms))
    return secret_by_id, secret_by_key, folder_perms


def resolve_access(secret_id, secret_name, folder, perms):
    """Return (entries, source). Secret-level wins; else nearest folder ancestor."""
    by_id, by_key, by_folder = perms
    if secret_id and secret_id in by_id:
        return by_id[secret_id], "secret"
    key = (folder.lower(), (secret_name or "").lower())
    if key in by_key:
        return by_key[key], "secret"
    parts = folder.strip("\\").split("\\") if folder != "\\" else []
    for i in range(len(parts), -1, -1):
        candidate = ("\\" + "\\".join(parts[:i])).lower()
        if candidate in by_folder:
            return by_folder[candidate], "folder"
    return [], "none"


# --------------------------------------------------------------------------- #
# Safe resolution and sanitization
# --------------------------------------------------------------------------- #
def match_group_rules(access, cfg):
    """First rule (in config order) matching any group on the secret."""
    for rule in cfg["group_rules"]:
        min_rank = PERMISSION_RANK.get(str(rule.get("min_permission", "list")).lower(), 0)
        for group, perm in access:
            if PERMISSION_RANK.get(perm.lower(), 0) < min_rank:
                continue
            if "group" in rule and group.lower() == rule["group"].lower():
                return rule["safe"], f"group_rule:{rule['group']}"
            if "group_pattern" in rule:
                m = re.search(rule["group_pattern"], group, re.IGNORECASE)
                if m:
                    safe = rule["safe"]
                    for i, g in enumerate(m.groups(), start=1):
                        safe = safe.replace("{%d}" % i, g or "")
                    return safe, f"group_pattern:{rule['group_pattern']}"
    return None, None


def match_folder_rules(folder, cfg):
    best = None
    for rule in cfg["folder_rules"]:
        prefix = normalize_folder(rule["folder_prefix"]).lower()
        f = folder.lower()
        if f == prefix or f.startswith(prefix.rstrip("\\") + "\\") or prefix == "\\":
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, rule["safe"])
    if best:
        return best[1], f"folder_rule:{best[0]}"
    return None, None


def fallback_safe(folder, cfg):
    parts = [p for p in folder.split("\\") if p]
    strategy = cfg["fallback_strategy"]
    if strategy == "unmapped" or not parts:
        return "UNMAPPED", "fallback:unmapped"
    if strategy == "folder_path":
        return "-".join(parts), "fallback:folder_path"
    return parts[-1], "fallback:folder_leaf"


def sanitize_safe_name(name, cfg):
    """Return (sanitized_name, is_valid_as_given, issues)."""
    sc = cfg["safe_name"]
    issues = []
    raw = name or ""
    bad = sorted({c for c in raw if c in sc["invalid_chars"]})
    if bad:
        issues.append("invalid chars " + " ".join(bad))
    s = "".join(sc["replacement"] if c in sc["invalid_chars"] else c for c in raw)
    s = re.sub(r"[\x00-\x1f]", "", s)
    rep = re.escape(sc["replacement"]) if sc["replacement"] else None
    if rep:
        s = re.sub(rep + "{2,}", sc["replacement"], s)
    s = re.sub(r"\s+", " ", s).strip()
    if s != raw and not bad:
        issues.append("whitespace/control chars")
    if not s:
        s = "UNNAMED"
        issues.append("empty name")
    if len(s) > sc["max_length"]:
        issues.append(f"length {len(s)} > {sc['max_length']}")
        s = s[: sc["max_length"]].rstrip(" " + sc["replacement"])
    return s, not issues, issues


def apply_prefix(name, cfg):
    prefix = cfg["safe_name"].get("prefix") or ""
    return name if not prefix or name.startswith(prefix) else prefix + name


def resolve_collisions(proposed_to_safe, cfg):
    """
    Different proposed names can sanitize/truncate to the same Safe name.
    Give later ones a numbered suffix that still fits the length limit.
    Returns {proposed: (final_name, collided_with or None)}.
    """
    max_len = cfg["safe_name"]["max_length"]
    by_target = defaultdict(list)
    for proposed, safe in proposed_to_safe.items():
        by_target[safe.lower()].append((proposed, safe))
    used = {k for k in by_target}
    result = {}
    for _, items in by_target.items():
        first_proposed, first_safe = items[0]
        result[first_proposed] = (first_safe, None)
        n = 2
        for proposed, safe in items[1:]:
            while True:
                suffix = cfg["safe_name"]["replacement"] + str(n) if cfg["safe_name"]["replacement"] else f"-{n}"
                candidate = safe[: max_len - len(suffix)].rstrip() + suffix
                n += 1
                if candidate.lower() not in used:
                    break
            used.add(candidate.lower())
            result[proposed] = (candidate, first_proposed)
    return result


# --------------------------------------------------------------------------- #
# Main transform
# --------------------------------------------------------------------------- #
def build_review(records, cfg, perms, stats):
    platform_map = {k.lower(): v for k, v in cfg["platform_map"].items()}
    key_templates = {t.lower() for t in cfg["key_templates"]}
    excl = cfg["exclude_field_patterns"]
    secret_cols = cfg["secret_column_patterns"]
    slug_map = {k.lower(): v for k, v in cfg["secret_field_slugs"].items()}
    rows = []
    excluded_cols = set()

    for rec in records:
        notes = []
        _, secret_name = get_field(rec, cfg, "secret_name")
        _, folder_raw = get_field(rec, cfg, "folder")
        _, secret_id = get_field(rec, cfg, "secret_id")
        _, template_col = get_field(rec, cfg, "template")
        _, address = get_field(rec, cfg, "address")
        _, username = get_field(rec, cfg, "username")
        folder = normalize_folder(folder_raw)
        template = (template_col or rec["_template"] or f"Section {rec['_section']}").strip()

        # Secret type and the Delinea field Phase 2 will fetch. The value itself
        # is never kept: Phase 2 reads it from the Delinea API at send time.
        pk_col, private_key = get_field(rec, cfg, "private_key")
        pw_col, password = get_field(rec, cfg, "password")
        if private_key.strip() or password.strip():
            stats["plaintext_rows"] += 1
        is_key = template.lower() in key_templates or bool(private_key.strip())
        secret_type = "key" if is_key else "password"
        secret_field = slug_map.get(template.lower()) or \
            (cfg["key_secret_field"] if is_key else cfg["default_secret_field"])
        if pw_col and not is_key and not password.strip():
            notes.append("password field is empty in the source")
        if not secret_id.strip():
            notes.append("no Delinea Secret ID; Phase 2 cannot fetch the secret")
        elif not secret_id.strip().isdigit():
            notes.append(f"Delinea Secret ID '{secret_id}' is not numeric")
        if is_key:
            for k, v in rec.items():
                if "passphrase" in k.lower() and str(v).strip():
                    notes.append(f"key has a passphrase in '{k}'; confirm the target platform handles it")
        if not str(address).strip():
            notes.append("no address")
        if not str(username).strip():
            notes.append("no username")

        # Platform
        platform = platform_map.get(template.lower(), cfg["default_platform"])
        if platform == cfg["default_platform"]:
            notes.append(f"no platform mapping for template '{template}'")

        # Access groups + target Safe (RBAC flattening)
        access, access_src = resolve_access(secret_id.strip(), secret_name.strip(), folder, perms)
        safe, source = match_group_rules(access, cfg)
        if not safe:
            safe, source = match_folder_rules(folder, cfg)
        if not safe:
            safe, source = fallback_safe(folder, cfg)
            notes.append("safe from folder fallback, no group/folder rule matched")
        if access_src == "none":
            notes.append("no Delinea permissions found")
        proposed = apply_prefix(safe, cfg)

        account_name = ACCOUNT_NAME_INVALID.sub("_", secret_name).strip() or \
            f"{address}-{username}".strip("-")

        original = OrderedDict()
        for k, v in rec.items():
            if k.startswith("_"):
                continue
            if is_excluded_field(k, secret_cols):
                continue  # never write secret values to the review files
            if is_excluded_field(k, excl):
                excluded_cols.add(k)
                if str(v).strip():
                    notes.append(f"attachment field '{k}' excluded")
                continue
            original[k] = v

        rows.append({
            "proposed": proposed,
            "source": source,
            "access": access,
            "access_src": access_src,
            "core": OrderedDict([
                ("Migrate", "Y"),
                ("Review_Status", ""),
                ("Review_Notes", ""),
                ("Target CyberArk Safe", ""),
                ("Proposed_Safe_Name", proposed),
                ("Valid_Safe_Name", ""),
                ("Safe_Name_Issues", ""),
                ("Safe_Mapping_Source", source),
                ("Target Platform ID", platform),
                ("Account Name", account_name),
                ("Address", address),
                ("Username", username),
                ("Secret Type", secret_type),
                ("Delinea Secret ID", secret_id.strip()),
                ("Delinea Secret Field", secret_field),
                ("Delinea_Access_Groups", "; ".join(f"{g}={p}" for g, p in access)),
                ("Delinea_Access_Source", access_src),
                ("Delinea_Template", template),
                ("Delinea_Source_Line", rec["_source_line"]),
            ]),
            "notes": notes,
            "original": original,
        })

    if excluded_cols:
        log.info("Excluded attachment columns: %s", ", ".join(sorted(excluded_cols)))

    # Sanitize + de-collide Safe names
    sanitized = {}
    for r in rows:
        if r["proposed"] not in sanitized:
            sanitized[r["proposed"]] = sanitize_safe_name(r["proposed"], cfg)
    final = resolve_collisions({p: s[0] for p, s in sanitized.items()}, cfg)

    # Account names must be unique within a Safe
    seen_accounts = defaultdict(int)
    for r in rows:
        clean, valid, issues = sanitized[r["proposed"]]
        name, collided = final[r["proposed"]]
        issues = list(issues)
        if collided:
            issues.append(f"collided with '{collided}' after sanitizing; suffixed")
            valid = False
        c = r["core"]
        c["Target CyberArk Safe"] = name
        c["Valid_Safe_Name"] = "TRUE" if valid else "FALSE"
        c["Safe_Name_Issues"] = "; ".join(issues)
        if not valid:
            r["notes"].insert(0, "safe name changed: " + "; ".join(issues))

        key = (name.lower(), c["Account Name"].lower())
        seen_accounts[key] += 1
        if seen_accounts[key] > 1:
            c["Account Name"] = f"{c['Account Name']}_{seen_accounts[key]}"
            r["notes"].append("duplicate account name in safe; suffixed")

        c["Review_Notes"] = "; ".join(r["notes"])
        c["Review_Status"] = "REVIEW" if r["notes"] else "OK"

    return rows


def write_outputs(rows, cfg, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Migration_Review.csv
    orig_cols = []
    for r in rows:
        for k in r["original"]:
            if k not in orig_cols:
                orig_cols.append(k)
    core_cols = list(rows[0]["core"].keys()) if rows else []
    review_path = out_dir / "Migration_Review.csv"
    with open(review_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(core_cols + [f"Delinea.{c}" for c in orig_cols])
        for r in rows:
            w.writerow([r["core"][c] for c in core_cols] +
                       [r["original"].get(c, "") for c in orig_cols])

    # Safes_Review.csv
    safes = OrderedDict()
    for r in rows:
        c = r["core"]
        s = safes.setdefault(c["Target CyberArk Safe"], {
            "proposed": set(), "valid": True, "issues": set(), "sources": set(), "count": 0})
        s["proposed"].add(c["Proposed_Safe_Name"])
        s["valid"] &= c["Valid_Safe_Name"] == "TRUE"
        if c["Safe_Name_Issues"]:
            s["issues"].add(c["Safe_Name_Issues"])
        s["sources"].add(c["Safe_Mapping_Source"])
        s["count"] += 1
    safes_path = out_dir / "Safes_Review.csv"
    with open(safes_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Target CyberArk Safe", "Length", "Valid_Safe_Name", "Proposed_Safe_Names",
                    "Safe_Name_Issues", "Mapping_Sources", "Account_Count"])
        for name, s in safes.items():
            w.writerow([name, len(name), "TRUE" if s["valid"] else "FALSE",
                        " | ".join(sorted(s["proposed"])), " | ".join(sorted(s["issues"])),
                        " | ".join(sorted(s["sources"])), s["count"]])

    # Safe_Members_Review.csv: strongest Delinea permission per group per Safe
    pmap = {k.lower(): v for k, v in cfg["permission_map"].items()}
    members = OrderedDict()
    for r in rows:
        safe = r["core"]["Target CyberArk Safe"]
        for group, perm in r["access"]:
            key = (safe, group.lower())
            m = members.setdefault(key, {"group": group, "perm": perm, "secrets": 0, "mixed": set()})
            m["secrets"] += 1
            m["mixed"].add(perm)
            if PERMISSION_RANK.get(perm.lower(), 0) > PERMISSION_RANK.get(m["perm"].lower(), 0):
                m["perm"] = perm
    members_path = out_dir / "Safe_Members_Review.csv"
    with open(members_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Target CyberArk Safe", "Member_Name", "Member_Type", "Delinea_Permission",
                    "CyberArk_Role", "Secrets_With_Access", "Review_Notes"])
        for (safe, _), m in members.items():
            note = ""
            if len(m["mixed"]) > 1:
                note = ("mixed Delinea permissions " + "/".join(sorted(m["mixed"])) +
                        "; highest used, Safe-level RBAC widens access")
            role = pmap.get(m["perm"].lower(), "UNMAPPED_ROLE")
            w.writerow([safe, m["group"], "Group", m["perm"], role, m["secrets"], note])

    return review_path, safes_path, members_path, safes


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase 1: Delinea -> CyberArk offline mapping generation")
    ap.add_argument("--input", help="Delinea Secret Server CSV export")
    ap.add_argument("--config", help="Mapping config JSON (see --write-default-config)")
    ap.add_argument("--permissions", help="Delinea permissions CSV (groups per folder/secret)")
    ap.add_argument("--output-dir", default="phase1_output")
    ap.add_argument("--encoding", default="utf-8-sig", help="Input file encoding (try cp1252 if needed)")
    ap.add_argument("--write-default-config", metavar="PATH", help="Write a starter config and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    if args.write_default_config:
        write_default_config(args.write_default_config)
        return 0
    if not args.input:
        ap.error("--input is required")

    cfg = load_config(args.config)
    records = parse_delinea_export(args.input, cfg, args.encoding)
    if not records:
        log.error("No secrets found. Check header_markers in the config match the export.")
        return 1
    perms = load_permissions(args.permissions, args.encoding)
    stats = {"plaintext_rows": 0}
    rows = build_review(records, cfg, perms, stats)
    review, safes_path, members_path, safes = write_outputs(rows, cfg, args.output_dir)

    review_count = sum(1 for r in rows if r["core"]["Review_Status"] == "REVIEW")
    invalid_safes = sum(1 for s in safes.values() if not s["valid"])
    print()
    print(f"Secrets processed:        {len(rows)}")
    print(f"Rows flagged for REVIEW:  {review_count}")
    print(f"Target Safes:             {len(safes)} ({invalid_safes} with Valid_Safe_Name=FALSE)")
    print(f"Wrote {review}")
    print(f"Wrote {safes_path}")
    print(f"Wrote {members_path}")
    print("The review files hold no secret values; Phase 2 fetches each one from the Delinea API.")
    if stats["plaintext_rows"]:
        print(f"WARNING: the INPUT file has plaintext secret values in {stats['plaintext_rows']} rows. "
              "Securely delete it, and next time use a metadata-only Secret Server report instead "
              "of a full export (see README).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
