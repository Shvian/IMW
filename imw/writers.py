"""Output files: review CSVs (no secrets) and upload CSVs (API body fields)."""

import csv
import hashlib
import json
import os
import platform as _platform
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, csvsafe
from .config import ALL_PERMISSIONS, all_roles
from .transform import safe_settings

# Upload CSV columns, named and ordered like the Privilege Cloud (ISPSS) bulk-upload samples:
# (CSV column, field it holds). The optional columns are added at the end only when a value is set.
SAFE_COLUMNS = [("SafeName", "safeName"), ("Description", "description"), ("Location", "location"),
                ("ManagingCPM", "managingCPM"), ("NumberOfDaysRetention", "numberOfDaysRetention"),
                ("NumberOfVersionsRetention", "numberOfVersionsRetention")]
SAFE_OPTIONAL = [("OlacEnabled", "olacEnabled"), ("AutoPurgeEnabled", "autoPurgeEnabled")]
MEMBER_COLUMNS = ["SafeName", "MemberName", "MemberType"]        # then one column per permission
MEMBER_OPTIONAL = ["SearchIn"]
ACCOUNT_COLUMNS = ["Name", "SafeName", "PlatformId", "UserName", "Address", "SecretType", "Secret",
                   "AutomaticManagement", "ManualManagementReason"]
PROPERTY_PREFIX = "platformAccountProperties."
DEFAULT_LOCATION = "\\"                # the Vault root, as the samples write it


# Accounts.csv column -> Vault file category (what the account stores it as) and a note.
FILE_CATEGORIES = {
    "Name": ("", "Account (object) name in the Safe (not a file category)"),
    "SafeName": ("", "Safe the account is stored in (not a file category)"),
    "PlatformId": ("PolicyID", "Platform ID"),
    "UserName": ("UserName", "Account username"),
    "Address": ("Address", "Target address"),
    "SecretType": ("", "password or key (the type of the account's secret)"),
    "Secret": ("", "The password or private key itself"),
    "AutomaticManagement": ("CPMDisabled", "False sets CPMDisabled on the account"),
    "ManualManagementReason": ("CPMDisabled", "Text stored in CPMDisabled when the CPM does not manage it"),
}


def _category(col):
    if col.startswith(PROPERTY_PREFIX):
        prop = col.split(".", 1)[1]
        return prop, "Platform account property from the source column(s) mapped in account_property_map"
    return FILE_CATEGORIES.get(col, ("", ""))


def write_categories(out, header, rows):
    """FileCategories.csv: every Accounts.csv column and how often it is filled.
    PlatformProperties.csv: per platform, which file categories its accounts use."""
    cols = list(header)
    used = {c: 0 for c in cols}
    per_platform = {}
    for row in rows:
        plat = row["PlatformId"]
        pp = per_platform.setdefault(plat, {"accounts": 0, "cols": {c: 0 for c in cols}})
        pp["accounts"] += 1
        for c in cols:
            if str(row.get(c, "")).strip():
                used[c] += 1
                pp["cols"][c] += 1
    cat_path = out / "FileCategories.csv"
    with _open(cat_path) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        w.writerow(["column", "fileCategory", "accountsWithValue", "accountsTotal", "platforms", "description"])
        for c in cols:
            fc, desc = _category(c)
            plats = sorted(p for p, v in per_platform.items() if v["cols"][c])
            w.writerow([c, fc, used[c], len(rows), "; ".join(plats), desc])
    plat_path = out / "PlatformProperties.csv"
    with _open(plat_path) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        w.writerow(["platformId", "column", "fileCategory", "accountsWithValue", "accountsOnPlatform"])
        for plat in sorted(per_platform):
            v = per_platform[plat]
            for c in cols:
                if v["cols"][c]:
                    w.writerow([plat, c, _category(c)[0], v["cols"][c], v["accounts"]])
    return [cat_path, plat_path]


def _bool(v):
    """Upload CSV booleans: True / False, as the Privilege Cloud samples write them."""
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        v = v.strip().lower() == "true"
    if isinstance(v, bool):
        return "True" if v else "False"
    return "" if v is None else str(v)


def _is_true(v):
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def _open(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return open(path, "w", newline="", encoding="utf-8-sig")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def restrict(path):
    """Owner-only file mode where the OS supports it (POSIX). On Windows rely on folder ACLs."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Review files
# --------------------------------------------------------------------------- #
def write_review(plan, out_dir):
    out = Path(out_dir) / "review"
    extra_cols = []
    for p in plan.accounts:
        for k in p.rec.extra:
            if k not in extra_cols:
                extra_cols.append(k)

    accounts = out / "Accounts_Review.csv"
    with _open(accounts) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh, quoting=csv.QUOTE_ALL))
        w.writerow(["Record_ID", "Migrate", "Status", "Notes", "Target_Safe", "Proposed_Safe_Name",
                    "Valid_Safe_Name", "Safe_Name_Issues", "Safe_Mapping_Source", "Platform_ID",
                    "Platform_Source", "Account_Name", "Address", "Username", "Secret_Type",
                    "Has_Secret", "Source", "Source_Ref", "Source_Type", "Folder", "Access_Groups",
                    "Access_Source"] + [f"Source.{c}" for c in extra_cols])
        for p in plan.accounts:
            r = p.rec
            w.writerow([r.record_id, p.migrate, p.status, "; ".join(p.errors + p.warnings), p.safe,
                        p.proposed_safe, "TRUE" if p.valid_safe else "FALSE",
                        "; ".join(p.safe_issues), p.safe_source, p.platform, p.platform_source,
                        p.account_name, r.address, r.username, r.secret_type,
                        "Y" if (r.has_secret if r.has_secret is not None else r.secret.strip()) else "N", r.source, r.source_ref, r.type,
                        r.folder_path, "; ".join(f"{g.member}={g.permission}" for g in p.grants),
                        p.access_source] + [r.extra.get(c, "") for c in extra_cols])

    safes = out / "Safes_Review.csv"
    with _open(safes) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        w.writerow(["Target_Safe", "Length", "Valid_Safe_Name", "Proposed_Safe_Names",
                    "Safe_Name_Issues", "Mapping_Sources", "Accounts", "Accounts_To_Upload"])
        for name, s in plan.safes.items():
            w.writerow([name, len(name), "TRUE" if s["valid"] else "FALSE",
                        " | ".join(sorted(s["proposed"])), " | ".join(sorted(s["issues"])),
                        " | ".join(sorted(s["sources"])), s["accounts"], s["migrating"]])

    members = out / "SafeMembers_Review.csv"
    with _open(members) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        w.writerow(["Target_Safe", "Source_Member", "Member_Name", "Search_In", "Member_Type",
                    "Source_Permission", "Role", "Accounts_With_Access", "Notes"])
        for (safe, _), m in plan.members.items():
            w.writerow([safe, m["source_name"], m["member_name"], m["search_in"], m["member_type"],
                        m["permission"], m["role"] or "UNMAPPED", m["accounts"], "; ".join(m["notes"])])
    files = [accounts, safes, members]
    create = groups_to_create(plan)
    if create:
        path = out / "MemberGroups_To_Create.csv"
        with _open(path) as fh:
            w = csvsafe.SafeWriter(csv.writer(fh))
            w.writerow(["Member_Name", "Member_Type", "Search_In", "Safes", "Roles", "Safe_Names", "Notes"])
            for g in create:
                w.writerow([g["member_name"], g["member_type"], g["search_in"], len(g["safes"]),
                            " | ".join(sorted(g["roles"])), " | ".join(g["safes"]), "; ".join(g["notes"])])
        files.append(path)
    return files


def groups_to_create(plan):
    """The standard member groups and roles (standard_members) to create in the directory
    before the upload: one row per name, with the Safes it goes on. Users are left out."""
    out = OrderedDict()
    for (safe, _), m in plan.members.items():
        if not m.get("standard") or m["member_type"] == "User":
            continue
        g = out.setdefault((m["member_name"].lower(), m["member_type"]), {
            "member_name": m["member_name"], "member_type": m["member_type"], "search_in": m["search_in"],
            "safes": [], "roles": set(), "notes": []})
        g["safes"].append(safe)
        g["roles"].add(m["role"] or "UNMAPPED")
        g["notes"].extend(n for n in m["notes"] if n.startswith("CHECK") and n not in g["notes"])
    return sorted(out.values(), key=lambda g: g["member_name"].lower())


# --------------------------------------------------------------------------- #
# Upload files
# --------------------------------------------------------------------------- #
# Safes.csv, SafeMembers.csv and Accounts.csv are written exactly as the API should get them,
# without csvsafe escaping (that would change the data, e.g. a password starting with '-').
# They are not for Excel; the CLI and Workbench say so.
def write_upload(plan, cfg, out_dir, include_secrets):
    out = Path(out_dir) / "upload"
    upload_safes = [n for n, s in plan.safes.items() if s["migrating"]]

    safes = out / "Safes.csv"
    bodies = [(name, safe_settings(name, plan.safes[name], cfg)) for name in upload_safes]
    safe_cols = SAFE_COLUMNS + [c for c in SAFE_OPTIONAL if any(_is_true(b.get(c[1])) for _, b in bodies)]
    with _open(safes) as fh:
        w = csv.writer(fh)
        w.writerow([c for c, _ in safe_cols])
        for name, body in bodies:
            body = dict(body, safeName=name)
            if not str(body.get("location") or "").strip():
                body["location"] = DEFAULT_LOCATION
            w.writerow([_bool(body.get(f, "")) for _, f in safe_cols])

    members = out / "SafeMembers.csv"
    skipped_members = 0
    roles = all_roles(cfg)
    member_rows = []
    for (safe, _), m in plan.members.items():
        if m["role"] not in roles:
            skipped_members += 1
            continue
        granted = set(roles[m["role"]])
        member_rows.append(([safe, m["member_name"], m["member_type"]] +
                            [_bool(p in granted) for p in ALL_PERMISSIONS], m["search_in"] or ""))
    with_search_in = any(si.strip() for _, si in member_rows)
    with _open(members) as fh:
        w = csv.writer(fh)
        w.writerow(MEMBER_COLUMNS + [p for p in ALL_PERMISSIONS] + (MEMBER_OPTIONAL if with_search_in else []))
        for row, search_in in member_rows:
            w.writerow(row + ([search_in] if with_search_in else []))

    prop_map = cfg["account_property_map"]
    acct_defaults = cfg["account_defaults"]
    auto = acct_defaults.get("automaticManagementEnabled", False)
    reason = "" if _is_true(auto) else acct_defaults.get("manualManagementReason", "")
    accounts = out / "Accounts.csv"
    rows = []
    for p in plan.accounts:
        if not p.uploadable:
            continue
        r = p.rec
        props = {}
        extra_lower = {k.lower(): v for k, v in r.extra.items()}
        for src, dst in prop_map.items():
            val = extra_lower.get(src.lower(), "")
            if val.strip() and not props.get(dst):
                props[dst] = val
        rows.append((p, [p.account_name, p.safe, p.platform, r.username, r.address, r.secret_type,
                         r.secret if include_secrets else "", _bool(auto), reason], props))
    # Property columns only for the platform properties some account has a value for.
    prop_cols = [c for c in dict.fromkeys(prop_map.values()) if any(props.get(c) for _, _, props in rows)]
    header = ACCOUNT_COLUMNS + [PROPERTY_PREFIX + c for c in prop_cols]
    usage = []
    with _open(accounts) as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for p, base, props in rows:
            values = base + [props.get(c, "") for c in prop_cols]
            w.writerow(values)
            row = dict(zip(header, values))
            r = p.rec
            row["Secret"] = "x" if r.has_secret or (r.secret or "").strip() else ""   # usage only, never the value
            usage.append(row)
    if include_secrets:
        restrict(accounts)
    extra_files = write_categories(out, header, usage)
    return [safes, members, accounts] + extra_files, {"safes": len(upload_safes), "members": len(plan.members) -
                                        skipped_members, "members_skipped": skipped_members,
                                        "accounts": len(rows)}


def write_manifest(out_dir, inputs, files, counts, include_secrets, cfg_path):
    manifest = {
        "tool": "Idira Migration Workbench", "version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": _platform.node(),
        "includes_secrets": include_secrets,
        "config": str(cfg_path or "(defaults)"),
        "inputs": [i if isinstance(i, dict) else {"source": i[0], "path": str(i[1]), "sha256": sha256(i[1])}
                   for i in inputs],
        "outputs": [{"path": str(Path(f).relative_to(out_dir)), "sha256": sha256(f)} for f in files],
        "counts": counts,
    }
    path = Path(out_dir) / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Safe naming convention: the rules as a document to keep using after the migration
# --------------------------------------------------------------------------- #
CONVENTION_HEADER = ["Section", "Item", "Code_Or_Value", "Applies_When", "Notes"]
FIELD_WORDS = {"folder_word": "a word in any folder level", "folder_level": "a whole folder level",
               "folder": "the folder path", "platform": "the platform ID", "username": "the username",
               "address": "the address", "address_domain": "the address's domain", "name": "the account name",
               "type": "the record type", "source": "the source", "env": "the {env} code",
               "tech": "the {tech} code", "flavor": "the {flavor} code", "acct": "the {acct} code"}


def _plain_pattern(pattern):
    """A rule pattern in words: ^Boston$ -> 'is Boston', ^svc -> 'starts with svc'."""
    import re
    p = re.sub(r"^\(\?i\)", "", str(pattern or ""))

    def literal(t):
        out, i = "", 0
        while i < len(t):
            c = t[i]
            if c == "\\" and i + 1 < len(t) and not t[i + 1].isalnum():
                out, i = out + t[i + 1], i + 2
                continue
            if c in ".*+?^${}()|[]\\":
                return None
            out, i = out + c, i + 1
        return out
    alts = p.split("|")
    if len(alts) > 1 and all(a.startswith("^") and a.endswith("$") and literal(a[1:-1]) for a in alts):
        vals = [literal(a[1:-1]) for a in alts]
        return ("is one of " + ", ".join(vals)) if len(vals) > 1 else f"is {vals[0]}"
    if p.startswith("^(") and p.endswith(")$") and all(literal(a) for a in p[2:-2].split("|")):
        vals = [literal(a) for a in p[2:-2].split("|")]
        return ("is one of " + ", ".join(vals)) if len(vals) > 1 else f"is {vals[0]}"
    for test, words, core in ((p.startswith("^") and p.endswith("$"), "is", p[1:-1]),
                              (p.startswith("^"), "starts with", p[1:]), (p.endswith("$"), "ends with", p[:-1]),
                              (True, "contains", p)):
        if test and core and literal(core) is not None:
            return f"{words} {literal(core)}"
    return f"matches the pattern {p}"


def _n(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _field_words(field):
    if str(field).startswith("column:"):
        return f"the {field[7:]} column"
    return FIELD_WORDS.get(field, field)


def convention_rows(plan, cfg, examples=25):
    """Every rule that names Safes (and their standard member groups), in plain words, so
    the same convention can name new Safes once Privilege Cloud is live."""
    from .naming import DEFAULT_ABBREVIATIONS, Namer, default_layers, norm
    conv, sn = cfg.get("safe_convention") or {}, cfg["safe_name"]
    sep = conv.get("separator", "-")
    rows = [
        ["Pattern", "Safes for accounts with folders", conv.get("template") or "{folder}",
         "the account is in a folder", "each placeholder becomes a short code; codes are joined with " + repr(sep)],
        ["Pattern", "Safes for accounts without folders", conv.get("template_no_folders") or "",
         "the account has no folder", ""],
        ["Pattern", "Naming", cfg.get("fallback_strategy", "convention"), "no exception below applies",
         "convention = the patterns above; folder_leaf / folder_path = the folder name as is; unmapped = UNMAPPED"],
        ["Limit", "Maximum length", sn["max_length"], "always",
         "too long: long folder names become initials, then the top folder levels are left out, then the end is cut"],
        ["Limit", "Forbidden characters", sn["invalid_chars"], "always", f"each becomes '{sn['replacement']}'"],
        ["Limit", "Prefix", sn.get("prefix") or "(none)", "every Safe", "counts toward the maximum length"],
        ["Limit", "Accounts per Safe", cfg.get("safe_max_accounts") or "(no limit)", "always",
         "over the limit: split into numbered Safes (" + sep + "01, " + sep + "02...) by address"
         if cfg.get("safe_split_over_max") else "over the limit: flagged for a look"],
        ["Limit", "Same name twice", f"{sn['replacement'] or '-'}2, {sn['replacement'] or '-'}3...", "two Safes end up with one name",
         "the later Safe gets the suffix, still within the maximum length"],
        ["Limit", "Repeated codes", "", "a code already appears earlier in the name", "it is left out the second time"],
        ["Placeholder", "{folder}", "", "the account has folders",
         "every folder level, in order, each abbreviated (see Abbreviation rows)"],
        ["Placeholder", "{folder_leaf}", "", "the account has folders", "the last folder level only, abbreviated"],
    ]
    layers = {k: v for k, v in (conv.get("layers") or default_layers()).items()}
    for name, base in default_layers().items():
        layers.setdefault(name, base)
    for name, layer in layers.items():
        label = layer.get("label") or name
        for r in layer.get("rules") or []:
            when = f"{_field_words(r.get('field'))} {_plain_pattern(r.get('pattern'))}"
            if r.get("field2"):
                when += f" and {_field_words(r['field2'])} {_plain_pattern(r.get('pattern2'))}"
            rows.append(["Placeholder", "{%s}" % name, r.get("code") or "(left out)", when, label])
        rows.append(["Placeholder", "{%s}" % name, layer.get("default") or "(left out)", "no row above matches",
                     label + ": default"])
    for r in cfg.get("folder_rules") or []:
        rows.append(["Exception", "Folder → Safe", r.get("safe", ""), f"the folder is {r.get('folder_prefix', '')} or under it",
                     "the most specific folder wins"])
    for r in cfg.get("group_rules") or []:
        what = f"the access group is {r['group']}" if r.get("group") else \
            f"the access group {_plain_pattern(r.get('group_pattern'))}"
        rows.append(["Exception", "Access group → Safe", r.get("safe", ""), what, "first match wins"])
    # Abbreviations: yours first, then the codes the loaded folders got, then the dictionary.
    namer = Namer(cfg)
    yours = {norm(k) for k in (conv.get("abbreviations") or {})}
    for word, code in sorted((conv.get("abbreviations") or {}).items(), key=lambda kv: kv[0].lower()):
        rows.append(["Abbreviation", word, code, "a folder name or word", "yours"])
    counts = {}
    for p in plan.accounts:
        for level in p.rec.folder:
            counts[level] = counts.get(level, 0) + 1
    for s in namer.suggest(counts):
        if not s["yours"]:
            rows.append(["Abbreviation", s["folder"], s["code"], "a folder name",
                         ("automatic" if s["automatic"] else "built-in") + f", used by {_n(s['accounts'], 'account')}"])
    for word, code in sorted(DEFAULT_ABBREVIATIONS.items()):
        if norm(word) not in yours and code:
            rows.append(["Abbreviation", word, code, "a folder name or word", "built-in"])
    rows.append(["Abbreviation", "(any other word)", "", "no abbreviation above",
                 "automatic: up to 4 letters, CamelCase and compound words become initials (SharePoint → SP)"])
    std = cfg.get("standard_members") or {}
    if (std.get("apply_to") or "no_source_members") != "off":
        where = "every Safe" if std.get("apply_to") == "all" else "Safes with no members from the source"
        for r in std.get("members") or []:
            rows.append(["Member group", r.get("name", ""), r.get("role", ""), where,
                         f"{r.get('member_type') or 'Group'}; {{safe}} = the Safe's name"
                         + (f"; searchIn {r['search_in']}" if r.get("search_in") else "")])
    shown = 0
    for name, s in plan.safes.items():
        if shown >= examples:
            break
        folders = sorted(f for f in s["folders"] if f and f != "\\")
        rows.append(["Example", name, "", "; ".join(folders[:2]) or "accounts without folders",
                     f"{len(name)} characters, {_n(s['accounts'], 'account')}"])
        shown += 1
    return rows


def write_convention(plan, cfg, out_dir):
    path = Path(out_dir) / "review" / "SafeNamingConvention.csv"
    with _open(path) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        w.writerow(CONVENTION_HEADER)
        for row in convention_rows(plan, cfg):
            w.writerow(row)
    return path
