"""Target rules: Safe mapping, Safe names, platforms, members and validation.

Everything here is source-independent; it only sees SourceRecord objects.
"""

import csv
import logging
import re
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import List

from .adapters.base import address_from_url
from .config import all_roles, resolve_role
from .model import Grant, split_folder
from .naming import Namer

log = logging.getLogger("pam2pc.transform")

ACCOUNT_NAME_INVALID = re.compile(r'[\\/:*?"<>|\t\r\n]')
ACCOUNT_NAME_MAX = 128


# --------------------------------------------------------------------------- #
# Permissions file: grants for sources that do not carry them (Delinea, KeePass)
# --------------------------------------------------------------------------- #
class Permissions:
    """
    CSV with one grant per row. Columns (case-insensitive):
      Folder Path, Secret Name (or Name), Secret ID (or ID), Group (or Principal/Member),
      Permission, optional Member Type.
    Rows with an ID or name apply to that record; rows with only a folder apply to
    the folder and its subfolders (nearest folder wins). Record-level rows win.
    """

    def __init__(self, path=None, encoding="utf-8-sig"):
        self.by_id = defaultdict(list)
        self.by_name = defaultdict(list)
        self.by_folder = defaultdict(list)
        self.loaded = bool(path)
        if not path:
            return
        with open(path, newline="", encoding=encoding) as fh:
            reader = csv.DictReader(fh)
            cols = {c.lower().strip(): c for c in reader.fieldnames or []}

            def col(row, *names):
                for n in names:
                    c = cols.get(n.lower())
                    if c and (row.get(c) or "").strip():
                        return row[c].strip()
                return ""

            for row in reader:
                member = col(row, "Group", "Principal", "Member", "Group Name", "User/Group", "Member Name")
                perm = col(row, "Permission", "Role", "Access")
                if not member or not perm:
                    continue
                g = Grant(member, perm, col(row, "Member Type", "Type", "Principal Type"))
                rid = col(row, "Secret ID", "SecretId", "ID", "Record ID")
                name = col(row, "Secret Name", "SecretName", "Name", "Title")
                folder = "\\".join(split_folder(col(row, "Folder Path", "Folder", "Path"), "auto")).lower()
                if rid:
                    self.by_id[rid].append(g)
                elif name:
                    self.by_name[(folder, name.lower())].append(g)
                else:
                    self.by_folder[folder].append(g)
        log.info("permissions: %d record-level, %d folder-level entries",
                 len(self.by_id) + len(self.by_name), len(self.by_folder))

    def resolve(self, rec):
        if rec.source_id in self.by_id:
            return self.by_id[rec.source_id], "record"
        folder = [f.lower() for f in rec.folder]
        key = ("\\".join(folder), rec.name.lower())
        if key in self.by_name:
            return self.by_name[key], "record"
        for i in range(len(folder), -1, -1):
            cand = "\\".join(folder[:i])
            if cand in self.by_folder:
                return self.by_folder[cand], "folder"
        return [], "none"


# --------------------------------------------------------------------------- #
# Safe names
# --------------------------------------------------------------------------- #
def sanitize_safe_name(name, cfg):
    """Return (clean_name, valid_as_given, [issues])."""
    sc = cfg["safe_name"]
    issues = []
    raw = name or ""
    bad = sorted({c for c in raw if c in sc["invalid_chars"]})
    if bad:
        issues.append("invalid chars " + " ".join(bad))
    s = "".join(sc["replacement"] if c in sc["invalid_chars"] else c for c in raw)
    s = re.sub(r"[\x00-\x1f]", "", s)
    if sc["replacement"]:
        s = re.sub(re.escape(sc["replacement"]) + "{2,}", sc["replacement"], s)
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


def resolve_collisions(proposed_to_clean, cfg):
    """Different proposed names may clean up to the same Safe; suffix the later ones.
    Returns {proposed: (final, collided_with_or_None)}."""
    max_len = cfg["safe_name"]["max_length"]
    rep = cfg["safe_name"]["replacement"] or "-"
    groups = OrderedDict()
    for proposed, clean in proposed_to_clean.items():
        groups.setdefault(clean.lower(), []).append((proposed, clean))
    used = set(groups)
    result = {}
    for items in groups.values():
        first_proposed, first_clean = items[0]
        result[first_proposed] = (first_clean, None)
        n = 2
        for proposed, clean in items[1:]:
            while True:
                suffix = f"{rep}{n}"
                cand = clean[: max_len - len(suffix)].rstrip() + suffix
                n += 1
                if cand.lower() not in used:
                    break
            used.add(cand.lower())
            result[proposed] = (cand, first_proposed)
    return result


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def role_for(permission, cfg):
    """Source permission word -> role name (a preset or custom role; unknown names kept as is)."""
    pmap = {k.lower(): v for k, v in cfg["permission_map"].items()}
    mapped = pmap.get((permission or "").strip().lower(), "")
    return resolve_role(mapped, cfg) or mapped


def role_rank(role, cfg):
    """How strong a role is: the number of permissions it grants (0 if undefined)."""
    return len(all_roles(cfg).get(role, ()))


def _min_rank(rule, cfg):
    if rule.get("min_role"):
        return role_rank(resolve_role(rule["min_role"], cfg), cfg)
    if rule.get("min_permission"):  # old phase 1 configs used source wording
        return role_rank(role_for(rule["min_permission"], cfg), cfg)
    return 0


def match_group_rules(grants, cfg, rec=None, ctx=None):
    for rule in cfg["group_rules"]:
        min_rank = _min_rank(rule, cfg)
        for g in grants:
            if min_rank and role_rank(role_for(g.permission, cfg), cfg) < min_rank:
                continue
            if "group" in rule and g.member.lower() == rule["group"].lower():
                return _fill(rule["safe"], rec, ctx), f"group_rule:{rule['group']}"
            if "group_pattern" in rule:
                m = re.search(rule["group_pattern"], g.member, re.IGNORECASE)
                if m:
                    safe = rule["safe"]
                    for i, val in enumerate(m.groups(), start=1):
                        safe = safe.replace("{%d}" % i, val or "")
                    return _fill(safe, rec, ctx), f"group_pattern:{rule['group_pattern']}"
    return None, None


CONVENTION_KEYS = ("{convention}", "{folder_abbrev}", "{env}", "{tech}", "{flavor}", "{acct}", "{type}")


def _fill(safe, rec, ctx=None):
    """Expand placeholders in a rule's Safe name.
    {folder_leaf} {folder_path}: raw folder text.
    {convention}: the full naming-convention name. {folder_abbrev} {env} {tech} {flavor}
    {acct} {type}: single convention layers, e.g. "APP-{1}-{env}-{flavor}"."""
    if rec is None or "{" not in safe:
        return safe
    if ctx and any(k in safe for k in CONVENTION_KEYS):
        namer, platform = ctx
        if safe.strip() == "{convention}":
            name, notes = namer.build(rec, platform)
        else:
            name, notes = namer.build(rec, platform, template=safe.replace("{folder_abbrev}", "{folder}"))
        namer.last_notes = notes
        namer.used = True
        return name
    leaf = rec.folder[-1] if rec.folder else ""
    return safe.replace("{folder_leaf}", leaf).replace("{folder_path}", "-".join(rec.folder))


def match_folder_rules(rec, cfg, ctx=None):
    folder = [f.lower() for f in rec.folder]
    best = None
    for rule in cfg["folder_rules"]:
        prefix = [p.lower() for p in split_folder(rule["folder_prefix"], "\\")]
        if folder[: len(prefix)] == prefix and (best is None or len(prefix) > len(best[0])):
            best = (prefix, rule["safe"], rule["folder_prefix"])
    if best:
        return _fill(best[1], rec, ctx), "folder_rule:" + best[2]
    return None, None


def fallback_safe(rec, cfg, ctx=None):
    strategy = cfg["fallback_strategy"]
    if strategy == "convention" and ctx:
        name = _fill("{convention}", rec, ctx)
        return (name or "UNMAPPED"), "fallback:convention"
    if strategy == "unmapped" or not rec.folder:
        return "UNMAPPED", "fallback:unmapped"
    if strategy == "folder_path":
        return "-".join(rec.folder), "fallback:folder_path"
    return rec.folder[-1], "fallback:folder_leaf"


def _rule_field(rec, name):
    builtin = {"type": rec.type, "folder": rec.folder_path, "name": rec.name,
               "address": rec.address, "username": rec.username}
    if name in builtin:
        return builtin[name]
    for k, v in rec.extra.items():
        if k.lower() == name.lower():
            return v
    return ""


def resolve_platform(rec, cfg):
    if rec.target_platform:
        return rec.target_platform, "source"
    for rule in cfg["platform_rules"]:
        if re.search(rule["pattern"], _rule_field(rec, rule.get("field", "type"))):
            return rule["platform"], f"platform_rule:{rule.get('field', 'type')}"
    pmap = {k.lower(): v for k, v in cfg["platform_map"].items()}
    if rec.type.lower() in pmap:
        return pmap[rec.type.lower()], "platform_map"
    return cfg.get("default_platform") or "", "default"


def member_target(name, cfg):
    """'CORP\\Group' -> (memberName, searchIn) using directory_map."""
    dmap = {k.lower(): v for k, v in cfg["directory_map"].items()}
    domain, _, short = name.rpartition("\\")
    if not domain and "@" in name:
        short, _, domain = name.partition("@")
    search_in = (dmap.get(domain.lower()) or dmap.get(domain.split(".")[0].lower())
                 or dmap.get("*", "Vault")) if domain else dmap.get("*", "Vault")
    member = short if (domain and cfg["strip_domain_prefix"]) else name
    return member, search_in


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #
@dataclass
class AccountPlan:
    rec: object
    migrate: str = "Y"
    proposed_safe: str = ""
    safe: str = ""
    valid_safe: bool = True
    safe_issues: List[str] = field(default_factory=list)
    safe_source: str = ""
    platform: str = ""
    platform_source: str = ""
    account_name: str = ""
    grants: List[Grant] = field(default_factory=list)
    access_source: str = ""
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    in_scope: bool = True          # False when an extract filter leaves the record out

    @property
    def status(self):
        return "ERROR" if self.errors else ("REVIEW" if self.warnings else "OK")

    @property
    def uploadable(self):
        return self.migrate == "Y" and not self.errors and self.in_scope


@dataclass
class Plan:
    accounts: List[AccountPlan]
    safes: "OrderedDict"
    members: "OrderedDict"


def load_overrides(path, encoding="utf-8-sig"):
    """Read an edited Accounts_Review.csv. Returns {Record_ID: {column: value}}."""
    out = {}
    with open(path, newline="", encoding=encoding) as fh:
        for row in csv.DictReader(fh):
            rid = (row.get("Record_ID") or "").strip()
            if rid:
                out[rid] = {k: (v or "").strip() for k, v in row.items() if k}
    log.info("overrides: %d rows from %s", len(out), path)
    return out


def _changed(edited, computed):
    """True when a review-file value was edited (ignores the -N/_N suffixes this tool adds)."""
    if not edited:
        return False
    e, c = edited.strip().lower(), (computed or "").strip().lower()
    if e == c:
        return False
    m = re.match(r"^(.*)([-_]\d+)$", e)
    if not m:
        return True
    stem, suffix = m.group(1), m.group(2)
    # The suffix may have been added after cutting the name to fit a length limit.
    for limit in (len(c) + len(suffix), 28, ACCOUNT_NAME_MAX):
        if stem == c[: limit - len(suffix)].rstrip(" -_"):
            return False
    return True


def rebuild_totals(plan, cfg):
    """Recompute Safe and member totals after in_scope or migrate changed."""
    plan.safes = _safes(plan.accounts, cfg)
    plan.members = _members(plan.accounts, cfg)
    return plan


def _explicit_changed(edited, computed):
    return bool(edited) and edited.strip().lower() != (computed or "").strip().lower()


def build_plan(records, cfg, perms=None, overrides=None, explicit=False):
    """explicit=True: overrides are deliberate edits (database), not a re-fed review file."""
    changed = _explicit_changed if explicit else _changed
    perms = perms or Permissions()
    overrides = overrides or {}
    plans = []
    seen_ids = defaultdict(int)
    namer = Namer(cfg)
    convention_folders = defaultdict(set)

    for rec in records:
        p = AccountPlan(rec=rec)
        p.warnings.extend(rec.notes)
        seen_ids[rec.record_id] += 1
        if seen_ids[rec.record_id] > 1:
            rec.source_id = f"{rec.source_id}#{seen_ids[rec.record_id]}"
            p.warnings.append("duplicate id in the source; suffixed in Record_ID")
        ov = overrides.get(rec.record_id, {})

        # Access
        if rec.grants is not None:
            p.grants, p.access_source = list(rec.grants), rec.access_source or "source"
        elif perms.loaded:
            p.grants, p.access_source = perms.resolve(rec)
            p.grants = list(p.grants)
        else:
            p.access_source = "none"
        if not p.grants:
            p.warnings.append("no access groups found; Safe gets no members from the source")

        # Platform
        p.platform, p.platform_source = resolve_platform(rec, cfg)
        if changed(ov.get("Platform_ID"), p.platform):
            p.platform, p.platform_source = ov["Platform_ID"], "override"
        if not p.platform:
            p.errors.append(f"no platform for type '{rec.type}'; add it to platform_map")

        # Safe
        ctx = (namer, p.platform)
        namer.last_notes, namer.used = [], False
        safe, src = None, None
        if rec.target_safe:
            safe, src = rec.target_safe, "source"
        rules = [lambda: match_folder_rules(rec, cfg, ctx), lambda: match_group_rules(p.grants, cfg, rec, ctx)]
        if cfg.get("group_rules_first"):
            rules.reverse()
        for rule in rules:
            if not safe:
                safe, src = rule()
        fell_back = not safe
        if not safe:
            safe, src = fallback_safe(rec, cfg, ctx)
        safe = safe if src == "source" else apply_prefix(safe, cfg)
        # An edited review file repeats every value; only a changed one is an override.
        if changed(ov.get("Target_Safe"), sanitize_safe_name(safe, cfg)[0]):
            safe, src, fell_back = ov["Target_Safe"], "override", False
        if fell_back and src == "fallback:unmapped":
            p.warnings.append("no Safe: no rule matched and no folder to name it from")
        p.proposed_safe = safe
        p.safe_source = src
        if src != "override" and namer.last_notes:
            p.warnings.extend("Safe name: " + n for n in namer.last_notes)
        p.by_convention = (namer.used or src.startswith("fallback:folder")) and src != "override"
        if p.by_convention:
            convention_folders[safe.lower()].add(rec.folder_path)

        # Account name
        name = rec.name or f"{rec.address}-{rec.username}".strip("-")
        if changed(ov.get("Account_Name"), ACCOUNT_NAME_INVALID.sub("_", name).strip()):
            name = ov["Account_Name"]
        clean = ACCOUNT_NAME_INVALID.sub("_", name).strip()
        if len(clean) > ACCOUNT_NAME_MAX:
            clean = clean[:ACCOUNT_NAME_MAX]
            p.warnings.append(f"account name cut to {ACCOUNT_NAME_MAX} characters")
        if clean != name and len(name) <= ACCOUNT_NAME_MAX:
            p.warnings.append("invalid characters in account name replaced with _")
        p.account_name = clean

        if cfg.get("url_address_to_host") and "://" in rec.address:
            rec.address = address_from_url(rec.address)
        if not rec.username:
            p.errors.append("no username")
        if not rec.address:
            p.warnings.append("no address")

        mig = (ov.get("Migrate") or "Y").upper()
        p.migrate = "N" if mig in ("N", "NO", "FALSE", "0") else "Y"
        plans.append(p)

    for p in plans:
        folders = convention_folders.get(p.proposed_safe.lower(), set())
        if getattr(p, "by_convention", False) and len(folders) > 1:
            p.warnings.append(f"Safe shared by {len(folders)} source folders; check least privilege")

    # Clean Safe names and resolve collisions across the whole run.
    cleaned = {}
    for p in plans:
        if p.proposed_safe not in cleaned:
            cleaned[p.proposed_safe] = sanitize_safe_name(p.proposed_safe, cfg)
    final = resolve_collisions({k: v[0] for k, v in cleaned.items()}, cfg)

    names_in_safe = defaultdict(int)
    dupes = defaultdict(list)
    for p in plans:
        _, valid, issues = cleaned[p.proposed_safe]
        p.safe, collided = final[p.proposed_safe]
        p.safe_issues = list(issues)
        if collided:
            p.safe_issues.append(f"same name as '{collided}' after cleanup; suffixed")
            valid = False
        p.valid_safe = valid
        if not valid:
            p.warnings.insert(0, "Safe name changed: " + "; ".join(p.safe_issues))
        if not p.uploadable:
            continue
        key = (p.safe.lower(), p.account_name.lower())
        names_in_safe[key] += 1
        if names_in_safe[key] > 1:
            p.account_name = f"{p.account_name[:ACCOUNT_NAME_MAX - 4]}_{names_in_safe[key]}"
            p.warnings.append("duplicate account name in Safe; suffixed")
        dupes[(p.safe.lower(), p.rec.username.lower(), p.rec.address.lower(),
               p.rec.secret_type)].append(p)
    for group in dupes.values():
        if len(group) > 1:
            for x in group:
                others = [y.rec.record_id for y in group if y is not x]
                more = f" and {len(others) - 3} more" if len(others) > 3 else ""
                x.warnings.append("possible duplicate: same username/address/type in this Safe as "
                                  + ", ".join(others[:3]) + more)

    return Plan(plans, _safes(plans, cfg), _members(plans, cfg))


def _safes(plans, cfg=None):
    safes = OrderedDict()
    limit = (cfg or {}).get("safe_max_accounts") or 0
    for p in plans:
        s = safes.setdefault(p.safe, {"proposed": set(), "valid": True, "issues": set(),
                                      "sources": set(), "accounts": 0, "migrating": 0})
        s["proposed"].add(p.proposed_safe)
        s["valid"] &= p.valid_safe
        s["issues"].update(p.safe_issues)
        s["sources"].add(p.safe_source)
        s["accounts"] += 1
        s["migrating"] += 1 if p.uploadable else 0
    if limit:
        for s in safes.values():
            if s["accounts"] > limit:
                s["issues"].add(f"{s['accounts']} accounts; over the {limit} recommended per Safe")
    return safes


def _members(plans, cfg):
    """Strongest role per (Safe, member) over the accounts that migrate."""
    members = OrderedDict()
    for p in plans:
        if not p.uploadable:
            continue
        for g in p.grants:
            role = role_for(g.permission, cfg)
            key = (p.safe, g.member.lower())
            m = members.setdefault(key, {"source_name": g.member, "type": g.member_type,
                                         "role": role, "permission": g.permission,
                                         "accounts": 0, "seen": set()})
            m["accounts"] += 1
            m["seen"].add(g.permission or "(blank)")
            if role_rank(role, cfg) > role_rank(m["role"], cfg):
                m["role"], m["permission"] = role, g.permission
    for m in members.values():
        notes = []
        if len(m["seen"]) > 1:
            notes.append("mixed source permissions " + "/".join(sorted(m["seen"])) +
                         "; strongest used, Safe-level access widens it")
        if not m["role"]:
            notes.append(f"no role for permission '{m['permission']}'; add it to permission_map")
        elif m["role"] not in all_roles(cfg):
            notes.append(f"role '{m['role']}' is not a preset or custom role")
        m["notes"] = notes
        m["member_name"], m["search_in"] = member_target(m["source_name"], cfg)
        m["member_type"] = m["type"] or cfg["default_member_type"]
    return members
