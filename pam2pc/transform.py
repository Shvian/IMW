"""Target rules: Safe mapping, Safe names, platforms, members and validation.

Everything here is source-independent; it only sees SourceRecord objects.
"""

import csv
import logging
import re
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import List

from . import csvsafe
from .adapters.base import address_from_url
from .config import all_roles, resolve_role
from .model import Grant, split_folder
from .naming import Namer

log = logging.getLogger("pam2pc.transform")

NO_PLATFORM = "(none)"          # an edit that removes the platform on purpose
NO_NAME = "(none)"              # an edit that leaves the account name empty: Privilege Cloud names it
PLATFORM_INVALID = re.compile(r"[^A-Za-z0-9_.\-]")
# Characters removed from every stored text value: control characters, zero-width and BOM.
UNSAFE_TEXT = re.compile("[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u2028\u2029\u2060\ufeff]")
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
        """path: one file or a list of files; grants from several files are merged."""
        self.by_id = defaultdict(list)
        self.by_name = defaultdict(list)
        self.by_folder = defaultdict(list)
        paths = [p for p in (path if isinstance(path, (list, tuple)) else [path]) if p]
        self.loaded = bool(paths)
        self.paths = paths
        for one in paths:
            self._read(one, encoding)
        if paths:
            self.log_summary()

    @staticmethod
    def _add(lst, g):
        key = (g.member.lower(), g.permission.lower())
        if all((x.member.lower(), x.permission.lower()) != key for x in lst):
            lst.append(g)

    def _read(self, path, encoding):
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
                    self._add(self.by_id[rid], g)
                elif name:
                    self._add(self.by_name[(folder, name.lower())], g)
                else:
                    self._add(self.by_folder[folder], g)

    def log_summary(self):
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


def _split_member(name):
    domain, _, short = name.rpartition("\\")
    if not domain and "@" in name:
        short, _, domain = name.partition("@")
    return domain, short


def _source_matches(src, name, domain, member_type):
    # Group sources also take roles: like groups, they are named without a domain.
    kind = (src.get("members") or "both").lower()
    mt = (member_type or "").lower()
    if kind == "groups" and mt == "user" or kind == "users" and mt != "user":
        return False
    match = (src.get("match") or "*").strip()
    if match == "*":
        return True
    if match.lower().startswith("re:"):
        return bool(re.search(match[3:], name, re.IGNORECASE))
    m = match.lower()
    d = domain.lower()
    return bool(d) and (d == m or d.split(".")[0] == m or m.split(".")[0] == d)


def convert_member_name(src, name, domain, short):
    out = short if (domain and src.get("strip_domain", True)) else name
    if src.get("find"):
        out = re.sub(src["find"], src.get("replace", ""), out, flags=re.IGNORECASE)
    out = f"{src.get('add_prefix', '')}{out}{src.get('add_suffix', '')}"
    case = (src.get("case") or "keep").lower()
    return out.lower() if case == "lower" else out.upper() if case == "upper" else out


MEMBER_TYPES = ("User", "Group", "Role")


def normalize_member_type(value, default="Group"):
    """'group', 'USER', 'role' -> Group / User / Role; anything else -> default."""
    v = (value or "").strip().lower()
    for t in MEMBER_TYPES:
        if v == t.lower() or v == t.lower() + "s":
            return t
    return default if default in MEMBER_TYPES else "Group"


def member_target(name, cfg, member_type=""):
    """'CORP\\Group' -> (memberName, searchIn, source name) using directory_sources, then directory_map."""
    domain, short = _split_member(name)
    member_type = member_type or cfg.get("default_member_type", "Group")
    for src in cfg.get("directory_sources") or []:
        if _source_matches(src, name, domain, member_type):
            return convert_member_name(src, name, domain, short), src.get("search_in") or "", \
                src.get("name") or src.get("match") or ""
    dmap = {k.lower(): v for k, v in cfg["directory_map"].items()}
    search_in = (dmap.get(domain.lower()) or dmap.get(domain.split(".")[0].lower())
                 or dmap.get("*", "")) if domain else dmap.get("*", "")
    member = short if (domain and cfg["strip_domain_prefix"]) else name
    return member, search_in, ""


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
    member_edits: list = field(default_factory=list)


def load_overrides(path, encoding="utf-8-sig"):
    """Read an edited Accounts_Review.csv. Returns {Record_ID: {column: value}}."""
    out = {}
    with open(path, newline="", encoding=encoding) as fh:
        for row in csv.DictReader(fh):
            rid = csvsafe.unescape((row.get("Record_ID") or "").strip())
            if rid:
                out[rid] = {k: csvsafe.unescape((v or "").strip()) for k, v in row.items() if k}
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
    plan.members = _members(plan.accounts, cfg, plan.member_edits)
    return plan


def _explicit_changed(edited, computed):
    return bool(edited) and edited.strip().lower() != (computed or "").strip().lower()


def build_plan(records, cfg, perms=None, overrides=None, explicit=False, member_edits=None):
    """explicit=True: overrides are deliberate edits (database), not a re-fed review file."""
    changed = _explicit_changed if explicit else _changed
    perms = perms or Permissions()
    overrides = overrides or {}
    plans = []
    records = list(records)
    all_ids = {r.record_id for r in records}
    used_ids, dup_count = set(), defaultdict(lambda: 1)
    namer = Namer(cfg)
    convention_folders = defaultdict(set)

    for rec in records:
        p = AccountPlan(rec=rec)
        p.warnings.extend(rec.notes)
        # Access (looked up by the source's own id, before a duplicate id is suffixed)
        if rec.grants is not None:
            p.grants, p.access_source = list(rec.grants), rec.access_source or "source"
        elif perms.loaded:
            p.grants, p.access_source = perms.resolve(rec)
            p.grants = list(p.grants)
        else:
            p.access_source = "none"
        # Only a real duplicate in this run is suffixed. Records from the database are already
        # unique (Store.ingest added any #N), so they are never suffixed again, and a second
        # build_plan over the same records changes nothing.
        if rec.record_id in used_ids:
            base, n = rec.source_id, dup_count[rec.record_id] + 1
            rec.source_id = f"{base}#{n}"
            while rec.record_id in used_ids or rec.record_id in all_ids:
                n += 1
                rec.source_id = f"{base}#{n}"
            dup_count[f"{rec.source}:{rec.source_file}:{base}"] = n
            p.warnings.append("duplicate id in the source; suffixed in Record_ID")
        used_ids.add(rec.record_id)
        ov = overrides.get(rec.record_id, {})
        if not p.grants:
            p.warnings.append("no access groups found; Safe gets no members from the source")

        # Platform
        p.platform, p.platform_source = resolve_platform(rec, cfg)
        if ov.get("Platform_ID") == NO_PLATFORM:
            p.platform, p.platform_source = "", "override"
            p.errors.append("no platform: removed by you")
        elif changed(ov.get("Platform_ID"), p.platform):
            p.platform, p.platform_source = ov["Platform_ID"], "override"
        if p.platform and PLATFORM_INVALID.search(p.platform):
            bad = " ".join(sorted({repr(c)[1:-1] if c != " " else "space" for c in PLATFORM_INVALID.findall(p.platform)}))
            clean = PLATFORM_INVALID.sub("_", p.platform)
            p.warnings.append(f"forbidden characters in platform ID '{p.platform}' ({bad}); changed to "
                              f"'{clean}', check that platform exists")
            p.platform = clean
        if not p.platform and p.platform_source != "override":
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

        # Address first: the account name template may use {address}.
        if cfg.get("url_address_to_host") and "://" in rec.address:
            rec.address = address_from_url(rec.address)

        # Account name
        name = account_name_for(rec, p, cfg)
        if changed(ov.get("Account_Name"), ACCOUNT_NAME_INVALID.sub("_", name).strip()):
            name = ov["Account_Name"]
        if name.strip().lower() == NO_NAME:
            name = ""                   # left empty on purpose: Privilege Cloud generates one
        clean = ACCOUNT_NAME_INVALID.sub("_", name).strip()
        if len(clean) > ACCOUNT_NAME_MAX:
            clean = clean[:ACCOUNT_NAME_MAX]
            p.warnings.append(f"account name cut to {ACCOUNT_NAME_MAX} characters")
        if clean != name and len(name) <= ACCOUNT_NAME_MAX:
            bad = " ".join(sorted({repr(c)[1:-1] for c in ACCOUNT_NAME_INVALID.findall(name)}))
            p.warnings.append(f"forbidden characters in account name ({bad}) replaced with _")
        p.account_name = clean

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
        dupes[(p.safe.lower(), p.rec.username.lower(), p.rec.address.lower(),
               p.rec.secret_type)].append(p)
    _unique_account_names(plans)
    for group in dupes.values():
        if len(group) > 1:
            for x in group:
                others = [y.rec.record_id for y in group if y is not x]
                more = f" and {len(others) - 3} more" if len(others) > 3 else ""
                x.warnings.append("possible duplicate: same username/address/type in this Safe as "
                                  + ", ".join(others[:3]) + more
                                  + ("; with no account name Privilege Cloud gives both the same "
                                     "name and rejects the second" if not x.account_name else ""))

    return Plan(plans, _safes(plans, cfg), _members(plans, cfg, member_edits), list(member_edits or []))


def _unique_account_names(plans):
    """Account names must be unique within a Safe. The first account keeps its name; later
    duplicates get _2, _3, ... skipping any name already used (or still to come) in that Safe."""
    taken = defaultdict(set)                      # every name the uploadable accounts start with
    for p in plans:
        if p.uploadable:
            taken[p.safe.lower()].add(p.account_name.lower())
    claimed = defaultdict(set)
    for p in plans:
        if not p.uploadable:
            continue
        safe = p.safe.lower()
        if not p.account_name:          # Privilege Cloud names it; nothing to make unique
            continue
        if p.account_name.lower() not in claimed[safe]:
            claimed[safe].add(p.account_name.lower())
            continue
        n = 2
        while True:
            suffix = f"_{n}"
            cand = f"{p.account_name[:ACCOUNT_NAME_MAX - len(suffix)]}{suffix}"
            if cand.lower() not in taken[safe] and cand.lower() not in claimed[safe]:
                break
            n += 1
        claimed[safe].add(cand.lower())
        p.account_name = cand
        p.warnings.append("duplicate account name in Safe; suffixed")


def account_name_for(rec, p, cfg):
    """Account name from account_name.template, else account_name.fallback; empty when
    account_name.mode is "none" (Privilege Cloud then generates a name)."""
    an = cfg.get("account_name") or {}
    if str(an.get("mode") or "").lower() == "none":
        return ""                       # Privilege Cloud generates the name on upload
    vals = {"name": rec.name, "address": rec.address, "username": rec.username, "platform": p.platform,
            "safe": p.proposed_safe, "folder_leaf": rec.folder[-1] if rec.folder else "",
            "type": rec.type, "source_id": rec.source_id}

    def fill(t):
        return re.sub(r"\{(\w+)\}", lambda m: str(vals.get(m.group(1), "") or ""), t or "").strip("-_. ")
    return fill(an.get("template") or "{name}") or fill(an.get("fallback") or "{address}-{username}")


def safe_settings(name, info, cfg):
    """Body fields for one Safe: safe_defaults, then the first matching safe_rules entry."""
    body = dict(cfg["safe_defaults"])
    for rule in cfg.get("safe_rules") or []:
        pat = rule.get("safe_pattern") or ""
        if pat and re.search(pat, name, re.IGNORECASE):
            for k in ("managingCPM", "description", "numberOfVersionsRetention", "numberOfDaysRetention"):
                if str(rule.get(k, "")).strip() != "":
                    body[k] = rule[k]
            if str(rule.get("numberOfVersionsRetention", "")).strip():
                body["numberOfDaysRetention"] = ""
            elif str(rule.get("numberOfDaysRetention", "")).strip():
                body["numberOfVersionsRetention"] = ""
            break
    folders = sorted((info or {}).get("folders") or [])
    if body.get("description") and "{" in str(body["description"]):
        body["description"] = str(body["description"]).replace("{folder}", folders[0] if folders else "") \
            .replace("{safe}", name)[:100]
    body["safeName"] = name
    return body


def apply_member_edits(members, plans, edits):
    """Your member changes on the Safes page: remove a member from a Safe, or add one."""
    if not edits:
        return members
    uploading = defaultdict(int)
    names = {}
    for p in plans:
        if p.uploadable:
            uploading[p.safe.lower()] += 1
            names[p.safe.lower()] = p.safe
    for e in edits:
        safe_l, name_l = e["safe_name"].lower(), e["member_name"].lower()
        for key in [k for k, m in members.items() if k[0].lower() == safe_l and
                    name_l in (m["member_name"].lower(), m["source_name"].lower())]:
            del members[key]
        if e["action"] == "add" and safe_l in uploading:
            members[(names[safe_l], "edit:" + name_l)] = {
                "source_name": e["member_name"], "type": normalize_member_type(e.get("member_type")),
                "member_type": normalize_member_type(e.get("member_type")), "role": e.get("role") or "",
                "permission": "(added by you)", "accounts": uploading[safe_l], "seen": set(),
                "member_name": e["member_name"], "search_in": e.get("search_in") or "",
                "directory_source": "added by you",
                "notes": ["added by you" + (f": {e['reason']}" if e.get("reason") else "")]}
    return members


def sanitize_record(rec):
    """Remove control and invisible characters from every text value (not the secret).
    Returns the names of the fields that changed and notes them on the record."""
    changed = []

    def clean(v):
        if not isinstance(v, str):
            return v
        out = UNSAFE_TEXT.sub("", v.replace("\u00a0", " "))
        return out.strip() if out != v else v
    for f in ("name", "type", "address", "username", "source_ref"):
        v = getattr(rec, f)
        c = clean(v)
        if c != v:
            setattr(rec, f, c)
            changed.append(f)
    folder = tuple(x for x in (clean(x) for x in rec.folder) if x)
    if folder != tuple(rec.folder):
        rec.folder = folder
        changed.append("folder")
    for k in list(rec.extra):
        c = clean(rec.extra[k])
        if c != rec.extra[k]:
            rec.extra[k] = c
            changed.append(k)
    for g in rec.grants or []:
        c = clean(g.member)
        if c != g.member:
            g.member = c
            changed.append("access group")
    if changed:
        rec.notes.append("forbidden characters (control or invisible) removed from: " + ", ".join(changed))
    return changed


def _safes(plans, cfg=None):
    safes = OrderedDict()
    limit = (cfg or {}).get("safe_max_accounts") or 0
    for p in plans:
        s = safes.setdefault(p.safe, {"proposed": set(), "valid": True, "issues": set(),
                                      "sources": set(), "accounts": 0, "migrating": 0, "folders": set()})
        s["folders"].add(p.rec.folder_path)
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


def _members(plans, cfg, edits=None):
    """Strongest role per (Safe, member) over the accounts that migrate, then your member edits."""
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
        m["member_type"] = normalize_member_type(m["type"], normalize_member_type(cfg["default_member_type"]))
        m["member_name"], m["search_in"], m["directory_source"] = member_target(
            m["source_name"], cfg, m["member_type"])
    apply_member_edits(members, plans, edits)
    return members
