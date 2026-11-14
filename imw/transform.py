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
from .config import PERMISSION_PRESETS, all_roles, resolve_role
from .model import ERROR_NOTE, Grant, split_folder
from .naming import Namer

log = logging.getLogger("imw.transform")

NO_PLATFORM = "(none)"          # an edit that removes the platform on purpose
NO_NAME = "(none)"              # an edit that leaves the account name empty: Privilege Cloud names it
NO_ACCESS_NOTE = "no access groups found; Safe gets no members from the source"
PLATFORM_INVALID = re.compile(r"[^A-Za-z0-9_.\-]")
# Characters removed from every stored text value: control characters, zero-width and BOM.
UNSAFE_TEXT = re.compile("[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u2028\u2029\u2060\ufeff]")
# One-line values you type (Safe settings, member names, searchIn): also no tab or line break.
UNSAFE_LINE = re.compile("[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029\u2060\ufeff]")
ACCOUNT_NAME_INVALID = re.compile(r'[\\/:*?"<>|\t\r\n]')
ACCOUNT_NAME_MAX = 128


# --------------------------------------------------------------------------- #
# Permissions file: grants for sources that do not carry them (Delinea, KeePass)
# --------------------------------------------------------------------------- #
# Column names a permissions file may use (case-insensitive), in order of preference. They
# cover the Workbench's own layout and Delinea's folder-permission reports ("What folder
# permissions exist for groups?", "What folder permissions exist?", "What folders can a user
# see?", "What folders can all users see?"), which list assigned and inherited permissions alike.
PERM_FOLDER_COLUMNS = ("Folder Path", "FolderPath", "Folder", "Path", "Folder Name")
PERM_GROUP_COLUMNS = ("Group", "Group Name", "GroupName", "Principal", "Member", "User/Group",
                      "Member Name", "Group Display Name")
PERM_USER_COLUMNS = ("User", "User Name", "UserName", "Username", "User Display Name", "Display Name")
# For a folder the secret role is what its secrets get, so it comes before the folder role.
PERM_ROLE_COLUMNS = ("Permission", "Secret Permission", "Secret Permissions", "Secret Access Role",
                     "Secret Access Role Name", "SecretAccessRoleName", "Secret Role", "Role", "Access",
                     "Permissions", "Folder Permission", "Folder Permissions", "Folder Access Role",
                     "Folder Access Role Name", "FolderAccessRoleName", "Folder Role")
PERM_TYPE_COLUMNS = ("Member Type", "Type", "Principal Type")
PERM_DOMAIN_COLUMNS = ("Domain", "Domain Name", "DomainName")
# Strongest first: a report cell such as "View, Edit, Owner" keeps the strongest right.
_PERMISSION_ORDER = ("owner", "full", "admin", "manage", "edit", "write", "modify", "add secret",
                     "approve", "view", "read", "use", "connect", "list")


def strongest_permission(text):
    """'View, Edit, Owner' (or '/', ';' or '|' between them) -> 'Owner'; a single word stays as is."""
    parts = [p.strip() for p in re.split(r"[,;/|]+", text or "") if p.strip()]
    if len(parts) <= 1:
        return (text or "").strip()
    rank = {w: i for i, w in enumerate(_PERMISSION_ORDER)}
    return min(parts, key=lambda p: rank.get(p.lower(), len(rank)))


class Permissions:
    """
    CSV with one grant per row. Columns (case-insensitive, see PERM_*_COLUMNS):
      Folder Path, Secret Name (or Name), Secret ID (or ID), Group (or Principal/Member) or
      User, Permission (or a Delinea report's Secret / Folder Permission), optional Member Type
      and Domain.
    Rows with an ID or name apply to that record; rows with only a folder apply to
    the folder and its subfolders (nearest folder wins). Record-level rows win.
    Delinea reports list inherited permissions next to assigned ones; both are read the same
    way, since an inherited row only repeats what the parent folder already has.
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
        with open(path, newline="", encoding=encoding) as fh, csvsafe.reading(path):
            reader = csv.DictReader(fh)
            cols = {c.lower().strip(): c for c in reader.fieldnames or [] if c}

            def pick(names):
                return next((cols[n.lower()] for n in names if n.lower() in cols), None)

            group_col, user_col = pick(PERM_GROUP_COLUMNS), pick(PERM_USER_COLUMNS)
            perm_cols = [cols[n.lower()] for n in PERM_ROLE_COLUMNS if n.lower() in cols]
            type_col = pick(PERM_TYPE_COLUMNS)
            domain_col = pick(PERM_DOMAIN_COLUMNS)
            if user_col and not group_col:
                log.warning("%s lists permissions per user, not per group: each user becomes a Safe member. "
                            "Delinea's 'What folder permissions exist for groups?' report keeps the groups.", path)

            def col(row, *names):
                for n in names:
                    c = cols.get(n.lower())
                    if c and (row.get(c) or "").strip():
                        return row[c].strip()
                return ""

            for row in reader:
                member, mtype = "", ""
                # A report row that names both a user and the group the access comes from:
                # the group is the Safe member.
                if group_col and (row.get(group_col) or "").strip():
                    member = row[group_col].strip()
                    mtype = "Group" if user_col else ""
                elif user_col and (row.get(user_col) or "").strip():
                    member, mtype = row[user_col].strip(), "User"
                domain = (row.get(domain_col) or "").strip() if domain_col else ""
                if member and domain and "\\" not in member:
                    member = f"{domain}\\{member}"
                perm = strongest_permission(next(((row.get(c) or "").strip() for c in perm_cols
                                                  if (row.get(c) or "").strip()), ""))
                if not member or not perm:
                    continue
                g = Grant(member, perm, ((row.get(type_col) or "").strip() if type_col else "") or mtype)
                rid = col(row, "Secret ID", "SecretId", "ID", "Record ID")
                name = col(row, "Secret Name", "SecretName", "Name", "Title")
                folder = "\\".join(split_folder(col(row, *PERM_FOLDER_COLUMNS), "auto")).lower()
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
    s = UNSAFE_LINE.sub("", s.replace("\u00a0", " "))
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
        # Case-insensitive, like every other pattern in the rules.
        if re.search(rule["pattern"], _rule_field(rec, rule.get("field", "type")), re.IGNORECASE):
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
    rule_safe: str = ""            # the Safe name the rules gave, before you renamed the Safe
    # Notes about the account's Safe rather than the account itself (no access groups, a long
    # name shortened, a Safe shared by several folders). They show on the Safe, not on the
    # account, so they never make an account "need a look".
    safe_notes: List[str] = field(default_factory=list)

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
    member_overrides: dict = field(default_factory=dict)
    safe_overrides: dict = field(default_factory=dict)


def load_overrides(path, encoding="utf-8-sig"):
    """Read an edited Accounts_Review.csv. Returns {Record_ID: {column: value}}."""
    out = {}
    with open(path, newline="", encoding=encoding) as fh, csvsafe.reading(path):
        for row in csv.DictReader(fh):
            rid = csvsafe.unescape((row.get("Record_ID") or "").strip()).strip()
            if rid:
                out[rid] = {k: csvsafe.unescape((v or "").strip()).strip() for k, v in row.items() if k}
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
    plan.safes = _safes(plan.accounts, cfg, plan.safe_overrides)
    plan.members = _members(plan.accounts, cfg, plan.member_edits, plan.member_overrides)
    flag_safes_without_full_member(plan.safes, plan.members, cfg)
    return plan


def _explicit_changed(edited, computed):
    return bool(edited) and edited.strip().lower() != (computed or "").strip().lower()


def build_plan(records, cfg, perms=None, overrides=None, explicit=False, member_edits=None,
               member_overrides=None, safe_overrides=None):
    """explicit=True: overrides are deliberate edits (database), not a re-fed review file.
    safe_overrides: {lower Safe name as the rules give it: {"new_name": ..., settings...}},
    your direct changes to whole Safes (name, description, CPM, retention, ...)."""
    safe_overrides = safe_overrides or {}
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
        p.warnings.extend(n for n in rec.notes if not n.startswith(ERROR_NOTE))
        p.errors.extend(n[len(ERROR_NOTE):] for n in rec.notes if n.startswith(ERROR_NOTE))
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
        # Address first, so platform and Safe rules, the account name template ({address}) and
        # the output all see the same value. Sources keep the full URL; the review file's
        # Source.* columns keep it too. Records are reloaded from the database for every
        # mapping, so changing the setting needs no new ingest.
        if cfg.get("url_address_to_host") and "://" in rec.address:
            rec.address = address_from_url(rec.address)
        ov = overrides.get(rec.record_id, {})
        if not p.grants:
            p.safe_notes.append(NO_ACCESS_NOTE)

        # Platform
        p.platform, p.platform_source = resolve_platform(rec, cfg)
        if ov.get("Platform_ID") == NO_PLATFORM:
            p.platform, p.platform_source = "", "override"
            p.errors.append("no platform: removed by you")
        elif changed(ov.get("Platform_ID"), p.platform):
            p.platform, p.platform_source = ov["Platform_ID"], "override"
        p.platform = UNSAFE_LINE.sub("", p.platform or "")
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
            p.safe_notes.extend("Safe name: " + n for n in namer.last_notes)
        p.by_convention = (namer.used or src.startswith("fallback:folder")) and src != "override"
        if p.by_convention:
            convention_folders[safe.lower()].add(rec.folder_path)


        # Account name
        name = account_name_for(rec, p, cfg)
        if changed(ov.get("Account_Name"), ACCOUNT_NAME_INVALID.sub("_", name).strip()):
            name = ov["Account_Name"]
        if name.strip().lower() == NO_NAME:
            name = ""                   # left empty on purpose: Privilege Cloud generates one
        unsafe = UNSAFE_TEXT.sub("", name)
        if unsafe != name:
            p.warnings.append("invisible or control characters removed from the account name")
            name = unsafe
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
            p.safe_notes.append(f"Safe shared by {len(folders)} source folders; check least privilege")

    # Clean Safe names and resolve collisions across the whole run.
    cleaned = {}
    for p in plans:
        if p.proposed_safe not in cleaned:
            cleaned[p.proposed_safe] = sanitize_safe_name(p.proposed_safe, cfg)
    final = resolve_collisions({k: v[0] for k, v in cleaned.items()}, cfg)

    # Safe names compare without case in Privilege Cloud: a rename onto an existing Safe (or two
    # renames onto one new name) in another case joins it, spelled as that Safe is.
    spelling = {name.lower(): name for name, _ in final.values()}
    dupes = defaultdict(list)
    for p in plans:
        _, valid, issues = cleaned[p.proposed_safe]
        p.safe, collided = final[p.proposed_safe]
        p.safe_issues = list(issues)
        if collided:
            p.safe_issues.append(f"same name as '{collided}' after cleanup; suffixed")
            valid = False
        p.valid_safe = valid
        p.rule_safe = p.safe
        new_name = (safe_overrides.get(p.safe.lower()) or {}).get("new_name")
        if new_name:
            # You renamed this whole Safe: its accounts follow, whatever the rules gave.
            p.safe, p.valid_safe, p.safe_issues = sanitize_safe_name(new_name, cfg)
            p.safe = spelling.setdefault(p.safe.lower(), p.safe)
            p.safe_source = "Safe renamed by you"
        # A changed (sanitized) Safe name is a Safe issue: p.safe_issues, shown on the Safe.
        # Same username and address (trimmed, any case) is a possible duplicate wherever it is:
        # another Safe, another folder or another source file. Accounts you set to not migrate
        # (or an extract filter leaves out) drop out, so setting one copy to N clears the flag.
        user, addr = p.rec.username.strip().lower(), p.rec.address.strip().lower()
        if p.migrate == "Y" and p.in_scope and user and addr:
            dupes[(user, addr)].append(p)
    _unique_account_names(plans)
    flag_duplicates(dupes.values())

    # A Safe you renamed onto a name another Safe already has: both now share one Safe.
    from_rules = {p.safe.lower() for p in plans if p.rule_safe == p.safe}
    for p in plans:
        if p.rule_safe != p.safe and p.safe.lower() in from_rules:
            p.safe_notes.append(f"Safe '{p.rule_safe}' renamed by you to '{p.safe}', which another Safe "
                                "already has: their accounts are now in one Safe")

    safes = _safes(plans, cfg, safe_overrides)
    members = _members(plans, cfg, member_edits, member_overrides)
    flag_safes_without_full_member(safes, members, cfg)
    return Plan(plans, safes, members,
                list(member_edits or []), dict(member_overrides or {}), dict(safe_overrides))


DUPLICATE_NOTE = "possible duplicate"


def _describe(y, x):
    """How another copy y differs from account x, so the note says where to look."""
    where = []
    if y.rec.source_file != x.rec.source_file or y.rec.source != x.rec.source:
        where.append(f"file {y.rec.source_file}")
    where.append("same Safe" if y.safe.lower() == x.safe.lower() else f"Safe {y.safe}")
    label = f"'{y.rec.name}' " if y.rec.name else ""
    return f"{label}{y.rec.record_id} ({', '.join(where)})"


def flag_duplicates(groups):
    """Note every account that shares its username and address with another account."""
    for group in groups:
        if len(group) < 2:
            continue
        for x in group:
            others = [y for y in group if y is not x]
            more = f" and {len(others) - 3} more" if len(others) > 3 else ""
            same_safe_no_name = not x.account_name and any(
                y.safe.lower() == x.safe.lower() and y.rec.secret_type == x.rec.secret_type
                and not y.account_name for y in others)
            x.warnings.append(f"{DUPLICATE_NOTE}: same username and address as "
                              + "; ".join(_describe(y, x) for y in others[:3]) + more
                              + (". With no account name Privilege Cloud gives both the same "
                                 "name and rejects the second" if same_safe_no_name else
                                 ". Keep one, or set the others to not migrate"))


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


SAFE_OVERRIDE_KEYS = ("description", "location", "managingCPM", "numberOfVersionsRetention",
                      "numberOfDaysRetention", "olacEnabled", "autoPurgeEnabled")


def safe_settings(name, info, cfg, with_override=True):
    """Body fields for one Safe: safe_defaults, then the first matching safe_rules entry, then
    your own changes to this Safe (info["override"]), which always win."""
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
    ov = (info or {}).get("override") if with_override else None
    for k in SAFE_OVERRIDE_KEYS:
        v = (ov or {}).get(k)
        if v is None or str(v).strip() == "":
            continue
        body[k] = v
        if k == "numberOfVersionsRetention":
            body["numberOfDaysRetention"] = ""
        elif k == "numberOfDaysRetention":
            body["numberOfVersionsRetention"] = ""
    folders = sorted((info or {}).get("folders") or [])
    if body.get("description") and "{" in str(body["description"]):
        body["description"] = str(body["description"]).replace("{folder}", folders[0] if folders else "") \
            .replace("{safe}", name)[:100]
    for k in ("description", "location", "managingCPM"):
        if isinstance(body.get(k), str):
            body[k] = clean_line(body[k])     # also covers config.json edited by hand
    body["safeName"] = name
    return body


def _member_names(m):
    """Every name a per-Safe edit may use for a member: its target name, the name the rules
    gave it before you renamed it, and each source member name."""
    names = {m.get("member_name") or "", m.get("rule_name") or ""}
    names.update(m.get("sources") or [m.get("source_name") or ""])
    return {n.lower() for n in names if n}


def apply_member_edits(members, plans, edits):
    """Your member changes on the Safes page: remove a member from a Safe, or add one.
    Adding a member that is already on the Safe changes its role (and its type or searchIn
    when the change gives one) and keeps everything else."""
    if not edits:
        return members
    uploading = defaultdict(int)
    names = {}
    for p in plans:
        if p.uploadable:
            uploading[p.safe.lower()] += 1
            names[p.safe.lower()] = p.safe
    for e in edits:
        e = dict(e, member_name=clean_line(e["member_name"]), search_in=clean_line(e.get("search_in") or ""))
        safe_l, name_l = e["safe_name"].lower(), e["member_name"].lower()
        found = [k for k, m in members.items() if k[0].lower() == safe_l and name_l in _member_names(m)]
        why = f": {e['reason']}" if e.get("reason") else ""
        if e["action"] == "add" and found:
            for key in found[1:]:
                del members[key]
            m = members[found[0]]
            if e.get("role"):
                m["role"] = e["role"]
            if (e.get("member_type") or "").strip():
                m["member_type"] = m["type"] = normalize_member_type(e["member_type"], m["member_type"])
            if (e.get("search_in") or "").strip():
                m["search_in"] = e["search_in"].strip()
            m["notes"] = list(m.get("notes") or []) + ["role changed by you" + why]
            continue
        for key in found:
            del members[key]
        if e["action"] == "add" and safe_l in uploading:
            members[(names[safe_l], "edit:" + name_l)] = {
                "source_name": e["member_name"], "type": normalize_member_type(e.get("member_type")),
                "member_type": normalize_member_type(e.get("member_type")), "role": e.get("role") or "",
                "permission": "(added by you)", "accounts": uploading[safe_l], "seen": set(),
                "member_name": e["member_name"], "search_in": e.get("search_in") or "",
                "directory_source": "added by you", "rule_name": "", "sources": [e["member_name"]],
                "notes": ["added by you" + why]}
    return members


def apply_member_override(m, ov):
    """Your change to one member everywhere (its memberName, memberType or searchIn).
    A None value keeps what the rules give; searchIn may be set to empty on purpose."""
    if not ov:
        return m
    changed = []
    if clean_line(ov.get("member_name")):
        m["member_name"] = clean_line(ov["member_name"])
        changed.append("name")
    if ov.get("member_type"):
        m["member_type"] = m["type"] = normalize_member_type(ov["member_type"], m.get("member_type") or "Group")
        changed.append("type")
    if ov.get("search_in") is not None:
        m["search_in"] = clean_line(ov["search_in"])
        changed.append("searchIn")
    if changed:
        m["directory_source"] = "edited by you"
        if "notes" in m:
            m["notes"] = list(m["notes"]) + ["edited by you (" + ", ".join(changed) + ")"
                                             + (f": {ov['reason']}" if ov.get("reason") else "")]
    return m


def apply_member_overrides(members, overrides):
    if overrides:
        for m in members.values():
            apply_member_override(m, overrides.get(m["source_name"].lower()))
    return members


def clean_line(v):
    """A one-line text value without control or invisible characters, trimmed.
    Non-text values come back unchanged."""
    if not isinstance(v, str):
        return v
    return UNSAFE_LINE.sub("", v.replace("\u00a0", " ")).strip()


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


def _safes(plans, cfg=None, safe_overrides=None):
    safes = OrderedDict()
    limit = (cfg or {}).get("safe_max_accounts") or 0
    safe_overrides = safe_overrides or {}
    for p in plans:
        s = safes.setdefault(p.safe, {"proposed": set(), "valid": True, "issues": set(),
                                      "sources": set(), "accounts": 0, "migrating": 0, "folders": set(),
                                      "rule_names": set(), "override": None})
        s["folders"].add(p.rec.folder_path)
        rule_name = p.rule_safe or p.safe
        s["rule_names"].add(rule_name)
        if s["override"] is None and safe_overrides.get(rule_name.lower()):
            s["override"] = safe_overrides[rule_name.lower()]
        s["proposed"].add(p.proposed_safe)
        s["valid"] &= p.valid_safe
        s["issues"].update(p.safe_issues)
        s["issues"].update(n for n in p.safe_notes if n != NO_ACCESS_NOTE)
        s["no_access"] = s.get("no_access", 0) + (1 if NO_ACCESS_NOTE in p.safe_notes else 0)
        s["sources"].add(p.safe_source)
        s["accounts"] += 1
        s["migrating"] += 1 if p.uploadable else 0
    for name, s in safes.items():
        # A Safe that other Safes were renamed into keeps its own settings: only your change to
        # this Safe itself applies (the renamed Safes' other settings don't follow them).
        if name.lower() in {n.lower() for n in s["rule_names"]}:
            s["override"] = safe_overrides.get(name.lower())
    for s in safes.values():
        n = s.pop("no_access", 0)
        if n:
            s["issues"].add(f"{n} of its accounts have no access groups in the source"
                            if n < s["accounts"] else "no access groups in the source for any of its accounts")
    if limit:
        for s in safes.values():
            if s["accounts"] > limit:
                s["issues"].add(f"{s['accounts']} accounts; over the {limit} recommended per Safe")
    return safes


NO_FULL_MEMBER_NOTE = ("no member with full permissions: no user, group or role from your source can manage "
                       "this Safe or its members (only the user who uploads it and the Privilege Cloud "
                       "administrators can). Give one member the Full role, or a custom role with every "
                       "Full permission")


def full_roles(cfg):
    """Role names that grant every permission of the Full preset (case-insensitive)."""
    full = set(PERMISSION_PRESETS["Full"])
    return {name.lower() for name, perms in all_roles(cfg).items() if full <= set(perms)}


def flag_safes_without_full_member(safes, members, cfg):
    """A Safe that will be uploaded needs at least one member who can fully manage it."""
    full = full_roles(cfg)
    managed = {safe.lower() for (safe, _), m in members.items() if (m.get("role") or "").lower() in full}
    for name, s in safes.items():
        if s.get("migrating") and name.lower() not in managed:
            s["issues"].add(NO_FULL_MEMBER_NOTE)
    return safes


def _members(plans, cfg, edits=None, overrides=None):
    """Strongest role per (Safe, member) over the accounts that migrate. Order matters:
    the rules give each source member its target name, your member changes (overrides)
    rename it everywhere, rows that now share a target name on one Safe merge (the API
    takes one row per Safe and member), and last your per-Safe edits apply."""
    members = OrderedDict()
    for p in plans:
        if not p.uploadable:
            continue
        for g in p.grants:
            role = role_for(g.permission, cfg)
            key = (p.safe, g.member.lower())
            m = members.setdefault(key, {"source_name": g.member, "type": g.member_type,
                                         "role": role, "permission": g.permission,
                                         "accounts": 0, "seen": set(), "ids": set()})
            if id(p) not in m["ids"]:
                m["ids"].add(id(p))
                m["accounts"] += 1
            m["seen"].add(g.permission or "(blank)")
            if role_rank(role, cfg) > role_rank(m["role"], cfg):
                m["role"], m["permission"] = role, g.permission
    for m in members.values():
        m["member_type"] = normalize_member_type(m["type"], normalize_member_type(cfg["default_member_type"]))
        m["member_name"], m["search_in"], m["directory_source"] = member_target(
            m["source_name"], cfg, m["member_type"])
        m["rule_name"] = m["member_name"]
        m["sources"] = [m["source_name"]]
        m["notes"] = []
    apply_member_overrides(members, overrides)
    members = _merge_members(members, cfg)
    for m in members.values():
        notes = []
        if len(m["seen"]) > 1:
            notes.append("mixed source permissions " + "/".join(sorted(m["seen"])) +
                         "; strongest used, Safe-level access widens it")
        if not m["role"]:
            notes.append(f"no role for permission '{m['permission']}'; add it to permission_map")
        elif m["role"] not in all_roles(cfg):
            notes.append(f"role '{m['role']}' is not a preset or custom role")
        m["notes"] = notes + m["notes"]
        m.pop("ids", None)
    apply_member_edits(members, plans, edits)
    return members


def _merge_members(members, cfg):
    """One row per (Safe, target member name). Two source members can end up with the same
    name, e.g. CORP\\SQL-Admins and LEGACY\\SQL-Admins once the domain is stripped, or
    because you renamed one to the other. The merged row keeps the strongest role and lists
    every source member (joined with ' | ')."""
    out = OrderedDict()
    for (safe, _), m in members.items():
        key = (safe, (m["member_name"] or m["source_name"]).lower())
        cur = out.get(key)
        if cur is None:
            out[key] = m
            continue
        cur["sources"].extend(m["sources"])
        cur["source_name"] = " | ".join(cur["sources"])
        new_ids = m["ids"] - cur["ids"]
        cur["ids"] |= new_ids
        cur["accounts"] += len(new_ids)
        cur["seen"] |= m["seen"]
        if role_rank(m["role"], cfg) > role_rank(cur["role"], cfg):
            cur["role"], cur["permission"] = m["role"], m["permission"]
        note = "merged source members " + ", ".join(cur["sources"]) + " (same target name on this Safe)"
        if (m["search_in"] or "") != (cur["search_in"] or ""):
            note += (f"; CHECK: they point at different directories ('{cur['search_in'] or 'any'}' and "
                     f"'{m['search_in'] or 'any'}'), so they may be different groups. The first is used")
        if m["member_type"] != cur["member_type"]:
            note += f"; member types differ ({cur['member_type']}/{m['member_type']}), {cur['member_type']} used"
        cur["notes"] = [n for n in cur["notes"] if not n.startswith("merged source members")] + [note]
        cur["notes"].extend(n for n in m["notes"] if n not in cur["notes"])
    return out
