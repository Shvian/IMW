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
    if plan.undecided:
        path = out / "Users_To_Decide.csv"
        with _open(path) as fh:
            w = csvsafe.SafeWriter(csv.writer(fh))
            w.writerow(["Folder", "Target_Safe", "Source_Member", "Member_Name", "Source_Permission",
                        "Groups_With_This_Access", "Accounts", "Decision", "Notes"])
            for h in plan.undecided:
                w.writerow([h["folder"], h["safe"], h["member"], h["member_name"], h["permission"],
                            h["groups"], h["accounts"], h["decision"] or "not decided", h["note"]])
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
# Safe naming convention: the parts of the Safe names the upload creates, to keep naming Safes the same way
# --------------------------------------------------------------------------- #
def convention_rows(plan, cfg):
    """(header, rows): the parts of every Safe name the upload creates. Each name is split on the
    separator, and column varN lists every value used as its Nth part, so the effective convention
    ({var1}-{var2}-{var3}-{var4}) and its codes can name new Safes after go-live. Personal Safes
    follow their own pattern and are left out."""
    sep = (cfg.get("safe_convention") or {}).get("separator", "-") or "-"
    parts = []
    for name, s in plan.safes.items():
        if not s["migrating"]:
            continue
        sources = s.get("sources") or set()
        if sources and all(str(x).startswith("personal:") for x in sources):
            continue
        for i, part in enumerate(name.split(sep)):
            while len(parts) <= i:
                parts.append(set())
            if part:
                parts[i].add(part)
    cols = [sorted(p, key=lambda v: (v.lower(), v)) for p in parts]
    header = [f"var{i + 1}" for i in range(max(len(cols), 1))]
    depth = max((len(c) for c in cols), default=0)
    return header, [[c[r] if r < len(c) else "" for c in cols] for r in range(depth)]


def write_convention(plan, cfg, out_dir):
    path = Path(out_dir) / "review" / "SafeNamingConvention.csv"
    with _open(path) as fh:
        w = csvsafe.SafeWriter(csv.writer(fh))
        header, rows = convention_rows(plan, cfg)
        w.writerow(header)
        for row in rows:
            w.writerow(row)
    return path
