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

SAFE_FIELDS = ["safeName", "description", "location", "managingCPM",
               "numberOfVersionsRetention", "numberOfDaysRetention", "olacEnabled", "autoPurgeEnabled"]
ACCOUNT_FIELDS = ["safeName", "platformId", "name", "address", "userName", "secretType", "secret",
                  "secretManagement.automaticManagementEnabled",
                  "secretManagement.manualManagementReason"]


# Accounts.csv column -> Vault file category (what the account stores it as) and a note.
FILE_CATEGORIES = {
    "safeName": ("", "Safe the account is stored in (not a file category)"),
    "platformId": ("PolicyID", "Platform ID"),
    "name": ("", "Account (object) name in the Safe (not a file category)"),
    "address": ("Address", "Target address"),
    "userName": ("UserName", "Account username"),
    "secretType": ("", "password or key (the type of the account's secret)"),
    "secret": ("", "The password or private key itself"),
    "secretManagement.automaticManagementEnabled": ("CPMDisabled", "false sets CPMDisabled on the account"),
    "secretManagement.manualManagementReason": ("CPMDisabled", "Text stored in CPMDisabled when the CPM does not manage it"),
}


def _category(col):
    if col.startswith("platformAccountProperties."):
        prop = col.split(".", 1)[1]
        return prop, "Platform account property from the source column(s) mapped in account_property_map"
    return FILE_CATEGORIES.get(col, ("", ""))


def write_categories(out, header, rows):
    """FileCategories.csv: every Accounts.csv column and how often it is filled.
    PlatformProperties.csv: per platform, which file categories its accounts use."""
    cols = header[1:]                                   # without recordId
    used = {c: 0 for c in cols}
    per_platform = {}
    for row in rows:
        plat = row["platformId"]
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


def _fmt(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else str(v)


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
    with _open(safes) as fh:
        w = csv.writer(fh)
        w.writerow(SAFE_FIELDS)
        for name in upload_safes:
            body = safe_settings(name, plan.safes[name], cfg)
            w.writerow([_fmt(body.get(f, "")) for f in SAFE_FIELDS])

    members = out / "SafeMembers.csv"
    skipped_members = 0
    roles = all_roles(cfg)
    with _open(members) as fh:
        w = csv.writer(fh)
        w.writerow(["safeName", "memberName", "memberType", "searchIn", "role"] +
                   [f"permissions.{p}" for p in ALL_PERMISSIONS])
        for (safe, _), m in plan.members.items():
            if m["role"] not in roles:
                skipped_members += 1
                continue
            granted = set(roles[m["role"]])
            w.writerow([safe, m["member_name"], m["member_type"], m["search_in"], m["role"]] +
                       [_fmt(p in granted) for p in ALL_PERMISSIONS])

    prop_map = cfg["account_property_map"]
    prop_cols = list(dict.fromkeys(prop_map.values()))
    acct_defaults = cfg["account_defaults"]
    accounts = out / "Accounts.csv"
    count = 0
    header = ["recordId"] + ACCOUNT_FIELDS + [f"platformAccountProperties.{c}" for c in prop_cols]
    usage = []
    with _open(accounts) as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(header)
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
            values = [r.record_id, p.safe, p.platform, p.account_name, r.address, r.username,
                      r.secret_type, r.secret if include_secrets else "",
                      _fmt(acct_defaults.get("automaticManagementEnabled", False)),
                      "" if acct_defaults.get("automaticManagementEnabled") else
                      acct_defaults.get("manualManagementReason", "")] + [props.get(c, "") for c in prop_cols]
            w.writerow(values)
            row = dict(zip(header, values))
            row["secret"] = "x" if r.has_secret or (r.secret or "").strip() else ""   # usage only, never the value
            usage.append(row)
            count += 1
    if include_secrets:
        restrict(accounts)
    extra_files = write_categories(out, header, usage)
    return [safes, members, accounts] + extra_files, {"safes": len(upload_safes), "members": len(plan.members) -
                                        skipped_members, "members_skipped": skipped_members,
                                        "accounts": count}


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
