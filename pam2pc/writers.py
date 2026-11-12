"""Output files: review CSVs (no secrets) and upload CSVs (API body fields)."""

import csv
import hashlib
import json
import os
import platform as _platform
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import ALL_PERMISSIONS

SAFE_FIELDS = ["safeName", "description", "location", "managingCPM",
               "numberOfVersionsRetention", "numberOfDaysRetention", "olacEnabled", "autoPurgeEnabled"]
ACCOUNT_FIELDS = ["safeName", "platformId", "name", "address", "userName", "secretType", "secret",
                  "secretManagement.automaticManagementEnabled",
                  "secretManagement.manualManagementReason"]


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
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
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
                        "Y" if r.secret.strip() else "N", r.source, r.source_ref, r.type,
                        r.folder_path, "; ".join(f"{g.member}={g.permission}" for g in p.grants),
                        p.access_source] + [r.extra.get(c, "") for c in extra_cols])

    safes = out / "Safes_Review.csv"
    with _open(safes) as fh:
        w = csv.writer(fh)
        w.writerow(["Target_Safe", "Length", "Valid_Safe_Name", "Proposed_Safe_Names",
                    "Safe_Name_Issues", "Mapping_Sources", "Accounts", "Accounts_To_Upload"])
        for name, s in plan.safes.items():
            w.writerow([name, len(name), "TRUE" if s["valid"] else "FALSE",
                        " | ".join(sorted(s["proposed"])), " | ".join(sorted(s["issues"])),
                        " | ".join(sorted(s["sources"])), s["accounts"], s["migrating"]])

    members = out / "SafeMembers_Review.csv"
    with _open(members) as fh:
        w = csv.writer(fh)
        w.writerow(["Target_Safe", "Source_Member", "Member_Name", "Search_In", "Member_Type",
                    "Source_Permission", "Role", "Accounts_With_Access", "Notes"])
        for (safe, _), m in plan.members.items():
            w.writerow([safe, m["source_name"], m["member_name"], m["search_in"], m["member_type"],
                        m["permission"], m["role"] or "UNMAPPED", m["accounts"], "; ".join(m["notes"])])
    return [accounts, safes, members]


# --------------------------------------------------------------------------- #
# Upload files
# --------------------------------------------------------------------------- #
def write_upload(plan, cfg, out_dir, include_secrets):
    out = Path(out_dir) / "upload"
    upload_safes = [n for n, s in plan.safes.items() if s["migrating"]]

    safes = out / "Safes.csv"
    defaults = cfg["safe_defaults"]
    with _open(safes) as fh:
        w = csv.writer(fh)
        w.writerow(SAFE_FIELDS)
        for name in upload_safes:
            body = dict(defaults, safeName=name)
            w.writerow([_fmt(body.get(f, "")) for f in SAFE_FIELDS])

    members = out / "SafeMembers.csv"
    skipped_members = 0
    roles = cfg["role_permissions"]
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
    with _open(accounts) as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(["recordId"] + ACCOUNT_FIELDS + [f"platformAccountProperties.{c}" for c in prop_cols])
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
            w.writerow([r.record_id, p.safe, p.platform, p.account_name, r.address, r.username,
                        r.secret_type, r.secret if include_secrets else "",
                        _fmt(acct_defaults.get("automaticManagementEnabled", False)),
                        acct_defaults.get("manualManagementReason", "")] +
                       [props.get(c, "") for c in prop_cols])
            count += 1
    if include_secrets:
        restrict(accounts)
    return [safes, members, accounts], {"safes": len(upload_safes), "members": len(plan.members) -
                                        skipped_members, "members_skipped": skipped_members,
                                        "accounts": count}


def write_manifest(out_dir, inputs, files, counts, include_secrets, cfg_path):
    manifest = {
        "tool": "pam2pc", "version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": _platform.node(),
        "includes_secrets": include_secrets,
        "config": str(cfg_path or "(defaults)"),
        "inputs": [{"source": s, "path": str(p), "sha256": sha256(p)} for s, p in inputs],
        "outputs": [{"path": str(Path(f).relative_to(out_dir)), "sha256": sha256(f)} for f in files],
        "counts": counts,
    }
    path = Path(out_dir) / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path
