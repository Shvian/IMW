#!/usr/bin/env python3
"""
Generate realistic SYNTHETIC Delinea Secret Server data for testing the
migration without access to Delinea.

Writes to --out:
  delinea_export_synthetic.csv       multi-template, multi-header export with Secret IDs
                                     (metadata only; --with-values adds fake password values,
                                     to mimic a full export and exercise Phase 1's scrubbing)
  delinea_permissions_synthetic.csv  folder- and secret-level group permissions
  mapping_config_synthetic.json      a Phase 1 config with group rules for the generated groups

It deliberately includes the messy cases a real export has: long and invalid
folder names (Safe-name truncation, invalid characters, collisions), duplicate
secret names, empty usernames/addresses, an unmapped template, secrets with no
permissions, mixed permissions for one group, and secret-level overrides.

Pass your REAL AD/Entra group names with --groups to make a rehearsal also
prove that CyberArk can find those groups. No real secret is ever produced.

  python generate_synthetic_delinea.py --secrets 2000 --out synthetic \
      --groups "CORP\\PAM-Windows-Admins" "CORP\\PAM-Unix-Admins" "CORP\\PAM-DBA"
"""

import argparse
import csv
import json
import random
from pathlib import Path

TEMPLATES = OrderedTemplates = [
    # name, address column, secret column, weight
    ("Active Directory Account", "Domain", "Password", 30),
    ("Windows Account", "Machine", "Password", 20),
    ("Unix Account (SSH)", "Machine", "Password", 20),
    ("Unix Account (SSH Key Rotation)", "Machine", "Private Key", 8),
    ("SQL Server Account", "Server", "Password", 10),
    ("Web Password", "URL", "Password", 10),
    ("Legacy Mainframe Login", "Host", "Password", 2),   # deliberately unmapped
]

DEFAULT_GROUPS = ["CORP\\PAM-Windows-Admins", "CORP\\PAM-Unix-Admins", "CORP\\PAM-DBA",
                  "CORP\\PAM-Web-Ops", "CORP\\PAM-Network", "CORP\\APP-Payments-Owners",
                  "CORP\\APP-Storefront-Owners", "CORP\\Helpdesk"]

FOLDERS = [
    ("\\Infrastructure\\Windows\\Domain Controllers", 0),
    ("\\Infrastructure\\Windows\\Member Servers", 0),
    ("\\Infrastructure\\Linux\\Web Tier", 1),
    ("\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs", 1),    # invalid chars
    ("\\Databases\\SQL Production", 2),
    ("\\Databases\\SQL Production Reporting Replicas EU West", 2),  # truncation
    ("\\Databases\\SQL Production Reporting Replicas EU East", 2),  # collides after truncation
    ("\\Web\\Vendor Portals", 3),
    ("\\Network\\Firewalls", 4),
    ("\\Applications\\Payments\\Prod", 5),
    ("\\Applications\\Storefront\\Prod", 6),
    ("\\Unfiled", None),                                             # no permissions
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--secrets", type=int, default=500)
    ap.add_argument("--out", default="synthetic")
    ap.add_argument("--groups", nargs="+", help="Real group names to use (in the order of the default roles)")
    ap.add_argument("--with-values", action="store_true", help="Add FAKE secret values, like a full export")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--start-id", type=int, default=10001)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    groups = list(DEFAULT_GROUPS)
    for i, g in enumerate(args.groups or []):
        if i < len(groups):
            groups[i] = g
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    weights = [t[3] for t in TEMPLATES]
    by_template = {t[0]: [] for t in TEMPLATES}
    sid = args.start_id
    for n in range(args.secrets):
        tmpl = rnd.choices(TEMPLATES, weights=weights)[0]
        name, addr_col, secret_col, _ = tmpl
        if "Unix" in name:
            folder = rnd.choice([f for f in FOLDERS if f[1] == 1])[0]
        elif "SQL" in name:
            folder = rnd.choice([f for f in FOLDERS if f[1] == 2])[0]
        elif "Web" in name:
            folder = rnd.choice([f for f in FOLDERS if f[1] in (3, 5, 6)])[0]
        elif "Mainframe" in name:
            folder = "\\Unfiled"
        else:
            folder = rnd.choice([f for f in FOLDERS if f[1] in (0, 4)])[0]
        host = f"{rnd.choice(['srv', 'app', 'db', 'web', 'fw'])}{rnd.randint(1, 400):03d}.corp.example.com"
        user = rnd.choice(["svc_", "adm_", "root", "oracle", "sa", "admin"])
        user = user + f"{rnd.randint(1, 999)}" if user.endswith("_") else user
        address = {"Domain": "corp.example.com", "URL": f"https://{host}"}.get(addr_col, host)
        secret_name = f"{user}@{host.split('.')[0]}"
        if n % 97 == 0:
            secret_name = by_template[name][-1]["Secret Name"] if by_template[name] else secret_name  # duplicate name
        if n % 131 == 0:
            address = ""                                                                            # missing address
        row = {"Secret ID": sid, "Secret Name": secret_name, "Folder Path": folder,
               addr_col: address, "Username": user, "Notes": f"synthetic record {n}"}
        if args.with_values:
            row[secret_col] = ("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----"
                               if secret_col == "Private Key" else f"FAKE-{rnd.getrandbits(48):x}")
        by_template[name].append(row)
        sid += 1

    export = out / "delinea_export_synthetic.csv"
    with open(export, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for name, addr_col, secret_col, _ in TEMPLATES:
            rows = by_template[name]
            if not rows:
                continue
            cols = ["Secret ID", "Secret Name", "Folder Path", addr_col, "Username"]
            cols += [secret_col] if args.with_values else []
            cols += ["Notes"]
            w.writerow([name])
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c, "") for c in cols])
            w.writerow([])

    perms = out / "delinea_permissions_synthetic.csv"
    with open(perms, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Folder Path", "Secret Name", "Secret ID", "Group", "Permission"])
        for folder, gi in FOLDERS:
            if gi is None:
                continue
            w.writerow([folder, "", "", groups[gi], "Owner"])
            w.writerow([folder, "", "", groups[7], "List"])          # helpdesk sees everything listed
        w.writerow(["\\Infrastructure\\Linux", "", "", groups[0], "View"])  # mixed permissions
        # A few secret-level overrides (broken inheritance)
        web = by_template["Web Password"][:3]
        for r in web:
            w.writerow([r["Folder Path"], r["Secret Name"], r["Secret ID"], groups[3], "Edit"])

    safe_for = ["WIN-Admins", "UNIX-Admins", "DB-SQL-Production", "WEB-Vendor-Portals", "NET-Firewalls",
                "APP-Payments", "APP-Storefront"]
    cfg = {
        "_comment": "Generated for synthetic data. min_permission=Owner keeps Helpdesk List grants from choosing Safes.",
        "group_rules": [{"group": groups[i], "safe": safe_for[i], "min_permission": "Owner"} for i in range(7)],
        "fallback_strategy": "folder_path",
    }
    cfgp = out / "mapping_config_synthetic.json"
    cfgp.write_text(json.dumps(cfg, indent=2))
    total = sum(len(v) for v in by_template.values())
    print(f"Wrote {total} synthetic secrets across {sum(1 for v in by_template.values() if v)} templates:")
    for p in (export, perms, cfgp):
        print(f"  {p}")
    print("No real secrets." + ("" if args.with_values else " Export is metadata-only."))


if __name__ == "__main__":
    main()
