#!/usr/bin/env python3
"""
Build a FAKE sample data pack for trying the Idira Migration Workbench.

Writes a ready-to-use workspace:

  <out>/config.json                      starter mapping rules matching the data
  <out>/inbox/delinea_export.csv         Delinea Secret Server multi-template export (fake secrets)
  <out>/inbox/delinea_permissions.csv    folder- and secret-level group permissions
  <out>/inbox/delinea_export.xml         Delinea Secret Server XML export with folder permissions (fake secrets)
  <out>/inbox/keepass_export.xml         KeePass 2.x XML export (fake secrets)
  <out>/inbox/it_inventory.xlsx          spreadsheet inventory, one account per row
  <out>/SAMPLE_DATA_README.txt           what is in it, and the problems planted on purpose

Then:  python -m imw ui --workspace <out>

Every name, host and password is invented (example.com / corp.example.com). The
data deliberately contains the problems a real migration has, so each review
list in the Workbench has something in it.
"""

import argparse
import csv
import json
import random
import sys
import uuid
from base64 import b64encode
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from xlsx_writer import write_xlsx  # noqa: E402

DOMAIN = "corp.example.com"
GROUPS = {
    "win": "CORP\\PAM-Windows-Admins", "unix": "CORP\\PAM-Unix-Admins", "dba": "CORP\\PAM-DBA",
    "net": "CORP\\PAM-Network", "web": "CORP\\PAM-Web-Ops", "pay": "CORP\\APP-Payments-Owners",
    "shop": "CORP\\APP-Storefront-Owners", "hr": "CORP\\APP-HRPortal-Owners",
    "help": "CORP\\Helpdesk", "audit": "CORP\\Security-Audit",
}


def pw(rnd):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@"
    return "FAKE-" + "".join(rnd.choice(chars) for _ in range(14))


def fake_key(rnd):
    body = b64encode(bytes(rnd.getrandbits(8) for _ in range(96))).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY{body}\n-----END OPENSSH PRIVATE KEY-----"


# --------------------------------------------------------------------------- #
# Delinea
# --------------------------------------------------------------------------- #
TEMPLATES = [
    # template, address column, secret column, extra columns, weight
    ("Active Directory Account", "Domain", "Password", [], 25),
    ("Windows Account", "Machine", "Password", [], 20),
    ("Unix Account (SSH)", "Machine", "Password", ["Port"], 18),
    ("Unix Account (SSH Key Rotation)", "Machine", "Private Key", ["Private Key Passphrase"], 6),
    ("SQL Server Account", "Server", "Password", ["Port", "Database"], 12),
    ("Oracle Account", "Server", "Password", ["Port", "Database"], 6),
    ("Web Password", "URL", "Password", ["Attachment"], 10),
    ("Cisco Account (SSH)", "Host", "Password", ["Enable Password"], 5),
]
FOLDERS = [
    ("\\Infrastructure\\Windows\\Domain Controllers", "win", "Active Directory Account"),
    ("\\Infrastructure\\Windows\\Member Servers", "win", "Windows Account"),
    ("\\Infrastructure\\Windows\\Member Servers\\Legacy 2012R2", "win", "Windows Account"),
    ("\\Infrastructure\\Linux\\Web Tier", "unix", "Unix Account (SSH)"),
    ("\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs", "unix", "Unix Account (SSH)"),
    ("\\Infrastructure\\Linux\\Deploy Keys", "unix", "Unix Account (SSH Key Rotation)"),
    ("\\Databases\\SQL Production", "dba", "SQL Server Account"),
    ("\\Databases\\SQL Production Reporting Replicas EU West", "dba", "SQL Server Account"),
    ("\\Databases\\SQL Production Reporting Replicas EU East", "dba", "SQL Server Account"),
    ("\\Databases\\Oracle Finance", "dba", "Oracle Account"),
    ("\\Infrastructure\\Network\\Core Switches", "net", "Cisco Account (SSH)"),
    ("\\Web\\Vendor Portals", "web", "Web Password"),
    ("\\Applications\\Payments\\Prod", "pay", "Windows Account"),
    ("\\Applications\\Storefront\\Prod", "shop", "Unix Account (SSH)"),
    ("\\Applications\\HR Portal \"Self-Service\"", "hr", "Web Password"),
    ("\\Unfiled", None, "Windows Account"),
]


def delinea(out, rnd, count):
    rows_by_template = {t[0]: [] for t in TEMPLATES}
    sid = 20001
    names_used = []
    for n in range(count):
        folder, team, tmpl_name = rnd.choice(FOLDERS)
        tmpl = next(t for t in TEMPLATES if t[0] == tmpl_name)
        _, addr_col, secret_col, extras, _ = tmpl
        host = f"{rnd.choice(['srv', 'app', 'db', 'web', 'sw', 'bat'])}{rnd.randint(1, 499):03d}.{DOMAIN}"
        if tmpl_name == "Active Directory Account":
            user = rnd.choice(["svc_", "adm_"]) + rnd.choice(["backup", "sql", "iis", "sccm", "scan", "deploy"]) + str(rnd.randint(1, 60))
            address = DOMAIN
        elif tmpl_name == "Web Password":
            user = rnd.choice(["ap_team", "ops", "admin", "billing"])
            address = f"https://{rnd.choice(['portal', 'billing', 'support'])}.vendor{rnd.randint(1, 9)}.example.com/login"
        else:
            user = rnd.choice({"Windows Account": ["Administrator", "Administrator", "svc_app", "localadmin"],
                               "Unix Account (SSH)": ["root", "root", "svc_app", "deploy"],
                               "Unix Account (SSH Key Rotation)": ["deploy", "ansible", "root"],
                               "SQL Server Account": ["sa", "svc_sql", "dbadmin"],
                               "Oracle Account": ["system", "oracle", "svc_ora"],
                               "Cisco Account (SSH)": ["admin", "enable"]}.get(tmpl_name, ["admin"]))
            address = host
        name = f"{user}@{address.split('/')[2] if address.startswith('http') else address.split('.')[0]}"
        if n % 53 == 7 and names_used:
            name = rnd.choice(names_used)            # duplicate secret name
        names_used.append(name)
        if n % 71 == 3:
            address = ""                             # missing address
        if n % 89 == 5:
            user = ""                                # missing username -> ERROR
        row = {"Secret ID": sid, "Secret Name": name, "Folder Path": folder, addr_col: address,
               "Username": user, "Notes": f"Sample record {n}"}
        if secret_col == "Private Key":
            row["Private Key"] = fake_key(rnd)
            row["Private Key Passphrase"] = pw(rnd) if n % 3 == 0 else ""
        else:
            row["Password"] = pw(rnd) if n % 97 != 11 else ""   # a few empty secrets
        if "Port" in extras:
            row["Port"] = {"SQL Server Account": "1433", "Oracle Account": "1521"}.get(tmpl_name, "22")
        if "Database" in extras:
            row["Database"] = rnd.choice(["FINPROD", "RPT01", "CRM", "master"])
        if "Enable Password" in extras:
            row["Enable Password"] = pw(rnd)
        if "Attachment" in extras and n % 4 == 0:
            row["Attachment"] = "vendor_contract.pdf"
        rows_by_template[tmpl_name].append(row)
        sid += 1

    path = out / "delinea_export.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for name, addr_col, secret_col, extras, _ in TEMPLATES:
            rows = rows_by_template[name]
            if not rows:
                continue
            cols = ["Secret ID", "Secret Name", "Folder Path", addr_col, "Username", secret_col] + extras + ["Notes"]
            w.writerow([name])
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c, "") for c in cols])
            w.writerow([])

    perms = out / "delinea_permissions.csv"
    with open(perms, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Folder Path", "Secret Name", "Secret ID", "Group", "Permission"])
        for folder, team, _ in FOLDERS:
            if team is None:
                continue                                         # \Unfiled has no permissions
            w.writerow([folder, "", "", GROUPS[team], "Owner"])
            w.writerow([folder, "", "", GROUPS["help"], "List"])
            w.writerow([folder, "", "", GROUPS["audit"], "View"])
        w.writerow(["\\Infrastructure\\Linux", "", "", GROUPS["win"], "View"])   # mixed permissions
        for r in rows_by_template["Web Password"][:4]:                           # secret-level overrides
            w.writerow([r["Folder Path"], r["Secret Name"], r["Secret ID"], GROUPS["pay"], "Edit"])
    return sum(len(v) for v in rows_by_template.values())


def delinea_xml(out, rnd, count):
    """Secret Server XML export (Advanced Import/Export format), UTF-16 like Secret Server
    writes it, with folder permissions, inheritance and secret-level overrides."""
    def x(v):
        return escape(str(v))

    def perms(grants, ind):
        if not grants:
            return f"{ind}<Permissions />"
        lines = [f"{ind}<Permissions>"]
        for group, role in grants:
            domain, name = group.split("\\", 1)
            lines += [f"{ind}  <Permission>", f"{ind}    <GroupName>{x(name)}</GroupName>",
                      f"{ind}    <DomainName>{x(domain)}</DomainName>",
                      f"{ind}    <FolderAccessRoleName>{x('View' if role == 'List' else role)}</FolderAccessRoleName>",
                      f"{ind}    <SecretAccessRoleName>{x(role)}</SecretAccessRoleName>", f"{ind}  </Permission>"]
        return "\n".join(lines + [f"{ind}</Permissions>"])

    # Folder permissions: each team folder lists its own; "Legacy 2012R2" lists none, so it
    # inherits from "Member Servers"; the top-level folders list none; \Unfiled has none at all.
    folder_grants = {}
    for folder, team, _ in FOLDERS:
        if team and "Legacy" not in folder:
            folder_grants[folder] = [(GROUPS[team], "Owner"), (GROUPS["help"], "List"), (GROUPS["audit"], "View")]
    all_folders = set()
    for folder, _, _ in FOLDERS:
        levels = folder.strip("\\").split("\\")
        for i in range(1, len(levels) + 1):
            all_folders.add("\\" + "\\".join(levels[:i]))
    xml = ['<?xml version="1.0" encoding="utf-16"?>',
           '<!-- FAKE Delinea Secret Server XML export: every name, host and password is invented. -->',
           '<ImportFile xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
           "  <Folders>"]
    for folder in sorted(all_folders, key=lambda f: (f.count("\\"), f)):
        xml += ["    <Folder>", f"      <FolderName>{x(folder.rsplit(chr(92), 1)[-1])}</FolderName>",
                f"      <FolderPath>{x(folder)}</FolderPath>", perms(folder_grants.get(folder), "      "), "    </Folder>"]
    xml += ["  </Folders>", "  <SecretTemplates>"]
    for name, addr_col, secret_col, extras, _ in TEMPLATES:
        fields = [(addr_col, False, addr_col == "URL", False), ("Username", False, False, False),
                  (secret_col, True, False, False)]
        fields += [(e, "Password" in e or "Passphrase" in e, False, e == "Attachment") for e in extras]
        fields.append(("Notes", False, False, False))
        xml += ["    <secrettype>", f"      <name>{x(name)}</name>", "      <active>true</active>", "      <fields>"]
        for fname, is_pw, is_url, is_file in fields:
            xml.append(f"        <field><displayname>{x(fname)}</displayname><name>{x(fname)}</name>"
                       f"<isurl>{str(is_url).lower()}</isurl><ispassword>{str(is_pw).lower()}</ispassword>"
                       f"<isnotes>{str(fname == 'Notes').lower()}</isnotes><isfile>{str(is_file).lower()}</isfile></field>")
        xml += ["      </fields>", "    </secrettype>"]
    xml += ["  </SecretTemplates>", "  <Secrets>"]
    for n in range(count):
        folder, team, tmpl_name = rnd.choice(FOLDERS)
        _, addr_col, secret_col, extras, _ = next(t for t in TEMPLATES if t[0] == tmpl_name)
        user = rnd.choice(["Administrator", "root", "svc_app", "deploy", "sa", "admin"])
        host = f"{rnd.choice(['srv', 'app', 'db', 'web'])}{rnd.randint(1, 499):03d}.{DOMAIN}"
        address = f"https://portal.vendor{rnd.randint(1, 9)}.example.com/login" if addr_col == "URL" else host
        items = [(addr_col, address), ("Username", user),
                 (secret_col, fake_key(rnd) if secret_col == "Private Key" else pw(rnd))]
        for e in extras:
            items.append((e, {"Port": "22", "Database": "FINPROD", "Attachment": "contract.pdf"}.get(e, pw(rnd))))
        items.append(("Notes", f"Sample XML record {n}"))
        override = [(GROUPS["pay"], "Edit")] if n % 17 == 4 else None     # secret-level permissions
        xml += ["    <Secret>", f"      <SecretName>{x(user)}@{x(host.split('.')[0])}</SecretName>",
                f"      <SecretTemplateName>{x(tmpl_name)}</SecretTemplateName>",
                f"      <FolderPath>{x(folder)}</FolderPath>", "      <SecretItems>"]
        for fname, val in items:
            xml.append(f"        <SecretItem><FieldName>{x(fname)}</FieldName><Value>{x(val)}</Value></SecretItem>")
        xml += ["      </SecretItems>", "      <SecretDependencies />", perms(override, "      "), "    </Secret>"]
    xml += ["  </Secrets>", "  <Groups />", "</ImportFile>", ""]
    (out / "delinea_export.xml").write_bytes("\r\n".join(xml).encode("utf-16"))
    return count


# --------------------------------------------------------------------------- #
# KeePass
# --------------------------------------------------------------------------- #
def keepass(out, rnd, count):
    tree = {"Network": ["Firewalls", "Wireless"], "Linux": ["Lab Servers", "DMZ: Edge/Proxy"],
            "Cloud": ["Azure Subscriptions", "AWS Accounts"], "Vendors": []}
    entries = {g: [] for g in [f"{a}/{b}" for a, bs in tree.items() for b in bs] + ["Vendors"]}
    keys = list(entries)
    for n in range(count):
        g = rnd.choice(keys)
        if g.startswith("Network"):
            title, user, url = f"fw{n:02d} admin GUI", "admin", f"https://fw{n:02d}.{DOMAIN}/login"
        elif g.startswith("Linux"):
            title, user, url = f"root@lab{n:02d}", "root", f"ssh://lab{n:02d}.{DOMAIN}:22"
        elif g.startswith("Cloud"):
            title, user, url = f"break-glass {n:02d}", f"breakglass{n:02d}@example.onmicrosoft.com", "https://portal.azure.com"
        else:
            title, user, url = f"vendor portal {n:02d}", rnd.choice(["accounts", "ops"]), f"https://vendor{n:02d}.example.com"
        if n % 37 == 4:
            user = ""
        e = {"uuid": b64encode(uuid.UUID(int=rnd.getrandbits(128)).bytes).decode(), "Title": title,
             "UserName": user, "Password": pw(rnd), "URL": url, "Notes": f"KeePass sample {n}",
             "attach": n % 9 == 0}
        if g == "Linux/Lab Servers" and n % 5 == 0:
            e["SSH Private Key"] = fake_key(rnd)
            e["Password"] = ""
        if g.startswith("Linux"):
            e["Port"] = "22"
        entries[g].append(e)

    def entry_xml(e, ind):
        s = [f"{ind}<Entry>", f"{ind}\t<UUID>{e['uuid']}</UUID>"]
        for k in ("Title", "UserName", "Password", "URL", "Notes", "Port", "SSH Private Key"):
            if k in e:
                prot = ' ProtectInMemory="True"' if k in ("Password", "SSH Private Key") else ""
                s.append(f"{ind}\t<String><Key>{k}</Key><Value{prot}>{escape(e[k])}</Value></String>")
        if e["attach"]:
            s.append(f"{ind}\t<Binary><Key>notes.txt</Key><Value Ref=\"0\" /></Binary>")
        s.append(f"{ind}\t<History><Entry><UUID>{e['uuid']}</UUID><String><Key>Password</Key>"
                 f"<Value>FAKE-old-password</Value></String></Entry></History>")
        s.append(f"{ind}</Entry>")
        return "\n".join(s)

    def gid(name):
        return b64encode(uuid.uuid5(uuid.NAMESPACE_DNS, name).bytes).decode()

    recycle = gid("Recycle Bin")
    xml = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>', "<KeePassFile>",
           "\t<Meta>", "\t\t<Generator>KeePass</Generator>", "\t\t<DatabaseName>IT Ops Vault</DatabaseName>",
           f"\t\t<RecycleBinUUID>{recycle}</RecycleBinUUID>", "\t</Meta>", "\t<Root>", "\t\t<Group>",
           f"\t\t\t<UUID>{gid('root')}</UUID>", "\t\t\t<Name>IT Ops Vault</Name>"]
    for top, subs in tree.items():
        xml += ["\t\t\t<Group>", f"\t\t\t\t<UUID>{gid(top)}</UUID>", f"\t\t\t\t<Name>{escape(top)}</Name>"]
        for e in entries.get(top, []):
            xml.append(entry_xml(e, "\t\t\t\t"))
        for sub in subs:
            xml += ["\t\t\t\t<Group>", f"\t\t\t\t\t<UUID>{gid(top + sub)}</UUID>", f"\t\t\t\t\t<Name>{escape(sub)}</Name>"]
            xml += [entry_xml(e, "\t\t\t\t\t") for e in entries[f"{top}/{sub}"]]
            xml.append("\t\t\t\t</Group>")
        xml.append("\t\t\t</Group>")
    xml += ["\t\t\t<Group>", f"\t\t\t\t<UUID>{recycle}</UUID>", "\t\t\t\t<Name>Recycle Bin</Name>",
            entry_xml({"uuid": gid("deleted"), "Title": "deleted test entry", "UserName": "old",
                       "Password": "FAKE-deleted", "URL": "", "Notes": "", "attach": False}, "\t\t\t\t"),
            "\t\t\t</Group>", "\t\t</Group>", "\t</Root>", "</KeePassFile>"]
    (out / "keepass_export.xml").write_text("\n".join(xml), encoding="utf-8")
    return count


# --------------------------------------------------------------------------- #
# Spreadsheet
# --------------------------------------------------------------------------- #
def spreadsheet(out, rnd, count):
    header = ["Account Name", "Hostname", "Login", "Password", "Account Type", "Folder", "Access",
              "Target Safe", "Owner Team", "Port"]
    rows = [header]
    for n in range(count):
        kind = rnd.choice(["Windows Account", "Windows Account", "SQL Server Account", "Mainframe Login",
                           "Unix Account (SSH)"])
        host = f"{'mf' if kind == 'Mainframe Login' else 'app'}{rnd.randint(500, 999)}.{DOMAIN}"
        login = {"Windows Account": "Administrator", "SQL Server Account": "sa",
                 "Mainframe Login": "MFADMIN", "Unix Account (SSH)": "svc_batch"}[kind]
        folder = {"Windows Account": "Applications/HR Portal", "SQL Server Account": "Databases/HR",
                  "Mainframe Login": "Legacy/Mainframe", "Unix Account (SSH)": "Applications/Batch"}[kind]
        access = f"{GROUPS['hr']}=Full; {GROUPS['help']}=Read" if "HR" in folder else \
            (f"{GROUPS['dba']}=Full" if "Databases" in folder else
             (f"CORP\\Mainframe-Ops=Write" if kind == "Mainframe Login" else f"{GROUPS['unix']}=Full"))
        target = "APP-HRPortal" if n % 10 == 0 and "HR" in folder else ""
        if n % 25 == 3:
            access = ""
        rows.append([f"{login}-{host.split('.')[0]}", host, login if n % 41 != 9 else "", pw(rnd), kind, folder,
                     access, target, rnd.choice(["HR IT", "DBA Team", "Mainframe Team", "Batch Ops"]),
                     {"SQL Server Account": 1433, "Unix Account (SSH)": 22}.get(kind, "")])
    write_xlsx(out / "it_inventory.xlsx", {"Accounts": rows,
                                           "Read me": [["Exported from the IT asset register (sample)."]]})
    return count


CONFIG = {
    "_comment": "Starter rules for the sample pack. Edit them on the Mapping rules page.",
    "config_version": 2,
    "folder_rules": [
        {"folder_prefix": "\\Cloud", "safe": "CLD-BG-{flavor}-{acct}"},
    ],
    "safe_convention": {
        "default_environment": "P",
        "abbreviations": {"Self-Service": "SS", "HR Portal": "HR", "Unfiled": "UNF"},
    },
    "custom_roles": {
        "List only": ["listAccounts"],
        "Helpdesk": ["listAccounts", "useAccounts", "retrieveAccounts", "viewAuditLog"],
    },
    "platform_map": {
        "Active Directory Account": "WinDomain", "Windows Account": "WinServerLocal",
        "Unix Account (SSH)": "UnixSSH", "Unix Account (SSH Key Rotation)": "UnixSSHKeys",
        "SQL Server Account": "MSSql", "Oracle Account": "Oracle", "Web Password": "GenericWebApp",
    },
    "platform_rules": [
        {"field": "folder", "pattern": "(?i)^\\\\Linux", "platform": "UnixSSH"},
        {"field": "folder", "pattern": "(?i)^\\\\(Network|Vendors)", "platform": "GenericWebApp"},
        {"field": "folder", "pattern": "(?i)^\\\\Cloud", "platform": "AzureWebAccount"},
    ],
    "directory_map": {"CORP": DOMAIN, "*": "Vault"},
    "account_property_map": {"Port": "Port", "Database": "Database"},
}

README = """IDIRA MIGRATION WORKBENCH SAMPLE DATA PACK - every name, host and password here is FAKE.

Start the Workbench on this folder:
    python -m imw ui --workspace "{out}"
(on Linux/macOS add --insecure-plaintext-secrets; on Windows secrets are encrypted with DPAPI)

inbox/
  delinea_export.csv       {d} Delinea secrets in 8 templates, multi-header format, fake passwords and SSH keys
  delinea_permissions.csv  tick this one as the "permissions file" when loading the Delinea export
  delinea_export.xml       {dx} Delinea secrets as a Secret Server XML export (UTF-16), with its own folder
                           and secret permissions: no permissions file needed
  keepass_export.xml       {k} KeePass entries in nested groups (plus a Recycle Bin entry and history that are skipped)
  it_inventory.xlsx        {x} rows from a spreadsheet: one account per row, an Access column, some Target Safe values
config.json                starter mapping rules (open "Mapping rules" to see and change them)

Problems planted on purpose, so the review lists have something to show:
  - Safe names over 28 characters, two that collide after shortening (SQL ... Replicas EU West/East)
  - Invalid Safe-name characters (Batch: Nightly/Weekly Jobs, HR Portal "Self-Service")
  - A record type with no platform yet: "Mainframe Login" -> Errors list
  - Missing usernames (Errors) and missing addresses
  - Empty secrets, SSH keys with passphrases, attachments that are not migrated
  - Duplicate secret names, folders with no permissions (\\Unfiled), mixed permissions
  - Spreadsheet rows with no Access value, and rows that name their Safe directly

Things to try:
  1. Load delinea_export.csv, keepass_export.xml and it_inventory.xlsx (tick delinea_permissions.csv as the
     permissions file). delinea_export.xml is a separate set of Delinea secrets: load it too, or on its own
     in a fresh workspace, to try the XML import with its built-in folder permissions.
  2. Mapping rules: give "Mainframe Login" a platform (pick one from the Platform ID list), Save.
  3. Review & change: open "Errors", "Safe name was changed", "No access groups"; move or exclude some accounts.
  4. Create upload files: first a dry run, then one wave (e.g. one Safe) upload-ready.
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="sample_workspace")
    ap.add_argument("--delinea", type=int, default=400)
    ap.add_argument("--delinea-xml", type=int, default=80)
    ap.add_argument("--keepass", type=int, default=60)
    ap.add_argument("--excel", type=int, default=120)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    out = Path(args.out)
    inbox = out / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    d = delinea(inbox, rnd, args.delinea)
    dx = delinea_xml(inbox, rnd, args.delinea_xml)
    k = keepass(inbox, rnd, args.keepass)
    x = spreadsheet(inbox, rnd, args.excel)
    (out / "config.json").write_text(json.dumps(CONFIG, indent=2), encoding="utf-8")
    (out / "SAMPLE_DATA_README.txt").write_text(README.format(out=out, d=d, dx=dx, k=k, x=x), encoding="utf-8")
    print(f"Wrote sample workspace to {out.resolve()}: {d} Delinea CSV, {dx} Delinea XML, {k} KeePass, {x} spreadsheet records.")
    print(f"Start it with: python -m imw ui --workspace \"{out}\"")


if __name__ == "__main__":
    main()
