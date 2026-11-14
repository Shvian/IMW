"""Delinea Secret Server XML exports, text encodings, and Delinea folder-permission reports."""

import unittest

from test_imw import SAMPLES, Base, read_csv

from imw import safexml
from imw.adapters import AdapterError, detect_adapter, get_adapter
from imw.config import CONFIG_VERSION, load_config, upgrade_config
from imw.transform import Permissions, strongest_permission
from imw.ui.server import looks_like_permissions

XML = SAMPLES / "delinea_export.xml"                 # UTF-16 with BOM, folders and permissions
CONVERTED = SAMPLES / "delinea_keepass_converted.xml"  # Delinea's KeePass converter output
XML_SECRETS = ["FAKE-Wq7!rT2mZ9pLk4", "FAKE-b8@Hn3vQx6Ye1", "FAKEKEYb3Blbn", "FAKE-pass-phrase-77",
               "FAKE-Sq1&Prod", "FAKE-Vend0r-Phrase-3", "FAKE-memorable", "FAKE-ünï"]


def records(path):
    return {r.name: r for r in detect_adapter(path).read(path, load_config())}


class Encoding(Base):
    def test_declared_utf16_but_utf8_bytes(self):
        # What Delinea's KeePass converter writes: encoding="utf-16" on plain UTF-8 bytes.
        self.assertTrue(CONVERTED.read_bytes().startswith(b'<?xml version="1.0" encoding="utf-16"?>'))
        self.assertEqual(safexml.parse(CONVERTED).getroot().tag, "ImportFile")

    def test_utf16_with_and_without_bom(self):
        text = XML.read_bytes().decode("utf-16")
        for i, data in enumerate((text.encode("utf-16"), text.encode("utf-16-le"), text.encode("utf-16-be"),
                                  text.encode("utf-8-sig"))):
            p = self.tmp / f"x{i}.xml"
            p.write_bytes(data)
            self.assertEqual(detect_adapter(p).name, "delinea", i)
            self.assertIn("Ünïcode admin@srv099", records(p))

    def test_dtd_refused_in_utf16(self):
        p = self.tmp / "evil.xml"
        p.write_bytes('<?xml version="1.0" encoding="utf-16"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
                      "<ImportFile><Secrets/></ImportFile>".encode("utf-16"))
        with self.assertRaises(AdapterError):
            get_adapter("delinea").read(p, load_config())

    def test_keepass_xml_in_utf16(self):
        p = self.tmp / "kp.xml"
        p.write_bytes((SAMPLES / "keepass_export.xml").read_text(encoding="utf-8").encode("utf-16"))
        self.assertEqual(detect_adapter(p).name, "keepass")
        self.assertTrue(list(detect_adapter(p).read(p, load_config())))

    def test_not_an_import_file(self):
        p = self.tmp / "other.xml"
        p.write_text("<Something/>", encoding="utf-8")
        with self.assertRaises(AdapterError):
            get_adapter("delinea").read(p, load_config())


class DelineaXml(Base):
    def test_converted_keepass_sample(self):
        recs = records(CONVERTED)
        self.assertEqual(len(recs), 2)
        r = recs["Sample Entry #2"]
        self.assertEqual((r.username, r.secret, r.type, r.folder), ("Michael321", "12345", "Kee Pass", ()))
        self.assertIsNone(r.grants)              # empty <Permissions>: a permissions file can add them
        self.assertNotIn("Password", r.extra)
        out = self.convert(CONVERTED)
        row = read_csv(out / "review" / "Accounts_Review.csv")[1]
        self.assertEqual(row["Platform_ID"], "GenericWebApp")
        self.assertEqual(row["Address"], "keepass.info")

    def test_folders_templates_and_permissions(self):
        recs = records(XML)
        self.assertEqual(len(recs), 6)
        inherit = recs["Administrator@srv001"]       # \Infrastructure\Windows has none: takes \Infrastructure's
        self.assertEqual(inherit.access_source, "folder")
        self.assertEqual([(g.member, g.permission, g.member_type) for g in inherit.grants],
                         [("CORP\\PAM-Infra-Admins", "Owner", "Group"), ("CORP\\Helpdesk", "List", "Group")])
        own = recs["svc_backup@srv002"]              # secret-level permissions replace the folder's
        self.assertEqual(own.access_source, "record")
        self.assertEqual([(g.member, g.permission, g.member_type) for g in own.grants],
                         [("CORP\\Backup-Operators", "Edit", "Group"), ("CORP\\adm_jdoe", "Owner", "User")])
        self.assertIn("1 secret dependency not migrated", own.notes)
        key = recs["deploy@web01"]
        self.assertEqual(key.secret_type, "key")
        self.assertTrue(key.secret.startswith("-----BEGIN OPENSSH"))
        self.assertIn(("CORP\\jsmith", "View", "User"), [(g.member, g.permission, g.member_type) for g in key.grants])
        self.assertIsNone(recs["sa@sql-prod-01"].grants)        # no permissions anywhere above it
        self.assertEqual(recs["sa@sql-prod-01"].secret, "FAKE-Sq1&Prod<99>")
        portal = recs["Billing portal (Vendor 3)"]
        # Old true/false style; a <Name> listed under <Groups> is a group.
        self.assertEqual([(g.member, g.permission, g.member_type) for g in portal.grants],
                         [("CORP\\APP-Payments-Owners", "Owner", "Group"), ("CORP\\Security-Audit", "View", "Group")])
        # ispassword fields are secrets whatever their name; isfile fields are attachments.
        self.assertEqual(portal.secret, "FAKE-Vend0r-Phrase-3")
        for f in ("Access Phrase", "Memorable Word", "Contract"):
            self.assertNotIn(f, portal.extra)
        self.assertEqual(portal.address, "https://billing.vendor3.example.com/login")
        self.assertEqual(portal.extra["Account Manager"], "Pat Example")
        self.assertTrue(any("Memorable Word" in n for n in portal.notes))
        self.assertTrue(any("attachment field 'Contract'" in n for n in portal.notes))
        self.assertIsNone(recs["Ünïcode admin@srv099"].grants)

    def test_convert_keeps_secrets_out_of_review(self):
        cfg = self.tmp / "cfg.json"
        cfg.write_text('{"platform_rules": [{"field": "type", "pattern": "^Vendor Portal$", "platform": "GenericWebApp"}]}')
        out = self.convert(XML, config=cfg, extra=["--include-secrets"])
        for f in (out / "review").rglob("*"):
            body = f.read_text(encoding="utf-8-sig")
            for s in XML_SECRETS:
                self.assertNotIn(s, body, f"{s!r} leaked into {f.name}")
        accounts = {a["name"]: a for a in read_csv(out / "upload" / "Accounts.csv")}
        self.assertEqual(len(accounts), 6)
        self.assertIn("FAKE-Vend0r-Phrase-3", [a["secret"] for a in accounts.values()])
        members = read_csv(out / "upload" / "SafeMembers.csv")
        got = {(m["safeName"], m["memberName"], m["memberType"]) for m in members}
        self.assertLessEqual({("INF-WIN", "PAM-Infra-Admins", "Group"), ("INF-WIN", "adm_jdoe", "User"),
                              ("APP-PAY", "APP-Payments-Owners", "Group")}, got)

    def test_permissions_file_fills_gaps_only(self):
        perms = self.tmp / "perms.csv"
        perms.write_text("Folder Path,Group,Permission\n\\Databases,CORP\\PAM-DBA,Owner\n"
                         "\\Infrastructure,CORP\\Someone-Else,Owner\n", encoding="utf-8")
        out = self.convert(XML, extra=["-p", str(perms)])
        text = (out / "review" / "Accounts_Review.csv").read_text(encoding="utf-8-sig")
        self.assertIn("CORP\\PAM-DBA=Owner", text)          # \Databases had none in the XML
        self.assertNotIn("Someone-Else", text)              # the XML's own permissions win


class DelineaReports(Base):
    def write(self, name, text):
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_group_report_secret_role_wins(self):
        p = self.write("groups.csv",
                       "Folder Path,Group Name,Folder Permissions,Secret Permissions,Inherited\n"
                       "\\Databases,PAM-DBA,Owner,Owner,No\n"
                       "\\Databases\\SQL,PAM-DBA,Owner,Owner,Yes\n"
                       "\\Databases\\SQL,Helpdesk,View,List,No\n")
        self.assertTrue(looks_like_permissions(p))
        perms = Permissions(p)
        self.assertEqual([(g.member, g.permission) for g in perms.by_folder["databases\\sql"]],
                         [("PAM-DBA", "Owner"), ("Helpdesk", "List")])

    def test_user_report_with_domain(self):
        p = self.write("users.csv", "Folder,User Name,Domain,Permissions\n"
                                    "\\Infra,jsmith,CORP,\"View, Edit\"\n")
        self.assertTrue(looks_like_permissions(p))
        g = Permissions(p).by_folder["infra"][0]
        self.assertEqual((g.member, g.permission, g.member_type), ("CORP\\jsmith", "Edit", "User"))

    def test_user_and_group_columns_keep_the_group(self):
        p = self.write("all.csv", "Folder Path,User,Group,Folder Permission\n\\Infra,jsmith,CORP\\Admins,Owner\n")
        g = Permissions(p).by_folder["infra"][0]
        self.assertEqual((g.member, g.member_type), ("CORP\\Admins", "Group"))

    def test_strongest_permission(self):
        self.assertEqual(strongest_permission("View, Edit, Owner"), "Owner")
        self.assertEqual(strongest_permission("List/View"), "View")
        self.assertEqual(strongest_permission("Edit"), "Edit")


class ConfigV4(unittest.TestCase):
    def test_saved_platform_map_gets_kee_pass(self):
        up = upgrade_config({"config_version": 3, "platform_map": {"Windows Account": "X"}})
        self.assertEqual(up["config_version"], CONFIG_VERSION)
        self.assertEqual(up["platform_map"]["Kee Pass"], "GenericWebApp")


if __name__ == "__main__":
    unittest.main()
