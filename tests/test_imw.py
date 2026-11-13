"""Tests for the Idira Migration Workbench (imw package). Run: python -m unittest discover -s tests   (from the repo root)."""

import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from imw import cli  # noqa: E402
from imw.adapters import AdapterError, detect_adapter, get_adapter  # noqa: E402
from imw.config import load_config  # noqa: E402
from imw.transform import _changed, build_plan, resolve_collisions, sanitize_safe_name  # noqa: E402
from xlsx_writer import SAMPLE, write_xlsx  # noqa: E402

SAMPLES = ROOT / "samples"
SECRETS_IN_SAMPLES = ["P@ssw0rd!1", "Kp!root-web02", "FAKEKEYDATA", "Sql!01sa", "Adm!101", "Rt!batch01",
                      "otpauth://"]


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(list(args))
        return rc, buf.getvalue()

    def convert(self, *inputs, config=None, extra=(), out="out"):
        args = ["convert", "-o", str(self.tmp / out), "--force"]
        for i in inputs:
            args += ["-i", str(i)]
        if config:
            args += ["-c", str(config)]
        rc, text = self.run_cli(*args, *extra)
        self.assertEqual(rc, 0, text)
        return self.tmp / out

    def assert_no_secrets(self, folder):
        for f in Path(folder).rglob("*"):
            if f.is_file():
                body = f.read_text(encoding="utf-8-sig")
                for s in SECRETS_IN_SAMPLES:
                    self.assertNotIn(s, body, f"secret {s!r} leaked into {f}")


class SafeNames(Base):
    def test_rules(self):
        cfg = load_config()
        self.assertEqual(sanitize_safe_name("Linux\\Web: DMZ/Edge", cfg)[0], "Linux-Web- DMZ-Edge")
        name, valid, issues = sanitize_safe_name("X" * 40, cfg)
        self.assertEqual(len(name), 28)
        self.assertFalse(valid)
        self.assertTrue(sanitize_safe_name("OK-Name", cfg)[1])

    def test_collision_suffix_fits(self):
        cfg = load_config()
        a, b = "A" * 30 + "1", "A" * 30 + "2"
        clean = {p: sanitize_safe_name(p, cfg)[0] for p in (a, b)}
        res = resolve_collisions(clean, cfg)
        self.assertEqual(res[a][0], "A" * 28)
        self.assertEqual(res[b][0], "A" * 26 + "-2")
        self.assertEqual(len(res[b][0]), 28)

    def test_changed_ignores_tool_suffixes(self):
        self.assertFalse(_changed("DB-Production-Privileged-A-2", "DB-Production-Privileged-Acc"))
        self.assertFalse(_changed("svc_2", "svc"))
        self.assertTrue(_changed("APP-2", "APP-Payments"))
        self.assertTrue(_changed("Other", "Name"))
        self.assertFalse(_changed("", "Name"))


class Delinea(Base):
    def test_sample(self):
        out = self.convert(SAMPLES / "delinea_export.csv", config=SAMPLES / "config_delinea.json",
                           extra=["-p", str(SAMPLES / "delinea_permissions.csv")])
        rows = read_csv(out / "review" / "Accounts_Review.csv")
        self.assertEqual(len(rows), 8)
        by_id = {r["Record_ID"].split(":")[-1]: r for r in rows}
        self.assertEqual(by_id["101"]["Target_Safe"], "DB-Production-Privileged-Acc")
        self.assertEqual(by_id["101"]["Valid_Safe_Name"], "FALSE")
        self.assertEqual(by_id["105"]["Secret_Type"], "key")
        self.assertEqual(by_id["105"]["Target_Safe"], "APP-Storefront")  # min_permission from old config
        self.assertEqual(by_id["108"]["Target_Safe"], "NET-Devices")
        self.assertEqual(by_id["108"]["Address"], "fw01.example.com")
        self.assertIn("Attachment", by_id["103"]["Notes"])
        self.assertNotIn("Source.Attachment", rows[0])
        accounts = read_csv(out / "upload" / "Accounts.csv")
        self.assertTrue(all(a["secret"] == "" for a in accounts))
        self.assert_no_secrets(out)

    def test_include_secrets(self):
        out = self.convert(SAMPLES / "delinea_export.csv", extra=["--include-secrets"])
        accounts = {a["recordId"].split(":")[-1]: a for a in read_csv(out / "upload" / "Accounts.csv")}
        self.assertEqual(accounts["101"]["secret"], "P@ssw0rd!1")
        self.assertTrue(accounts["105"]["secret"].startswith("-----BEGIN OPENSSH"))
        self.assert_no_secrets(out / "review")
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertTrue(manifest["includes_secrets"])
        self.assertNotIn("P@ssw0rd", (out / "manifest.json").read_text())
        if os.name == "posix":
            self.assertEqual(os.stat(out / "upload" / "Accounts.csv").st_mode & 0o777, 0o600)

    def test_overrides(self):
        out = self.convert(SAMPLES / "delinea_export.csv", config=SAMPLES / "config_delinea.json",
                           extra=["-p", str(SAMPLES / "delinea_permissions.csv")])
        review = out / "review" / "Accounts_Review.csv"
        rows = read_csv(review)
        for r in rows:
            if r["Record_ID"].endswith(":102"):
                r["Migrate"] = "N"
            if r["Record_ID"].endswith(":107"):
                r["Target_Safe"] = "FIN-Portals"
                r["Platform_ID"] = "VendorPortal"
        edited = self.tmp / "edited.csv"
        with open(edited, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        out2 = self.convert(SAMPLES / "delinea_export.csv", config=SAMPLES / "config_delinea.json",
                            extra=["-p", str(SAMPLES / "delinea_permissions.csv"), "--overrides", str(edited)],
                            out="out2")
        rows2 = {r["Record_ID"].split(":")[-1]: r for r in read_csv(out2 / "review" / "Accounts_Review.csv")}
        self.assertEqual(rows2["102"]["Migrate"], "N")
        self.assertEqual(rows2["107"]["Target_Safe"], "FIN-Portals")
        self.assertEqual(rows2["107"]["Safe_Mapping_Source"], "override")
        self.assertEqual(rows2["107"]["Platform_ID"], "VendorPortal")
        self.assertEqual(rows2["101"]["Safe_Mapping_Source"], "group_rule:CORP\\DBA-Team")
        uploaded = {a["recordId"].split(":")[-1] for a in read_csv(out2 / "upload" / "Accounts.csv")}
        self.assertNotIn("102", uploaded)
        self.assertNotIn("IT-Backup", [s["safeName"] for s in read_csv(out2 / "upload" / "Safes.csv")])


class KeePass(Base):
    def test_xml(self):
        self.assertEqual(detect_adapter(SAMPLES / "keepass_export.xml").name, "keepass")
        cfg = load_config(SAMPLES / "config_generic.json")
        recs = list(get_adapter("keepass").read(SAMPLES / "keepass_export.xml", cfg))
        names = {r.name: r for r in recs}
        self.assertNotIn("deleted entry", names)              # recycle bin skipped
        self.assertEqual(len(recs), 4)                         # history entries not duplicated
        web = names["root@web02"]
        self.assertEqual(web.folder, ("Linux", "Web Servers: DMZ/Edge"))
        self.assertEqual(web.address, "web02.example.com")
        self.assertEqual(web.secret, "Kp!root-web02")
        self.assertEqual(web.extra["Port"], "22")
        self.assertTrue(any("web02_notes.txt" in n for n in web.notes))
        key = names["deploy key build01"]
        self.assertEqual(key.secret_type, "key")
        self.assertNotIn("SSH Private Key", key.extra)

    def test_xml_end_to_end(self):
        out = self.convert(SAMPLES / "keepass_export.xml", config=SAMPLES / "config_generic.json",
                           extra=["--include-secrets"])
        rows = {r["Account_Name"]: r for r in read_csv(out / "review" / "Accounts_Review.csv")}
        self.assertEqual(rows["switch core01"]["Status"], "ERROR")   # no username
        self.assertEqual(rows["root@web02"]["Target_Safe"], "UNIX-Servers")
        accounts = {a["name"]: a for a in read_csv(out / "upload" / "Accounts.csv")}
        self.assertNotIn("switch core01", accounts)
        self.assertEqual(accounts["root@web02"]["platformAccountProperties.Port"], "22")
        self.assert_no_secrets(out / "review")

    def test_csv(self):
        self.assertEqual(detect_adapter(SAMPLES / "keepassxc_export.csv").name, "keepass")
        out = self.convert(SAMPLES / "keepassxc_export.csv", config=SAMPLES / "config_generic.json")
        rows = read_csv(out / "review" / "Accounts_Review.csv")
        self.assertEqual(len(rows), 2)                          # recycle bin skipped
        self.assertEqual({r["Platform_ID"] for r in rows}, {"Oracle", "MSSql"})
        self.assertNotIn("Source.TOTP", rows[0])
        self.assert_no_secrets(out)

    def test_kdbx_refused(self):
        p = self.tmp / "vault.kdbx"
        p.write_bytes(b"\x03\xd9\xa2\x9a")
        with self.assertRaises(AdapterError):
            list(get_adapter("keepass").read(p, load_config()))


class Table(Base):
    def test_csv_access_column(self):
        self.assertEqual(detect_adapter(SAMPLES / "accounts_inventory.csv").name, "table")
        out = self.convert(SAMPLES / "accounts_inventory.csv", config=SAMPLES / "config_generic.json",
                           extra=["--include-secrets"])
        rows = read_csv(out / "review" / "Accounts_Review.csv")
        mf = [r for r in rows if r["Username"] == "mfadmin"][0]
        self.assertEqual(mf["Status"], "ERROR")
        safes = sorted(r["Target_Safe"] for r in rows if r["Username"] == "sa")
        self.assertEqual(safes, ["DB-SQL Production Reportin-2", "DB-SQL Production Reporting"])
        members = read_csv(out / "upload" / "SafeMembers.csv")
        helpdesk = [m for m in members if m["memberName"] == "Helpdesk"][0]
        self.assertEqual(helpdesk["role"], "Read only")                  # "Read" -> Read only preset
        self.assertEqual(helpdesk["searchIn"], "corp.example.com")
        self.assertEqual(helpdesk["permissions.retrieveAccounts"], "true")
        self.assertEqual(helpdesk["permissions.manageSafe"], "false")
        uploaded = [a["userName"] for a in read_csv(out / "upload" / "Accounts.csv")]
        self.assertNotIn("mfadmin", uploaded)

    def test_xlsx_grants_per_row(self):
        x = self.tmp / "inv.xlsx"
        write_xlsx(x, SAMPLE)
        self.assertEqual(detect_adapter(x).name, "table")
        out = self.convert(x, config=SAMPLES / "config_excel.json", extra=["--include-secrets"])
        rows = read_csv(out / "review" / "Accounts_Review.csv")
        self.assertEqual(len(rows), 3)                                     # 2 grant rows merged
        batch = rows[0]
        self.assertEqual(batch["Target_Safe"], "UNIX-Batch")
        self.assertIn("CORP\\Helpdesk=List", batch["Access_Groups"])
        accounts = {a["name"]: a for a in read_csv(out / "upload" / "Accounts.csv")}
        self.assertEqual(accounts["leading zero id"]["userName"], "0042")
        self.assertEqual(accounts["leading zero id"]["secret"], "=1+1")
        self.assertEqual(accounts["unix-batch01-root"]["platformAccountProperties.Port"], "22")
        self.assertEqual(accounts["payments-api"]["safeName"], "APP-Payments-Prod")

    def test_multiple_inputs(self):
        out = self.convert(SAMPLES / "keepassxc_export.csv", "table=" + str(SAMPLES / "accounts_inventory.csv"),
                           config=SAMPLES / "config_generic.json")
        sources = {r["Source"] for r in read_csv(out / "review" / "Accounts_Review.csv")}
        self.assertEqual(sources, {"keepass", "table"})


class Cli(Base):
    def test_refuses_non_empty_output(self):
        (self.tmp / "busy").mkdir()
        (self.tmp / "busy" / "x.txt").write_text("x")
        rc, _ = self.run_cli("convert", "-i", str(SAMPLES / "delinea_export.csv"), "-o", str(self.tmp / "busy"))
        self.assertEqual(rc, 2)

    def test_init_config_round_trip(self):
        p = self.tmp / "cfg.json"
        rc, _ = self.run_cli("init-config", str(p))
        self.assertEqual(rc, 0)
        cfg = load_config(p)
        self.assertEqual(cfg["safe_name"]["max_length"], 28)
        self.assertEqual(cfg["safe_name"]["replacement"], "-")

    def test_plan_without_cli(self):
        cfg = load_config()
        recs = list(get_adapter("delinea").read(SAMPLES / "delinea_export.csv", cfg))
        plan = build_plan(recs, cfg)
        self.assertEqual(len(plan.accounts), 8)


if __name__ == "__main__":
    unittest.main()
