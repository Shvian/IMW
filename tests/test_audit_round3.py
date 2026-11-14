"""Regression tests for the round 3 audit (2026-11-13)."""

import re
import unittest
from pathlib import Path

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw.config import config_from_dict
from imw.model import Grant, SourceRecord
from imw.store import Store
from imw import xlsx
from imw.adapters.delinea import DelineaAdapter
from imw.adapters.keepass import KeePassAdapter
from imw.adapters.table import TableAdapter
from imw.transform import (UNSAFE_LINE, UNSAFE_TEXT, Permissions, build_plan, clean_line, load_overrides,
                           safe_settings, sanitize_safe_name)

APP_JS = Path(__file__).resolve().parent.parent / "imw" / "ui" / "static" / "app.js"


def rec(sid, folder):
    r = SourceRecord(source="t", source_file="f", source_id=sid, source_ref=sid, name=sid, folder=folder,
                     type="Windows", address="h1", username="u" + sid, secret="x")
    r.grants = [Grant("CORP\\Ops", "View")]
    return r


CFG = {"default_platform": "WinServerLocal", "safe_defaults": {"numberOfDaysRetention": 7, "description": "Rules"}}


class MemberCheckMatchesServer(unittest.TestCase):
    def test_no_invisible_characters_in_source(self):
        for path in APP_JS.parent.glob("*.*"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(UNSAFE_TEXT.search(text.replace("\n", "").replace("\t", "")), path.name)

    def test_name_checks_use_the_server_list(self):
        line = next(x for x in APP_JS.read_text(encoding="utf-8").splitlines() if x.startswith("const INVISIBLE ="))
        js = re.search(r"/(\[.*?\])/", line).group(1)
        self.assertEqual(js.encode().decode("unicode_escape"), UNSAFE_LINE.pattern)


class CleanSafeSettings(unittest.TestCase):
    def test_clean_line(self):
        self.assertEqual(clean_line(" a\u200b\tb\r\nc\u2028\ufeff "), "abc")
        self.assertEqual(clean_line(5), 5)

    def test_safe_settings_strip_control_characters(self):
        cfg = config_from_dict({**CFG, "safe_defaults": {"description": "Line1\r\nLine2\u200b", "location": "\\Win\x07",
                                                         "managingCPM": "CPM\t1"}})
        plan = build_plan([rec("1", ("Apps",))], cfg)
        name = next(iter(plan.safes))
        body = safe_settings(name, plan.safes[name], cfg)
        self.assertEqual((body["description"], body["location"], body["managingCPM"]), ("Line1Line2", "\\Win", "CPM1"))


class MergedSafeSettings(unittest.TestCase):
    def names(self):
        cfg = config_from_dict(CFG)
        plan = build_plan([rec("1", ("Apps",)), rec("2", ("Web",))], cfg)
        a = next(p.safe for p in plan.accounts if p.rec.folder == ("Apps",))
        b = next(p.safe for p in plan.accounts if p.rec.folder == ("Web",))
        return cfg, a, b

    def test_merge_target_keeps_its_own_settings(self):
        cfg, a, b = self.names()
        ov = {a.lower(): {"key": a.lower(), "new_name": b, "description": "From A"}}
        plan = build_plan([rec("1", ("Apps",)), rec("2", ("Web",))], cfg, safe_overrides=ov)
        self.assertEqual(list(plan.safes), [b])
        self.assertIsNone(plan.safes[b]["override"])
        self.assertEqual(safe_settings(b, plan.safes[b], cfg)["description"], "Rules")
        ov[b.lower()] = {"key": b.lower(), "description": "B's own"}
        plan = build_plan([rec("1", ("Apps",)), rec("2", ("Web",))], cfg, safe_overrides=ov)
        self.assertEqual(plan.safes[b]["override"]["key"], b.lower())
        self.assertEqual(safe_settings(b, plan.safes[b], cfg)["description"], "B's own")

    def test_rename_to_a_new_name_keeps_the_settings(self):
        cfg, a, _ = self.names()
        ov = {a.lower(): {"key": a.lower(), "new_name": "MY-NEW", "description": "From A"}}
        plan = build_plan([rec("1", ("Apps",)), rec("2", ("Web",))], cfg, safe_overrides=ov)
        self.assertEqual(safe_settings("MY-NEW", plan.safes["MY-NEW"], cfg)["description"], "From A")


class MemberEditsFollowRenames(Base):
    def setUp(self):
        super().setUp()
        db = str(self.tmp / "m.db")
        rc, text = self.run_cli("ingest", "--db", db, "--insecure-plaintext-secrets",
                                "-i", str(SAMPLES / "delinea_export.csv"), "-p", str(SAMPLES / "delinea_permissions.csv"))
        self.assertEqual(rc, 0, text)
        rc, text = self.run_cli("map", "--db", db, "-c", str(SAMPLES / "config_delinea.json"))
        self.assertEqual(rc, 0, text)
        self.st = Store(db)
        self.a, self.b = [r[0] for r in self.st.db.execute(
            "SELECT safe_name FROM plan_safes WHERE accounts_to_upload > 0 ORDER BY safe_name LIMIT 2")]

    def tearDown(self):
        self.st.close()
        super().tearDown()

    def edits(self, safe):
        return sorted(r["member_name"] for r in self.st.db.execute(
            "SELECT member_name FROM member_edits WHERE lower(safe_name) = lower(?)", (safe,)))

    def stamp(self, safe, member, when):
        self.st.db.execute("UPDATE member_edits SET changed_utc = ? WHERE safe_name = ? AND member_name = ?",
                           (when, safe, member))
        self.st.db.commit()

    def test_merge_and_undo_keep_each_safes_own_changes(self):
        st, a, b = self.st, self.a, self.b
        st.set_member_edits([a], "pam-auditors", "add", role="Read only")
        st.set_member_edits([a], "A-Only", "add", role="Read only")
        st.set_member_edits([b], "PAM-Auditors", "add", role="Full")
        st.set_member_edits([b], "B-Only", "add", role="Read only")
        self.stamp(a, "pam-auditors", "2026-01-01T00:00:00Z")
        self.stamp(b, "PAM-Auditors", "2026-02-01T00:00:00Z")
        # A renamed into B: one change per member (ignoring case), the newer one wins
        st.set_safe_override(a, {"new_name": b}, old_name=a, new_name=b)
        st.map(st.stored_config())
        self.assertEqual(self.edits(b), ["A-Only", "B-Only", "PAM-Auditors"])
        self.assertEqual(self.edits(a), [])
        self.assertEqual(st.db.execute("SELECT role FROM member_edits WHERE member_name = 'PAM-Auditors'").fetchone()[0],
                         "Full")
        # Undo on A moves back only what came with A
        st.set_safe_override(a, {}, undo=True, old_name=b, new_name=a)
        st.map(st.stored_config())
        self.assertEqual(self.edits(a), ["A-Only"])
        self.assertEqual(self.edits(b), ["B-Only", "PAM-Auditors"])

    def test_case_variant_collision_leaves_one_row(self):
        st, a, b = self.st, self.a, self.b
        st.set_member_edits([a], "pam-auditors", "add", role="Full")
        st.set_member_edits([b], "PAM-Auditors", "add", role="Read only")
        self.stamp(a, "pam-auditors", "2026-03-01T00:00:00Z")
        self.stamp(b, "PAM-Auditors", "2026-02-01T00:00:00Z")
        st.set_safe_override(a, {"new_name": b}, old_name=a, new_name=b)
        rows = st.db.execute("SELECT member_name, role FROM member_edits WHERE lower(safe_name) = lower(?)",
                             (b,)).fetchall()
        self.assertEqual([tuple(r) for r in rows], [("pam-auditors", "Full")])

    def test_plain_rename_and_undo_move_everything(self):
        st, a = self.st, self.a
        st.set_member_edits([a], "X1", "add", role="Read only")
        st.set_safe_override(a, {"new_name": "MY-SAFE"}, old_name=a, new_name="MY-SAFE")
        st.map(st.stored_config())
        st.set_member_edits(["MY-SAFE"], "X2", "add", role="Read only")     # made after the rename
        st.set_safe_override(a, {}, undo=True, old_name="MY-SAFE", new_name=a)
        self.assertEqual(self.edits(a), ["X1", "X2"])

    def test_settings_change_keeps_the_moved_list(self):
        st, a, b = self.st, self.a, self.b
        st.set_member_edits([a], "A-Only", "add", role="Read only")
        st.set_safe_override(a, {"new_name": b}, old_name=a, new_name=b)
        st.map(st.stored_config())
        st.set_safe_override(a, {"new_name": b, "description": "x"}, old_name=b, new_name=b)
        self.assertEqual(st.safe_overrides()[a.lower()]["moved_edits"], ["A-Only"])
        st.set_safe_override(a, {}, undo=True, old_name=b, new_name=a)
        self.assertEqual(self.edits(a), ["A-Only"])


class TypedNamesAreCleaned(unittest.TestCase):
    def test_safe_names(self):
        cfg = config_from_dict(CFG)
        self.assertEqual(sanitize_safe_name("AP\u200bPS\x7f\u2060", cfg)[0], "APPS")

    def test_account_name_platform_and_member_edits(self):
        cfg = config_from_dict(CFG)
        r = rec("1", ("Apps",))
        r2 = rec("2", ("Apps",))
        rid = r.record_id
        plan = build_plan([r, r2], cfg, overrides={rid: {"Account_Name": "web\u200b01\x7f", "Platform_ID": "Win\ufeffLocal"}},
                          explicit=True, member_edits=[{"safe_name": "APPS", "member_name": "PAM\u200b-Ops", "action": "add",
                                                        "search_in": "corp\u2060", "role": "Read only", "reason": ""}],
                          member_overrides={"corp\\ops": {"member_name": "Ops\u200e", "search_in": "dir\x7f"}})
        p = next(x for x in plan.accounts if x.rec.record_id == rid)
        self.assertEqual((p.account_name, p.platform), ("web01", "WinLocal"))
        self.assertIn("invisible or control characters removed from the account name", p.warnings)
        names = {(m["member_name"], m["search_in"]) for m in plan.members.values()}
        self.assertIn(("PAM-Ops", "corp"), names)
        self.assertIn(("Ops", "dir"), names)


class BrokenFilesGiveMessages(Base):
    def test_bad_xlsx(self):
        bad = self.tmp / "bad.xlsx"
        bad.write_bytes(b"not a zip at all")
        with self.assertRaisesRegex(ValueError, "not a readable Excel workbook"):
            xlsx.read_rows(bad)
        with self.assertRaisesRegex(ValueError, "not a readable Excel workbook"):
            xlsx.sheet_names(bad)

    def test_xlsx_with_missing_sheet_relationship(self):
        import zipfile
        src = SAMPLES / "accounts_by_group.xlsx"
        bad = self.tmp / "norel.xlsx"
        with zipfile.ZipFile(src) as zin, zipfile.ZipFile(bad, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "xl/_rels/workbook.xml.rels":
                    data = re.sub(rb'Id="rId1"', b'Id="rIdGone"', data)
                zout.writestr(item, data)
        with self.assertRaisesRegex(ValueError, "the workbook does not list"):
            xlsx.read_rows(bad)

    def test_csv_errors_become_value_errors(self):
        nul = self.tmp / "nul.csv"
        nul.write_bytes(b'Secret Name,Username,Password\n"a\x00b",u,"unterminated\n')
        import csv
        old = csv.field_size_limit(10)
        try:
            for reader in (lambda: list(DelineaAdapter().read(nul, config_from_dict(CFG))),
                           lambda: list(TableAdapter().read(nul, config_from_dict(CFG))),
                           lambda: list(KeePassAdapter()._read_csv(nul, config_from_dict(CFG), "utf-8-sig")),
                           lambda: Permissions(str(nul)),
                           lambda: load_overrides(nul)):
                with self.assertRaisesRegex(ValueError, "not a readable CSV file"):
                    reader()
        finally:
            csv.field_size_limit(old)

    def test_long_fields_are_fine(self):
        big = self.tmp / "big.csv"
        key = "A" * 300_000
        big.write_text(f'Secret Name,Folder Path,Username,Password,Notes\nweb,\\IT,admin,pw,"{key}"\n', encoding="utf-8")
        recs = list(DelineaAdapter().read(big, config_from_dict(CFG)))
        self.assertEqual(len(recs[0].extra["Notes"]), 300_000)

    def test_cli_reports_instead_of_crashing(self):
        bad = self.tmp / "bad.xlsx"
        bad.write_bytes(b"PK broken")
        rc, _ = self.run_cli("convert", "-i", str(bad), "-o", str(self.tmp / "o"), "--force")
        self.assertEqual(rc, 2)


class SecretsStayOutOfReviewFiles(Base):
    def review_text(self, src, *extra):
        cfg = self.tmp / "cfg.json"
        cfg.write_text('{"default_platform": "WinServerLocal"}', encoding="utf-8")
        out = self.convert(src, config=cfg, extra=extra)
        return "".join(f.read_text(encoding="utf-8") for f in (out / "review").glob("*.csv")), out

    def test_secret_like_columns(self):
        src = self.tmp / "aws.csv"
        src.write_text("Secret Name,Folder Path,Username,Password,Secret Key,Client Secret,API Key,Token,"
                       "Security Answer,Secret Template,Notes\n"
                       "aws,\\Cloud,svc,pw1,SKVALUE1,CSVALUE2,AKVALUE3,TKVALUE4,ANSVALUE5,Amazon IAM Key,fine\n",
                       encoding="utf-8")
        text, _ = self.review_text(src)
        for v in ("SKVALUE1", "CSVALUE2", "AKVALUE3", "TKVALUE4", "ANSVALUE5", "pw1"):
            self.assertNotIn(v, text)
        self.assertIn("Amazon IAM Key", text)                 # Secret Template is not a secret
        self.assertIn("secret field 'Secret Key' is not migrated", text)

    def test_keepass_protected_fields(self):
        src = self.tmp / "kp.xml"
        src.write_text("""<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta/><Root><Group><Name>Root</Name>
          <Entry><UUID>u1</UUID>
            <String><Key>Title</Key><Value>db</Value></String>
            <String><Key>UserName</Key><Value>sa</Value></String>
            <String><Key>Password</Key><Value ProtectInMemory="True">PWVALUE</Value></String>
            <String><Key>Vendor code</Key><Value ProtectInMemory="True">PROTVALUE1</Value></String>
            <String><Key>Recovery</Key><Value Protected="True">PROTVALUE2</Value></String>
            <String><Key>Port</Key><Value>1433</Value></String>
          </Entry></Group></Root></KeePassFile>""", encoding="utf-8")
        text, _ = self.review_text(src)
        for v in ("PWVALUE", "PROTVALUE1", "PROTVALUE2"):
            self.assertNotIn(v, text)
        self.assertIn("1433", text)

    def test_shifted_rows_are_errors_without_secret_pieces(self):
        src = self.tmp / "shift.csv"
        src.write_text("Secret Name,Folder Path,Username,Password,Notes,Machine\n"
                       "web,\\IT,admin,pa,ss,word,srv1\n"
                       "ok,\\IT,admin2,fine,n,srv2\n", encoding="utf-8")
        text, out = self.review_text(src)
        rows = {r["Account_Name"] or r["Username"]: r for r in read_csv(out / "review" / "Accounts_Review.csv")}
        bad = next(r for r in rows.values() if r["Username"] == "admin")
        self.assertEqual(bad["Status"], "ERROR")
        self.assertIn("more values than the header", bad["Notes"])
        self.assertNotIn(",ss,", text)
        self.assertNotIn("word", text.replace("password", "").replace("Password", ""))
        good = next(r for r in rows.values() if r["Username"] == "admin2")
        self.assertNotEqual(good["Status"], "ERROR", good["Notes"])
        self.assertNotIn("srv1", {r["Address"] for r in rows.values()})
        accounts = read_csv(out / "upload" / "Accounts.csv")
        self.assertEqual([a["userName"] for a in accounts], ["admin2"])

    def test_keepass_csv_and_table_csv_shifted(self):
        kp = self.tmp / "kp.csv"
        kp.write_text('"Group","Title","Username","Password","URL","Notes"\n'
                      '"Root/A","t","u","p1","p2","h.example","x"\n', encoding="utf-8")
        recs = KeePassAdapter().read(kp, config_from_dict(CFG))
        self.assertTrue(any("more values than the header" in n for n in recs[0].notes))
        self.assertNotIn("p2", list(recs[0].extra.values()) + [recs[0].address])
        tb = self.tmp / "t.csv"
        tb.write_text("Hostname,Login,Password,Notes\nh1,u1,p1,p2,note\n", encoding="utf-8")
        recs = list(TableAdapter().read(tb, config_from_dict(CFG)))
        self.assertTrue(any("more values than the header" in n for n in recs[0].notes))
        self.assertNotIn("p2", recs[0].extra.values())


class RenameJoinsSafeWhateverTheCase(unittest.TestCase):
    def test_case(self):
        cfg = config_from_dict(CFG)
        recs = lambda: [rec("1", ("Apps",)), rec("2", ("Web",))]
        p = build_plan(recs(), cfg, safe_overrides={"apps": {"new_name": "web"}})
        self.assertEqual(list(p.safes), ["WEB"])
        p = build_plan(recs(), cfg, safe_overrides={"apps": {"new_name": "new"}, "web": {"new_name": "NEW"}})
        self.assertEqual(len(p.safes), 1)


if __name__ == "__main__":
    unittest.main()
