"""Possible duplicates (same username and address) and one-time passwords in the source."""

import tempfile
import unittest
from pathlib import Path

from imw.adapters import get_adapter
from imw.config import load_config
from imw.model import SourceRecord, split_folder
from imw.transform import build_plan

SEED = "JBSWY3DPEHPK3PXP"


def rec(sid, folder="\\Apps", username="admin", address="h1.corp.example.com", source_file="f", name=""):
    return SourceRecord(source="t", source_file=source_file, source_id=sid, source_ref="", name=name or sid,
                        folder=split_folder(folder), username=username, type="Windows Account",
                        address=address, secret="x")


def dup_notes(plan):
    return {p.rec.record_id: [w for w in p.warnings if w.startswith("possible duplicate")] for p in plan.accounts}


class Duplicates(unittest.TestCase):
    def test_same_username_and_address_any_case_and_spaces(self):
        a = rec("1", username="Admin", address="H1.corp.example.com ")
        b = rec("2", username=" admin", address="h1.CORP.example.com")
        c = rec("3", username="admin", address="h2.corp.example.com")
        notes = dup_notes(build_plan([a, b, c], load_config()))
        self.assertEqual(len(notes[a.record_id]), 1)
        self.assertIn(b.record_id, notes[a.record_id][0])
        self.assertIn(a.record_id, notes[b.record_id][0])
        self.assertEqual(notes[c.record_id], [])
        self.assertEqual(build_plan([a, b, c], load_config()).accounts[0].status, "REVIEW")

    def test_across_files_and_safes(self):
        a = rec("1", folder="\\Prod\\Windows", source_file="delinea_export")
        b = rec("1", folder="\\Test\\Linux", source_file="keepass_export")
        plan = build_plan([a, b], load_config())
        notes = dup_notes(plan)
        self.assertIn("file keepass_export", notes[a.record_id][0])
        pb = plan.accounts[1]
        if pb.safe.lower() != plan.accounts[0].safe.lower():
            self.assertIn("Safe " + pb.safe, notes[a.record_id][0])

    def test_not_migrated_copy_clears_the_flag(self):
        a, b = rec("1"), rec("2")
        plan = build_plan([a, b], load_config(), overrides={b.record_id: {"Migrate": "N"}}, explicit=True)
        self.assertEqual(dup_notes(plan), {a.record_id: [], b.record_id: []})

    def test_blank_username_or_address_is_not_a_duplicate(self):
        plan = build_plan([rec("1", address=""), rec("2", address="")], load_config())
        self.assertFalse(any(dup_notes(plan).values()))

    def test_many_copies_are_summarised(self):
        recs = [rec(str(i)) for i in range(6)]
        note = dup_notes(build_plan(recs, load_config()))[recs[0].record_id][0]
        self.assertIn("and 2 more", note)


class OneTimePasswords(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_keepass_totp_fields(self):
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Root><Group><Name>Root</Name>
 <Entry><UUID>AAAA</UUID>
  <String><Key>Title</Key><Value>vpn</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw1</Value></String>
  <String><Key>TimeOtp-Secret-Base32</Key><Value Protected="True">{SEED}</Value></String>
  <String><Key>TimeOtp-Period</Key><Value>30</Value></String>
 </Entry>
 <Entry><UUID>BBBB</UUID>
  <String><Key>Title</Key><Value>git</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw2</Value></String>
  <String><Key>otp</Key><Value>otpauth://totp/x?secret={SEED}&amp;period=30</Value></String>
 </Entry>
 <Entry><UUID>CCCC</UUID>
  <String><Key>Title</Key><Value>plain</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw3</Value></String>
 </Entry>
</Group></Root></KeePassFile>"""
        path = self.tmp / "kp.xml"
        path.write_text(xml, encoding="utf-8")
        recs = {r.name: r for r in get_adapter("keepass").read(path, load_config())}
        for name in ("vpn", "git"):
            r = recs[name]
            otp = [n for n in r.notes if n.startswith("one-time password (OTP)")]
            self.assertEqual(len(otp), 1, r.notes)
            self.assertNotIn(SEED, repr(r.extra) + repr(r.notes))
            self.assertFalse(any("secret field" in n for n in r.notes), r.notes)   # one note, not two
            self.assertEqual(r.secret, "pw1" if name == "vpn" else "pw2")
        self.assertFalse(any("one-time" in n for n in recs["plain"].notes))
        plan = build_plan(list(recs.values()), load_config())
        self.assertEqual({p.rec.name: p.status for p in plan.accounts}["git"], "REVIEW")

    def test_table_otp_columns(self):
        path = self.tmp / "sheet.csv"
        path.write_text("Name,Username,Address,Password,TOTP,OTP Enabled,Login link\n"
                        f"a,u1,h1,pw,{SEED},true,\n"
                        "b,u2,h2,pw,,false,\n"
                        f"c,u3,h3,pw,,,otpauth://totp/x?secret={SEED}\n", encoding="utf-8")
        recs = {r.name: r for r in get_adapter("table").read(path, load_config())}
        self.assertTrue(any(n.startswith("one-time password (OTP)") for n in recs["a"].notes))
        self.assertFalse(any("one-time" in n for n in recs["b"].notes), recs["b"].notes)
        self.assertTrue(any("'Login link'" in n for n in recs["c"].notes), recs["c"].notes)
        for r in recs.values():
            self.assertNotIn(SEED, repr(r.extra) + repr(r.notes))


if __name__ == "__main__":
    unittest.main()
