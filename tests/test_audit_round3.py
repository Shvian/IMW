"""Regression tests for the round 3 audit (2026-11-13)."""

import re
import unittest
from pathlib import Path

from test_imw import SAMPLES, Base  # noqa: F401

from imw.config import config_from_dict
from imw.model import Grant, SourceRecord
from imw.store import Store
from imw.transform import UNSAFE_LINE, UNSAFE_TEXT, build_plan, clean_line, safe_settings

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

    def test_member_check_is_the_server_list(self):
        line = next(x for x in APP_JS.read_text(encoding="utf-8").splitlines() if x.strip().startswith("member:"))
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


if __name__ == "__main__":
    unittest.main()
