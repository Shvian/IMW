"""Your direct changes to whole Safes: rename one Safe, change its settings (2026-11-13)."""

import unittest

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw.config import config_from_dict
from imw.model import Grant, SourceRecord
from imw.store import Store
from imw.transform import build_plan, safe_settings


def rec(sid, folder, grants=(("CORP\\Ops", "View"),)):
    r = SourceRecord(source="t", source_file="f", source_id=sid, source_ref=sid, name=sid, folder=folder,
                     type="Windows", address="h1", username="u" + sid, secret="x")
    r.grants = [Grant(m, p) for m, p in grants]
    return r


CFG = {"default_platform": "WinServerLocal", "safe_defaults": {"numberOfDaysRetention": 7, "managingCPM": "RulesCPM"}}


def safe_of(plan, folder):
    return next(p.safe for p in plan.accounts if p.rec.folder == (folder,))


class SafeOverridesInPlan(unittest.TestCase):
    def plan(self, ov):
        cfg = config_from_dict(CFG)
        p = build_plan([rec("1", ("Apps",)), rec("2", ("Apps",)), rec("3", ("Web",))], cfg, safe_overrides=ov)
        return p, cfg

    def test_rename_moves_every_account_and_members(self):
        base, _ = self.plan({})
        old = safe_of(base, "Apps")
        plan, _ = self.plan({old.lower(): {"new_name": "MY-APPS"}})
        self.assertIn("MY-APPS", plan.safes)
        self.assertNotIn(old, plan.safes)
        self.assertEqual(plan.safes["MY-APPS"]["accounts"], 2)
        self.assertEqual({p.safe for p in plan.accounts if p.rec.folder == ("Apps",)}, {"MY-APPS"})
        self.assertEqual({s for (s, _) in plan.members}, {"MY-APPS", next(n for n in plan.safes if n != "MY-APPS")})

    def test_settings_win_over_rules_and_retention_is_one_or_the_other(self):
        base, _ = self.plan({})
        old = safe_of(base, "Web")
        plan, cfg = self.plan({old.lower(): {"description": "Mine", "numberOfVersionsRetention": 12,
                                             "olacEnabled": True}})
        body = safe_settings(old, plan.safes[old], cfg)
        self.assertEqual((body["description"], body["numberOfVersionsRetention"], body["numberOfDaysRetention"],
                          body["olacEnabled"], body["managingCPM"]), ("Mine", 12, "", True, "RulesCPM"))
        rules = safe_settings(old, plan.safes[old], cfg, with_override=False)
        self.assertEqual((rules["description"], rules["numberOfDaysRetention"]), ("", 7))

    def test_rename_onto_existing_safe_merges_and_warns(self):
        base, _ = self.plan({})
        apps = safe_of(base, "Apps")
        web = safe_of(base, "Web")
        plan, _ = self.plan({web.lower(): {"new_name": apps}})
        self.assertEqual(list(plan.safes), [apps])
        self.assertFalse(any("already has" in w for p in plan.accounts for w in p.warnings))
        self.assertTrue(any("already has" in i for i in plan.safes[apps]["issues"]))


class SafeOverridesInStore(Base):
    def test_store_upload_and_undo(self):
        db = str(self.tmp / "m.db")
        rc, text = self.run_cli("ingest", "--db", db, "--insecure-plaintext-secrets",
                                "-i", str(SAMPLES / "delinea_export.csv"), "-p", str(SAMPLES / "delinea_permissions.csv"))
        self.assertEqual(rc, 0, text)
        rc, text = self.run_cli("map", "--db", db, "-c", str(SAMPLES / "config_delinea.json"))
        self.assertEqual(rc, 0, text)
        st = Store(db)
        old = st.db.execute("SELECT safe_name FROM plan_safes ORDER BY safe_name").fetchone()[0]
        st.set_member_edits([old], "PAM-Auditors", "add", role="Read only")
        st.set_safe_override(old, {"new_name": "X-MINE", "managingCPM": "MyCPM", "numberOfVersionsRetention": 5},
                             "test", old_name=old, new_name="X-MINE")
        st.map(st.stored_config())
        row = st.db.execute("SELECT managing_cpm, retention, rule_names, override_json FROM plan_safes "
                            "WHERE safe_name = 'X-MINE'").fetchone()
        self.assertEqual((row[0], row[1], row[2]), ("MyCPM", "5 versions", old))
        self.assertTrue(row[3])
        # the per-Safe member change followed the rename
        self.assertTrue(st.db.execute("SELECT 1 FROM plan_members WHERE safe_name = 'X-MINE' AND "
                                      "member_name = 'PAM-Auditors'").fetchone())
        out = self.tmp / "o"
        from imw.store import run_extract
        run_extract(st, out)
        safes = {s["SafeName"]: s for s in read_csv(out / "upload" / "Safes.csv")}
        self.assertEqual((safes["X-MINE"]["ManagingCPM"], safes["X-MINE"]["NumberOfVersionsRetention"]), ("MyCPM", "5"))
        self.assertEqual(safes["X-MINE"]["Location"], "\\")                # empty location: the Vault root
        st.set_safe_override(old, {}, undo=True, old_name="X-MINE", new_name=old)
        st.map(st.stored_config())
        self.assertTrue(st.db.execute("SELECT 1 FROM plan_safes WHERE safe_name = ?", (old,)).fetchone())
        self.assertTrue(st.db.execute("SELECT 1 FROM plan_members WHERE safe_name = ? AND "
                                      "member_name = 'PAM-Auditors'", (old,)).fetchone())
        st.close()


if __name__ == "__main__":
    unittest.main()
