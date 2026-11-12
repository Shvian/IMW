"""Tests for the abbreviated Safe naming convention."""

import unittest

from test_pam2pc import SAMPLES, Base, read_csv  # noqa: F401

from pam2pc.config import config_from_dict, load_config
from pam2pc.model import SourceRecord, split_folder
from pam2pc.naming import Namer
from pam2pc.transform import build_plan


def rec(folder, username="admin", type_=""):
    return SourceRecord(source="t", source_file="f", source_id=folder + username, source_ref="",
                        folder=split_folder(folder), username=username, type=type_, address="h", secret="x")


class Naming(unittest.TestCase):
    def setUp(self):
        self.n = Namer(load_config())

    def name(self, folder, platform, user="admin"):
        return self.n.build(rec(folder, user), platform)[0]

    def test_cheat_sheet_style(self):
        self.assertEqual(self.name("\\Boston DC\\Production\\Windows Servers\\HR App", "WinServerLocal", "svc_hr"),
                         "P-BOS-DC-WIN-SVR-HR-APP-LS")
        self.assertEqual(self.name("\\Development\\Oracle\\HR", "Oracle", "svc_hr"), "D-ORC-HR-DB-LS")
        self.assertEqual(self.name("\\Infrastructure\\Windows\\Domain Controllers", "WinDomain", "svc_x"),
                         "INF-WIN-DC-DOM-DS")
        self.assertEqual(self.name("\\Network\\Core Switches", "CiscoSSH", "enable"), "NET-CSW-CSC-EN")

    def test_account_type_rules_respect_technology(self):
        self.assertTrue(self.name("\\Linux", "UnixSSH", "root").endswith("-RT"))
        self.assertTrue(self.name("\\Windows", "WinServerLocal", "root").endswith("-LA"))   # root only means RT on Unix flavors
        self.assertTrue(self.name("\\SQL", "MSSql", "sa").endswith("-SA"))
        self.assertTrue(self.name("\\Windows", "WinServerLocal", "sa").endswith("-LA"))

    def test_always_fits_and_keeps_levels(self):
        for folder in ["\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs",
                       "\\Customer Facing\\Development\\Oracle Finance Ledger Systems",
                       "\\A Very Long Business Unit Name\\Another Long Department\\Yet Another Deep Folder Level Here",
                       "\\L1 Alpha Beta\\L2 Gamma Delta\\L3 Epsilon Zeta\\L4 Eta Theta\\L5 Iota Kappa\\L6 Lambda"]:
            name, notes = self.n.build(rec(folder), "WinServerLocal")
            self.assertLessEqual(len(name), 28, name)
            self.assertTrue(notes)
        self.assertEqual(self.name("\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs", "UnixSSH", "root"),
                         "INF-LNX-BNWJ-SVR-UNX-RT")

    def test_collisions_stay_distinct(self):
        a = self.name("\\Databases\\SQL Production Reporting Replicas EU West", "MSSql", "sa")
        b = self.name("\\Databases\\SQL Production Reporting Replicas EU East", "MSSql", "sa")
        self.assertEqual(a, "P-DB-SQL-RPT-RPL-EU-W-SA")
        self.assertNotEqual(a, b)

    def test_user_settings(self):
        cfg = config_from_dict({"safe_convention": {"template": "{env}-{folder}-{flavor}",
                                                    "default_environment": "P",
                                                    "abbreviations": {"Payroll Systems": "PRS"},
                                                    "skip_folder_levels": ["Applications"]}})
        n = Namer(cfg)
        self.assertEqual(n.build(rec("\\Applications\\Payroll Systems"), "WinServerLocal")[0], "P-PRS-WIN")
        n.build(rec("\\Zebra Unit"), "WinServerLocal")
        self.assertEqual(n.unknown["Zebra"], "ZBR")


class ConventionInPlan(Base):
    def test_default_fallback_uses_convention(self):
        cfg = load_config()
        recs = [rec("\\Production\\Windows\\Member Servers", "Administrator", "Windows Account"),
                rec("\\Production\\Windows\\Member Servers", "svc_app", "Windows Account")]
        plan = build_plan(recs, cfg)
        self.assertEqual([p.safe for p in plan.accounts], ["P-WIN-SVR-LA", "P-WIN-SVR-LS"])
        self.assertEqual(plan.accounts[0].safe_source, "fallback:convention")
        self.assertTrue(all(p.valid_safe for p in plan.accounts))

    def test_rule_placeholders(self):
        cfg = config_from_dict({"group_rules": [
            {"group_pattern": "^CORP\\\\APP-(.+)-Owners$", "safe": "{env}-{1}-{tech}-{flavor}-{acct}"}]})
        r = rec("\\Production\\Payments", "svc_pay", "Windows Account")
        from pam2pc.model import Grant
        r.grants = [Grant("CORP\\APP-PAY-Owners", "Owner")]
        plan = build_plan([r], cfg)
        self.assertEqual(plan.accounts[0].safe, "P-PAY-SVR-WIN-LS")

    def test_capacity_warning(self):
        cfg = config_from_dict({"safe_max_accounts": 2})
        recs = [rec("\\Prod\\Windows", f"u{i}", "Windows Account") for i in range(3)]
        plan = build_plan(recs, cfg)
        issues = list(plan.safes.values())[0]["issues"]
        self.assertTrue(any("over the 2 recommended" in i for i in issues))

    def test_shared_safe_warning(self):
        cfg = config_from_dict({"safe_convention": {"skip_folder_levels": ["Team A", "Team B"]}})
        recs = [rec("\\Team A\\Windows", "x", "Windows Account"), rec("\\Team B\\Windows", "y", "Windows Account")]
        plan = build_plan(recs, cfg)
        self.assertTrue(any("shared by 2 source folders" in w for w in plan.accounts[0].warnings))


if __name__ == "__main__":
    unittest.main()
