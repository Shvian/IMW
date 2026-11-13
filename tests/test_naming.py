"""Tests for the abbreviated Safe naming convention."""

import unittest

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw.config import config_from_dict, load_config
from imw.model import SourceRecord, split_folder
from imw.naming import Namer
from imw.transform import build_plan


def rec(folder, username="admin", type_=""):
    return SourceRecord(source="t", source_file="f", source_id=folder + username, source_ref="",
                        folder=split_folder(folder), username=username, type=type_, address="h", secret="x")


LAYERED = {"safe_convention": {"template": "{env}-{folder}-{tech}-{flavor}-{acct}"}}


class FolderFirst(unittest.TestCase):
    """Defaults: the folder structure names the Safe; CyberArk layers only without folders."""
    def setUp(self):
        self.n = Namer(load_config())

    def test_folder_levels_in_order(self):
        self.assertEqual(self.n.build(rec("\\Applications\\Storefront\\Prod"), "UnixSSH")[0], "APP-SF-P")
        self.assertEqual(self.n.build(rec("\\Applications\\Payments\\Prod"), "WinServerLocal")[0], "APP-PAY-P")

    def test_no_folders_uses_cyberark_layers(self):
        self.assertEqual(self.n.build(rec("", "svc_web"), "WinServerLocal")[0], "SVR-WIN-LS")
        cfg = config_from_dict({"safe_convention": {"default_environment": "P"}})
        self.assertEqual(Namer(cfg).build(rec("", "root"), "UnixSSH")[0], "P-SVR-UNX-RT")

    def test_compound_and_camel_case_words(self):
        self.assertEqual(self.n.auto("Webportal"), "WP")
        self.assertEqual(self.n.auto("SharePoint"), "SP")

    def test_whole_folder_abbreviation_wins(self):
        cfg = config_from_dict({"safe_convention": {"abbreviations": {"Batch: Nightly/Weekly Jobs": "BNW"}}})
        self.assertEqual(Namer(cfg).build(rec("\\Linux\\Batch: Nightly/Weekly Jobs"), "UnixSSH")[0], "LNX-BNW")

    def test_suggestions_from_folder_names(self):
        rows = {r["folder"]: r for r in self.n.suggest({"Storefront": 4, "Prod": 9, "Zebra": 1, "Zbr": 1})}
        self.assertEqual(rows["Storefront"]["code"], "SF")
        self.assertFalse(rows["Storefront"]["automatic"])
        self.assertTrue(rows["Zebra"]["automatic"])
        self.assertEqual(rows["Zbr"]["clash"] or rows["Zebra"]["clash"], "Zebra" if rows["Zbr"]["clash"] else "Zbr")


class Naming(unittest.TestCase):
    """The CyberArk layered template from the cheat sheet."""
    def setUp(self):
        self.n = Namer(config_from_dict(LAYERED))

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
        recs = [rec("\\Production\\Windows\\Member Servers", "Administrator", "Windows Account"),
                rec("\\Production\\Windows\\Member Servers", "svc_app", "Windows Account")]
        plan = build_plan(recs, load_config())
        self.assertEqual([p.safe for p in plan.accounts], ["P-WIN-SVR", "P-WIN-SVR"])
        self.assertEqual(plan.accounts[0].safe_source, "fallback:convention")
        self.assertTrue(all(p.valid_safe for p in plan.accounts))
        self.assertFalse(any("fallback" in w for w in plan.accounts[0].warnings))
        plan = build_plan(recs, config_from_dict(LAYERED))
        self.assertEqual([p.safe for p in plan.accounts], ["P-WIN-SVR-LA", "P-WIN-SVR-LS"])

    def test_folder_rules_beat_group_rules_by_default(self):
        from imw.model import Grant
        r = rec("\\Applications\\Payments", "svc_pay", "Windows Account")
        r.grants = [Grant("CORP\\Payments-Team", "Owner")]
        user = {"group_rules": [{"group": "CORP\\Payments-Team", "safe": "ROLE-PAY"}],
                "folder_rules": [{"folder_prefix": "\\Applications\\Payments", "safe": "APP-PAYMENTS"}]}
        self.assertEqual(build_plan([r], config_from_dict(user)).accounts[0].safe, "APP-PAYMENTS")
        user["group_rules_first"] = True
        self.assertEqual(build_plan([r], config_from_dict(user)).accounts[0].safe, "ROLE-PAY")
        user.pop("folder_rules")
        user["group_rules_first"] = False
        self.assertEqual(build_plan([r], config_from_dict(user)).accounts[0].safe, "ROLE-PAY")

    def test_rule_placeholders(self):
        cfg = config_from_dict({"group_rules": [
            {"group_pattern": "^CORP\\\\APP-(.+)-Owners$", "safe": "{env}-{1}-{tech}-{flavor}-{acct}"}]})
        r = rec("\\Production\\Payments", "svc_pay", "Windows Account")
        from imw.model import Grant
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
