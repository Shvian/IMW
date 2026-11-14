"""Guided mappings: the Safe full-member check, new platform defaults, column hints and the
column picker report."""

import unittest

from test_roles import rec

from imw.adapters.table import TableAdapter
from imw.config import (CONFIG_VERSION, DEFAULT_CONFIG, PERMISSION_PRESETS, config_from_dict, upgrade_config)
from imw.model import SourceRecord, split_folder
from imw.naming import DEFAULT_PLATFORM_CODES
from imw.transform import NO_FULL_MEMBER_NOTE, build_plan, resolve_platform


class FullMemberCheck(unittest.TestCase):
    def issues(self, grants, cfg=None):
        plan = build_plan([rec("\\App", grants)], config_from_dict(cfg or {}), explicit=True)
        return next(iter(plan.safes.values()))["issues"]

    def test_safe_without_full_member_is_flagged(self):
        self.assertIn(NO_FULL_MEMBER_NOTE, self.issues([("CORP\\Ops", "View"), ("CORP\\Dev", "Edit")]))

    def test_safe_with_no_members_is_flagged(self):
        self.assertIn(NO_FULL_MEMBER_NOTE, self.issues([]))

    def test_full_member_clears_it(self):
        self.assertNotIn(NO_FULL_MEMBER_NOTE, self.issues([("CORP\\Ops", "View"), ("CORP\\Admins", "Owner")]))

    def test_custom_role_with_every_full_permission_counts(self):
        cfg = {"permission_map": {"Boss": "Everything"},
               "custom_roles": {"Everything": PERMISSION_PRESETS["Full"] + ["requestsAuthorizationLevel2"]}}
        self.assertNotIn(NO_FULL_MEMBER_NOTE, self.issues([("CORP\\A", "Boss")], cfg))
        cfg["custom_roles"]["Everything"] = PERMISSION_PRESETS["Full"][1:]
        self.assertIn(NO_FULL_MEMBER_NOTE, self.issues([("CORP\\A", "Boss")], cfg))

    def test_member_added_by_you_with_full_clears_it(self):
        edits = [{"safe_name": "App", "member_name": "PAM-Admins", "action": "add", "role": "Full",
                  "member_type": "Group", "search_in": ""}]
        plan = build_plan([rec("\\App", [("CORP\\Ops", "View")])], config_from_dict({}), explicit=True,
                          member_edits=edits)
        safe = next(iter(plan.safes))
        self.assertTrue(any(m["role"] == "Full" for m in plan.members.values()), plan.members)
        self.assertNotIn(NO_FULL_MEMBER_NOTE, plan.safes[safe]["issues"])


class PlatformDefaults(unittest.TestCase):
    def test_new_templates_map_to_known_platforms(self):
        pmap = DEFAULT_CONFIG["platform_map"]
        for t in ("Windows Local Admin", "Active Directory Domain Admin", "Cisco Account (SSH)", "Palo Alto",
                  "VMware ESXi", "PostgreSQL", "MySQL", "AWS IAM Key", "Azure AD Account"):
            self.assertIn(pmap[t], DEFAULT_PLATFORM_CODES, t)

    def test_saved_v2_platform_map_gets_the_new_types(self):
        up = upgrade_config({"config_version": 2, "platform_map": {"Windows Account": "X", "cisco account (ssh)": "Mine"}})
        self.assertEqual(up["config_version"], CONFIG_VERSION)
        self.assertEqual(up["platform_map"]["Windows Account"], "X")
        self.assertEqual(up["platform_map"]["cisco account (ssh)"], "Mine")      # yours stays
        self.assertNotIn("Cisco Account (SSH)", up["platform_map"])
        self.assertEqual(up["platform_map"]["PostgreSQL"], "PostgreSQL")

    def test_platform_rules_ignore_case(self):
        r = SourceRecord(source="t", source_file="f", source_id="1", source_ref="", folder=split_folder("\\LINUX\\Web"),
                         username="root", type="Password", address="h", secret="x")
        cfg = config_from_dict({"platform_rules": [{"field": "folder", "pattern": "\\\\linux\\\\", "platform": "UnixSSH"}]})
        self.assertEqual(resolve_platform(r, cfg)[0], "UnixSSH")


class ColumnReport(unittest.TestCase):
    def test_unknown_headers_are_reported(self):
        import tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        f = d / "inventory.csv"
        f.write_text("Title,SAMAccountName,TargetHost,Pwd\nWeb admin,svc_web,web01,x\n", encoding="utf-8")
        cfg = config_from_dict({})
        headers, current = TableAdapter().column_report(f, cfg)
        self.assertEqual(headers, ["Title", "SAMAccountName", "TargetHost", "Pwd"])
        self.assertEqual((current["name"], current["username"], current["address"]), ("Title", "", ""))
        cfg = config_from_dict({"sources": {"table": {"columns": {"username": "SAMAccountName", "address": "TargetHost"}}}})
        recs = list(TableAdapter().read(f, cfg))
        self.assertEqual((recs[0].username, recs[0].address), ("svc_web", "web01"))


if __name__ == "__main__":
    unittest.main()
