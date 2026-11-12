"""Permission presets, custom roles and config upgrades."""

import unittest

from pam2pc.config import (_V1_PERMISSION_MAP, _V1_ROLE_PERMISSIONS, ALL_PERMISSIONS, PERMISSION_PRESETS,
                           all_roles, config_diff, config_from_dict, load_config, resolve_role)
from pam2pc.model import Grant, SourceRecord, split_folder
from pam2pc.transform import build_plan


def rec(folder, grants):
    r = SourceRecord(source="t", source_file="f", source_id=folder, source_ref="", folder=split_folder(folder),
                     username="admin", type="Windows Account", address="h", secret="x")
    r.grants = [Grant(g, p) for g, p in grants]
    return r


class Roles(unittest.TestCase):
    def test_presets(self):
        self.assertEqual(list(PERMISSION_PRESETS), ["Connect only", "Read only", "Approver", "Accounts manager", "Full"])
        self.assertEqual(set(PERMISSION_PRESETS["Connect only"]), {"listAccounts", "useAccounts"})
        self.assertNotIn("requestsAuthorizationLevel2", PERMISSION_PRESETS["Full"])
        self.assertEqual(len(PERMISSION_PRESETS["Full"]), len(ALL_PERMISSIONS) - 1)

    def test_default_permission_map_uses_presets(self):
        cfg = load_config()
        plan = build_plan([rec("\\App", [("CORP\\A", "Owner"), ("CORP\\B", "Edit"), ("CORP\\C", "View"),
                                         ("CORP\\D", "List")])], cfg)
        roles = {m["source_name"]: m["role"] for m in plan.members.values()}
        self.assertEqual(roles, {"CORP\\A": "Full", "CORP\\B": "Accounts manager", "CORP\\C": "Read only",
                                 "CORP\\D": "List only"})
        self.assertTrue(all(not m["notes"] for m in plan.members.values()))

    def test_custom_role_and_strongest_wins(self):
        cfg = config_from_dict({"custom_roles": {"Break glass": ["listAccounts", "useAccounts", "retrieveAccounts",
                                                                 "viewAuditLog"]},
                                "permission_map": {"BG": "Break glass", "View": "Read only"}})
        self.assertIn("Break glass", all_roles(cfg))
        plan = build_plan([rec("\\App", [("CORP\\A", "View")]), rec("\\App\\Sub", [("CORP\\A", "BG")])],
                          config_from_dict({**cfg, "fallback_strategy": "folder_leaf",
                                            "folder_rules": [{"folder_prefix": "\\App", "safe": "S"}]}))
        self.assertEqual([m["role"] for m in plan.members.values()], ["Break glass"])

    def test_legacy_role_names_still_resolve(self):
        cfg = load_config()
        self.assertEqual(resolve_role("Owner", cfg), "Full")
        self.assertEqual(resolve_role("viewer", cfg), "List only")
        self.assertEqual(resolve_role("Nope", cfg), "")


class Upgrade(unittest.TestCase):
    def test_old_defaults_move_to_new_defaults(self):
        old = {"field_aliases": {}, "permission_map": _V1_PERMISSION_MAP, "role_permissions": _V1_ROLE_PERMISSIONS,
               "fallback_strategy": "folder_leaf",
               "safe_convention": {"template": "{env}-{folder}-{tech}-{flavor}-{acct}", "abbreviations": {"X": "Y"}}}
        cfg = config_from_dict(old)
        self.assertEqual(cfg["permission_map"]["Owner"], "Full")
        self.assertEqual(cfg["fallback_strategy"], "convention")
        self.assertEqual(cfg["safe_convention"]["template"], "{folder}")
        self.assertEqual(cfg["safe_convention"]["abbreviations"], {"X": "Y"})
        self.assertNotIn("role_permissions", cfg)

    def test_changed_roles_become_custom_roles(self):
        roles = dict(_V1_ROLE_PERMISSIONS, Auditor=["listAccounts", "viewAuditLog"])
        cfg = config_from_dict({"field_aliases": {}, "role_permissions": roles,
                                "permission_map": {"Audit": "Auditor"}})
        self.assertEqual(cfg["custom_roles"]["Auditor"], ["listAccounts", "viewAuditLog"])
        self.assertEqual(resolve_role("Auditor", cfg), "Auditor")

    def test_new_and_hand_written_configs_are_left_alone(self):
        for user in ({"config_version": 2, "field_aliases": {}, "fallback_strategy": "folder_leaf"},
                     {"fallback_strategy": "folder_leaf"}):
            self.assertEqual(config_from_dict(user)["fallback_strategy"], "folder_leaf")

    def test_hand_written_old_role_names_still_work(self):
        cfg = config_from_dict({"role_permissions": {"Auditor": ["listAccounts"]}, "permission_map": {"A": "Auditor"}})
        self.assertEqual(resolve_role("Auditor", cfg), "Auditor")

    def test_diff_keeps_only_changes(self):
        cfg = config_from_dict({"safe_convention": {"default_environment": "P"}, "default_platform": "X"})
        self.assertEqual(config_diff(cfg), {"safe_convention": {"default_environment": "P"}, "default_platform": "X"})


if __name__ == "__main__":
    unittest.main()
