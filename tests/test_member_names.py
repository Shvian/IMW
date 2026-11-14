"""Member names: domain conversion (drop a domain, or the UPN form), many domains to one."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class DomainConversion(unittest.TestCase):
    def cfg(self, rows, **extra):
        from imw.config import config_from_dict
        return config_from_dict({"domain_map": rows, **extra})

    def test_many_to_one_drop_and_upn(self):
        from imw.transform import member_target
        cfg = self.cfg([{"from": "CORP, EMEA", "to": "corp.example.com"}, {"from": "APAC", "to": ""},
                        {"from": "*", "to": "@groups.example.com", "members": "groups"},
                        {"from": "LAB", "to": "lab.example.com", "members": "users+groups"}])
        self.assertEqual(member_target("CORP\\jdoe", cfg, "User")[0], "jdoe@corp.example.com")
        self.assertEqual(member_target("EMEA\\kmuller", cfg, "User")[0], "kmuller@corp.example.com")
        self.assertEqual(member_target("jx@emea.corp.example.com", cfg, "User")[0], "jx@corp.example.com")
        self.assertEqual(member_target("APAC\\wtan", cfg, "User")[:3], ("wtan", "", "domain conversion APAC"))
        self.assertEqual(member_target("CORP\\Admins", cfg, "Group")[0], "Admins@groups.example.com")
        self.assertEqual(member_target("OTHER\\bob", cfg, "User")[0], "bob")          # the default
        self.assertEqual(member_target("LAB\\ann", cfg, "User")[0], "ann@lab.example.com")
        self.assertEqual(member_target("LAB\\Ops", cfg, "Group")[0], "Ops@groups.example.com")  # * row first
        self.assertEqual(member_target("LAB\\Ops", self.cfg([{"from": "LAB", "to": "lab.example.com",
                                                                "members": "users+groups"}]), "Group")[0],
                         "Ops@lab.example.com")
        self.assertEqual(member_target("LAB\\Auditor", self.cfg([{"from": "LAB", "to": "lab.example.com",
                                                                    "members": "users+groups"}]), "Role")[0],
                         "Auditor")                                                   # roles not ticked
        self.assertEqual(member_target("CORP\\Admins", self.cfg([{"from": "CORP", "to": "x.com"}]), "Group")[0],
                         "Admins")                                                    # users only by default

    def test_directory_source_works_on_the_converted_name(self):
        from imw.transform import member_target
        cfg = self.cfg([{"from": "CORP", "to": "corp.example.com"}],
                       directory_sources=[{"name": "AD", "members": "users", "match": "CORP", "search_in": "dir-1",
                                           "case": "upper"}])
        self.assertEqual(member_target("CORP\\jdoe", cfg, "User")[:2], ("JDOE@CORP.EXAMPLE.COM", "dir-1"))

    def test_ui_validation(self):
        from imw.ui.server import UiError, check_settings as validate_config
        with self.assertRaises(UiError):
            validate_config(self.cfg([{"from": "CORP", "to": "bad domain"}]))
        with self.assertRaises(UiError):
            validate_config(self.cfg([{"from": "", "to": "x.com"}]))
        validate_config(self.cfg([{"from": "CORP", "to": "corp.example.com"}]))


if __name__ == "__main__":
    unittest.main()
