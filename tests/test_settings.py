"""Directory sources, placeholder layers, Safe settings, account names, merged permissions."""

import tempfile
import unittest
from pathlib import Path

from pam2pc.config import config_from_dict, load_config
from pam2pc.model import Grant, SourceRecord, split_folder
from pam2pc.naming import Namer, default_layers
from pam2pc.transform import Permissions, build_plan, member_target, safe_settings


def rec(folder, username="admin", address="h1.corp.example.com", grants=None, extra=None, name=""):
    r = SourceRecord(source="t", source_file="f", source_id=folder + username, source_ref="", name=name,
                     folder=split_folder(folder), username=username, type="Windows Account", address=address,
                     secret="x", extra=extra or {})
    r.grants = [Grant(g, p) for g, p in (grants or [])]
    return r


class DirectorySources(unittest.TestCase):
    def test_sources_in_order_with_name_rules(self):
        cfg = config_from_dict({"directory_sources": [
            {"name": "AD groups", "members": "groups", "match": "CORP", "search_in": "corp.example.com",
             "strip_domain": True, "find": "^GRP-", "replace": "PAM-", "case": "upper"},
            {"name": "AD users", "members": "users", "match": "corp.example.com", "search_in": "corp.example.com",
             "add_suffix": "@corp.example.com", "strip_domain": True},
            {"name": "Apps", "match": "re:^APP_", "search_in": "Vault", "strip_domain": False}]})
        self.assertEqual(member_target("CORP\\grp-dba", cfg, "Group"), ("PAM-DBA", "corp.example.com", "AD groups"))
        self.assertEqual(member_target("jdoe@corp.example.com", cfg, "User"),
                         ("jdoe@corp.example.com", "corp.example.com", "AD users"))
        self.assertEqual(member_target("APP_payments", cfg, "Group"), ("APP_payments", "Vault", "Apps"))
        self.assertEqual(member_target("OTHER\\x", cfg, "Group"), ("x", "Vault", ""))   # falls back to directory_map

    def test_old_directory_map_still_works(self):
        cfg = config_from_dict({"directory_map": {"CORP": "corp.example.com", "*": "Vault"}})
        self.assertEqual(member_target("CORP\\DBA", cfg)[:2], ("DBA", "corp.example.com"))


class Layers(unittest.TestCase):
    def test_built_in_values_are_editable(self):
        layers = default_layers()
        layers["env"]["rules"].insert(0, {"field": "folder_word", "pattern": "^live$", "code": "PRD"})
        layers["tech"]["rules"] = [{"field": "platform", "pattern": "^WinServerLocal$", "code": "SRV"}]
        cfg = config_from_dict({"safe_convention": {"layers": layers, "template": "{env}-{folder}-{tech}"}})
        self.assertEqual(Namer(cfg).build(rec("\\Live\\Payments"), "WinServerLocal")[0], "PRD-PAY-SRV")

    def test_custom_placeholder_from_a_column_with_default(self):
        cfg = config_from_dict({"safe_convention": {"template": "{site}-{folder}", "layers": {
            "site": {"default": "GL", "rules": [{"field": "column:Site", "pattern": "^bos", "code": "BOS"},
                                                {"field": "address", "pattern": r"\.eu\.", "code": "EU",
                                                 "field2": "tech", "pattern2": "^SVR$"}]}}}})
        n = Namer(cfg)
        self.assertEqual(n.build(rec("\\Apps", extra={"Site": "Boston"}), "WinServerLocal")[0], "BOS-APPS")
        self.assertEqual(n.build(rec("\\Apps", address="x.eu.example.com"), "WinServerLocal")[0], "EU-APPS")
        self.assertEqual(n.build(rec("\\Apps", address="x.eu.example.com"), "MSSql")[0], "GL-APPS")


class SafeSettings(unittest.TestCase):
    def test_defaults_and_rules(self):
        cfg = config_from_dict({"safe_defaults": {"managingCPM": "CPM1", "description": "From {folder}",
                                                  "numberOfDaysRetention": 7},
                                "safe_rules": [{"safe_pattern": "^DB-", "managingCPM": "CPM_DB",
                                                "numberOfVersionsRetention": 10}]})
        body = safe_settings("DB-SQL", {"folders": {"\\Databases\\SQL"}}, cfg)
        self.assertEqual((body["managingCPM"], body["numberOfVersionsRetention"], body["numberOfDaysRetention"]),
                         ("CPM_DB", 10, ""))
        self.assertEqual(body["description"], "From \\Databases\\SQL")
        self.assertEqual(safe_settings("APP", {}, cfg)["managingCPM"], "CPM1")

    def test_account_name_template(self):
        cfg = config_from_dict({"account_name": {"template": "{username}@{address}"}})
        plan = build_plan([rec("\\Apps", "svc_x", "app1")], cfg)
        self.assertEqual(plan.accounts[0].account_name, "svc_x@app1")
        plan = build_plan([rec("\\Apps", "svc_x", "app1", name="")], load_config())
        self.assertEqual(plan.accounts[0].account_name, "app1-svc_x")


class MergedPermissions(unittest.TestCase):
    def test_two_files_merge(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.csv", Path(d) / "b.csv"
            a.write_text("Folder Path,Group,Permission\n\\Apps,CORP\\A,Owner\n\\Apps,CORP\\B,View\n")
            b.write_text("Folder Path,Group,Permission\n\\Apps,CORP\\B,View\n\\Apps,CORP\\C,List\n")
            grants, how = Permissions([str(a), str(b)]).resolve(rec("\\Apps\\Web"))
        self.assertEqual([g.member for g in grants], ["CORP\\A", "CORP\\B", "CORP\\C"])
        self.assertEqual(how, "folder")


if __name__ == "__main__":
    unittest.main()
