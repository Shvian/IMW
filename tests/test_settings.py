"""Directory sources, placeholder layers, Safe settings, account names, merged permissions."""

import tempfile
import unittest
from pathlib import Path

from imw.config import config_from_dict, load_config
from imw.model import Grant, SourceRecord, split_folder
from imw.naming import Namer, default_layers
from imw.transform import Permissions, build_plan, member_target, safe_settings


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
        # Falls back to directory_map, whose default searchIn is empty: Privilege Cloud searches every directory.
        self.assertEqual(member_target("OTHER\\x", cfg, "Group"), ("x", "", ""))

    def test_search_in_optional_and_roles_use_group_sources(self):
        cfg = config_from_dict({"directory_sources": [
            {"name": "Groups", "members": "groups", "match": "*", "strip_domain": True},
            {"name": "Users", "members": "users", "match": "*", "search_in": "abc-guid"}]})
        self.assertEqual(member_target("CORP\\PAM-Admins", cfg, "Role"), ("PAM-Admins", "", "Groups"))
        self.assertEqual(member_target("jdoe", cfg, "User"), ("jdoe", "abc-guid", "Users"))

    def test_member_types(self):
        from imw.transform import normalize_member_type
        self.assertEqual([normalize_member_type(v) for v in ("user", "GROUPS", "Role", "", "weird")],
                         ["User", "Group", "Role", "Group", "Group"])
        self.assertEqual(normalize_member_type("", "User"), "User")
        cfg = config_from_dict({"default_member_type": "Role"})
        r = rec("\\Apps", grants=[("PAM-Ops", "View")])
        plan = build_plan([r], cfg)
        m = next(iter(plan.members.values()))
        self.assertEqual((m["member_type"], m["search_in"]), ("Role", ""))

    def test_member_changed_everywhere_and_role_per_safe(self):
        r1 = rec("\\Apps", grants=[("CORP\\DBA", "View")])
        r2 = rec("\\Data", username="sa", grants=[("CORP\\DBA", "View")])
        cfg = load_config()
        plan = build_plan([r1, r2], cfg, member_overrides={"corp\\dba": {"member_name": "PAM-DBA", "member_type": "Role",
                                                                          "search_in": None}},
                          member_edits=[{"safe_name": "APPS", "member_name": "CORP\\DBA", "action": "add", "role": "Full",
                                         "member_type": "", "search_in": ""}])
        ms = {s: m for (s, _), m in plan.members.items()}
        self.assertEqual({s: (m["member_name"], m["member_type"], m["role"]) for s, m in ms.items()},
                         {"APPS": ("PAM-DBA", "Role", "Full"), "DATA": ("PAM-DBA", "Role", "Read only")})

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

    def test_account_name_left_to_privilege_cloud(self):
        cfg = config_from_dict({"account_name": {"mode": "none"}})
        a, b = rec("\\Apps", "svc_x", "app1", name="Same"), rec("\\Apps", "svc_y", "app1", name="Same")
        b.source_id = "other"
        plan = build_plan([a, b], cfg)
        self.assertEqual([p.account_name for p in plan.accounts], ["", ""])   # no _2 suffix on blanks
        self.assertFalse(any("duplicate" in w for p in plan.accounts for w in p.warnings))
        # One account left unnamed by an edit while the others keep their built names.
        plan = build_plan([a, b], load_config(), overrides={b.record_id: {"Account_Name": "(none)"}}, explicit=True)
        self.assertEqual([p.account_name for p in plan.accounts], ["Same", ""])


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
