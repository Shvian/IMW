"""A plain accounts list (no folders, no permissions): Safe names from account details,
splitting big Safes, standard member groups per Safe and the groups-to-create list."""

import shutil
import unittest
from collections import Counter

from test_imw import SAMPLES, Base, read_csv  # noqa: F401
import test_ui

from imw.adapters import get_adapter
from imw.config import STANDARD_MEMBER_SET, config_from_dict
from imw.model import Grant, SourceRecord
from imw.naming import address_domain
from imw.transform import STANDARD_NOTE, build_plan
from imw.writers import convention_rows, groups_to_create, write_convention, write_review

LIST = SAMPLES / "accounts_list_only.csv"


def records(cfg):
    return list(get_adapter("table").read(LIST, cfg))


class SafeNamesFromDetails(unittest.TestCase):
    def test_address_domain(self):
        self.assertEqual(address_domain("srv01.boston.corp.example.com"), "boston.corp.example.com")
        self.assertEqual(address_domain("SRV01"), "")
        self.assertEqual(address_domain("10.1.2.3"), "")
        self.assertEqual(address_domain("fe80::1"), "")

    def test_column_layer_and_env_from_column(self):
        cfg = config_from_dict({"safe_convention": {
            "template_no_folders": "{env}-{site}-{tech}-{flavor}-{acct}",
            "layers": {"site": {"label": "Site", "default": "", "rules": [
                {"field": "column:Site", "pattern": "^Boston$", "code": "BOS"},
                {"field": "column:site", "pattern": "^London$", "code": "LON"}]},
                "env": {"label": "Environment", "default": "", "rules": [
                    {"field": "column:Environment", "pattern": "^Production$", "code": "P"}]}}}})
        plan = build_plan(records(cfg), cfg)
        safes = set(plan.safes)
        self.assertIn("P-BOS-SVR-WIN-LA", safes)
        self.assertIn("LON-DB-SQL-SA", safes)            # Development: no {env} code
        self.assertIn("P-SVR-UNX-RT", safes)              # Singapore: no {site} code

    def test_address_domain_layer(self):
        cfg = config_from_dict({"safe_convention": {
            "template_no_folders": "{dom}-{tech}-{flavor}",
            "layers": {"dom": {"label": "Domain", "rules": [
                {"field": "address_domain", "pattern": "^london\\.", "code": "LON"}]}}}})
        plan = build_plan(records(cfg), cfg)
        self.assertIn("LON-SVR-WIN", plan.safes)


class Split(unittest.TestCase):
    def plan(self, **extra):
        cfg = config_from_dict({"safe_max_accounts": 10, **extra})
        return build_plan(records(cfg), cfg)

    def test_flag_only_by_default(self):
        plan = self.plan()
        self.assertEqual(plan.safes["SVR-WIN-LA"]["accounts"], 24)
        self.assertTrue(any("over the 10" in i for i in plan.safes["SVR-WIN-LA"]["issues"]))

    def test_split_even_and_by_address(self):
        plan = self.plan(safe_split_over_max=True)
        counts = Counter(p.safe for p in plan.accounts if p.safe.startswith("SVR-WIN-LA"))
        self.assertEqual(counts, {"SVR-WIN-LA-01": 8, "SVR-WIN-LA-02": 8, "SVR-WIN-LA-03": 8})
        first = sorted(p.rec.address for p in plan.accounts if p.safe == "SVR-WIN-LA-01")
        allw = sorted(p.rec.address for p in plan.accounts if p.safe.startswith("SVR-WIN-LA"))
        self.assertEqual(first, allw[:8])
        issues = plan.safes["SVR-WIN-LA-02"]["issues"]
        self.assertTrue(any("part 2 of 3" in i for i in issues), issues)
        self.assertFalse(any("recommended per Safe" in i for i in issues))
        self.assertTrue(all(len(n) <= 28 for n in plan.safes))

    def test_split_keeps_28_characters_and_skips_overrides(self):
        cfg = config_from_dict({"safe_max_accounts": 2, "safe_split_over_max": True,
                                "safe_name": {"prefix": "MIGRATION-LONG-PREFIX-"}})
        recs = records(cfg)
        plan = build_plan(recs, cfg, overrides={recs[0].record_id: {"Target_Safe": "Mine"}}, explicit=True)
        self.assertTrue(all(len(n) <= 28 for n in plan.safes), list(plan.safes))
        self.assertIn("Mine", plan.safes)
        self.assertTrue(any(n.endswith("-01") for n in plan.safes))


class StandardMembers(Base):
    def cfg(self, **std):
        return config_from_dict({"standard_members": {"members": STANDARD_MEMBER_SET, **std}})

    def test_every_safe_gets_the_set(self):
        cfg = self.cfg()
        plan = build_plan(records(cfg), cfg)
        names = {(s, m["member_name"], m["role"]) for (s, _), m in plan.members.items()}
        self.assertIn(("SVR-WIN-LA", "SVR-WIN-LA-Owners", "Full"), names)
        self.assertIn(("SVR-WIN-LA", "SVR-WIN-LA-Users", "Connect only"), names)
        self.assertIn(("SVR-WIN-LA", "SVR-WIN-LA-Approvers", "Approver"), names)
        self.assertEqual(len(plan.members), 3 * len(plan.safes))
        for s in plan.safes.values():
            self.assertFalse(any("no member with full" in i or "no access groups" in i for i in s["issues"]), s["issues"])
        m = plan.members[("SVR-WIN-LA", "svr-win-la-owners")]
        self.assertIn(STANDARD_NOTE["Group"], m["notes"])
        self.assertEqual(m["accounts"], plan.safes["SVR-WIN-LA"]["accounts"])

    def test_off_and_empty(self):
        for cfg in (config_from_dict({}), self.cfg(apply_to="off")):
            plan = build_plan(records(cfg), cfg)
            self.assertEqual(len(plan.members), 0)
            self.assertTrue(any("no member with full" in i for i in plan.safes["SVR-WIN-LA"]["issues"]))

    def rec(self, rid, folder, grants):
        return SourceRecord(source="t", source_file="f", source_id=rid, source_ref="", folder=(folder,),
                            username="admin", address="h" + rid, type="Windows Account", secret="x",
                            grants=grants)

    def test_only_safes_without_source_members_unless_all(self):
        recs = lambda: [self.rec("1", "Apps", [Grant("CORP\\App-Admins", "Owner", "Group")]),  # noqa: E731
                        self.rec("2", "Web", [])]
        plan = build_plan(recs(), self.cfg())
        self.assertEqual({s for s, _ in plan.members}, {"APPS", "WEB"})
        self.assertEqual(sum(1 for s, _ in plan.members if s == "APPS"), 1)
        plan = build_plan(recs(), self.cfg(apply_to="all"))
        self.assertEqual(sum(1 for s, _ in plan.members if s == "APPS"), 4)

    def test_same_name_as_source_member_merges_and_is_not_to_create(self):
        cfg = self.cfg(apply_to="all", members=[{"name": "App-Admins", "member_type": "Group", "role": "Connect only"}])
        plan = build_plan([self.rec("1", "Apps", [Grant("CORP\\App-Admins", "Owner", "Group")])], cfg)
        self.assertEqual(len(plan.members), 1)
        m = next(iter(plan.members.values()))
        self.assertEqual(m["role"], "Full")                        # the strongest wins
        self.assertFalse(m.get("standard"))
        self.assertEqual(groups_to_create(plan), [])

    def test_fixed_member_domain_conversion_and_checks(self):
        cfg = config_from_dict({"domain_map": [{"from": "CORP", "to": "corp.example.com", "members": "groups"}],
                                "standard_members": {"members": [
                                    {"name": "CORP\\{safe}-Users", "member_type": "Group", "role": "Connect only"},
                                    {"name": "PAM-Vault-Admins", "member_type": "Group", "role": "Full", "search_in": "Vault"},
                                    {"name": "{safe}+" + "x" * 60, "member_type": "Group", "role": "Read only"}]}})
        plan = build_plan(records(cfg), cfg)
        m = plan.members[("SVR-WIN-LA", "svr-win-la-users@corp.example.com")]
        self.assertEqual(m["member_name"], "SVR-WIN-LA-Users@corp.example.com")
        admins = [m for (s, k), m in plan.members.items() if m["member_name"] == "PAM-Vault-Admins"]
        self.assertEqual(len(admins), len(plan.safes))
        self.assertEqual(admins[0]["search_in"], "Vault")
        long = next(m for m in plan.members.values() if m["member_name"].endswith("x" * 60))
        self.assertTrue(any("does not allow +" in n for n in long["notes"]), long["notes"])
        self.assertTrue(any("at most 64" in n for n in long["notes"]), long["notes"])
        create = groups_to_create(plan)
        vault = next(g for g in create if g["member_name"] == "PAM-Vault-Admins")
        self.assertEqual(len(vault["safes"]), len(plan.safes))

    def test_review_file_and_split_names(self):
        cfg = config_from_dict({"safe_max_accounts": 10, "safe_split_over_max": True,
                                "standard_members": {"members": STANDARD_MEMBER_SET}})
        plan = build_plan(records(cfg), cfg)
        files = write_review(plan, self.tmp)
        self.assertEqual(files[-1].name, "MemberGroups_To_Create.csv")
        rows = read_csv(files[-1])
        names = {r["Member_Name"] for r in rows}
        self.assertIn("SVR-WIN-LA-02-Owners", names)
        self.assertEqual(len(rows), 3 * len(plan.safes))
        self.assertEqual({r["Safes"] for r in rows}, {"1"})
        self.assertNotIn("MemberGroups_To_Create.csv",
                         [f.name for f in write_review(build_plan(records(config_from_dict({})), config_from_dict({})),
                                                       self.tmp / "none")])


class NamingConventionFile(Base):
    def test_rows_in_plain_words(self):
        cfg = config_from_dict({"standard_members": {"members": STANDARD_MEMBER_SET},
                                "safe_convention": {"template_no_folders": "{env}-{site}-{tech}",
                                                    "abbreviations": {"Storefront": "SF"},
                                                    "layers": {"site": {"label": "Site", "default": "X", "rules": [
                                                        {"field": "column:Site", "pattern": "^Boston$", "code": "BOS"}]}}}})
        plan = build_plan(records(cfg), cfg)
        path = write_convention(plan, cfg, self.tmp)
        rows = read_csv(path)
        got = {(r["Section"], r["Item"], r["Code_Or_Value"], r["Applies_When"]) for r in rows}
        self.assertIn(("Pattern", "Safes for accounts without folders", "{env}-{site}-{tech}", "the account has no folder"), got)
        self.assertIn(("Placeholder", "{site}", "BOS", "the Site column is Boston"), got)
        self.assertIn(("Placeholder", "{site}", "X", "no row above matches"), got)
        self.assertIn(("Placeholder", "{tech}", "DOM", "the platform ID is WinDomain"), got)
        self.assertIn(("Abbreviation", "Storefront", "SF", "a folder name or word"), got)
        self.assertIn(("Limit", "Maximum length", "28", "always"), got)
        self.assertIn(("Member group", "{safe}-Owners", "Full", "Safes with no members from the source"), got)
        self.assertTrue(any(r["Section"] == "Example" and r["Applies_When"] == "accounts without folders" for r in rows))
        self.assertEqual(sum(1 for r in convention_rows(plan, cfg) if r[0] == "Abbreviation" and r[1] == "Storefront"), 1)


class ListOnlyUi(test_ui.UiServer):
    def setUp(self):
        super().setUp()
        for f in list((self.ws / "inbox").iterdir()):
            f.unlink()
        shutil.copy(LIST, self.ws / "inbox" / LIST.name)

    def test_values_hints_and_validation(self):
        self.login()
        st, r = self.req("POST", "/api/ingest", {"files": [{"name": LIST.name, "source": "table"}]})
        self.assertEqual(st, 200, r)
        st, c = self.req("GET", "/api/config")
        self.assertEqual((c["hints"]["records"], c["hints"]["without_folder"], c["hints"]["with_grants"]), (120, 120, 0))
        self.assertEqual(c["standard_member_set"], STANDARD_MEMBER_SET)
        st, v = self.req("POST", "/api/rules/values", {"field": "column:Site"})
        self.assertEqual(st, 200, v)
        codes = {x["value"]: x["code"] for x in v["values"]}
        self.assertEqual(codes["Boston"], "BOS")
        self.assertEqual(v["distinct"], 3)
        st, v = self.req("POST", "/api/rules/values", {"field": "column:Environment"})
        self.assertEqual({x["value"]: x["code"] for x in v["values"]}["Production"], "P")
        st, v = self.req("POST", "/api/rules/values", {"field": "address_domain"})
        self.assertIn("boston.corp.example.com", [x["value"] for x in v["values"]])
        self.assertEqual(self.req("POST", "/api/rules/values", {"field": "nope"})[0], 400)
        bad = [{"name": "{site}-Users", "role": "Full"}, {"name": "{safe}-Users", "role": "Nobody"},
               {"name": "", "role": "Full"}]
        for row in bad:
            st, r = self.req("POST", "/api/config", {"patch": {"standard_members": {"members": [row]}}})
            self.assertEqual(st, 400, (row, r))
        st, r = self.req("POST", "/api/rules/preview", {"kind": "members", "patch": {
            "standard_members": {"members": STANDARD_MEMBER_SET}}})
        self.assertEqual(st, 200, r)
        self.assertTrue(r["rows"] and all(x["standard"] for x in r["rows"]))
        self.assertTrue(r["rows"][0]["source"].startswith("(standard member group"))
        st, r = self.req("POST", "/api/config", {"patch": {"standard_members": {"members": STANDARD_MEMBER_SET},
                                                           "safe_split_over_max": True, "safe_max_accounts": 10}})
        self.assertEqual(st, 200, r)
        st, s = self.req("GET", "/api/safes")
        self.assertIn("SVR-WIN-LA-03", [x["safe_name"] for x in s["safes"]])
        st, out = self.req("POST", "/api/extract", {"name": "t1"})
        self.assertEqual(st, 200, out)
        files = [f.replace("\\", "/") for f in out["files"]]       # \ on Windows
        self.assertIn("review/MemberGroups_To_Create.csv", files)
        self.assertIn("review/SafeNamingConvention.csv", files)
        st, text = self.req("GET", "/api/export/convention.csv")
        self.assertEqual(st, 200)
        self.assertIn("{safe}-Owners", text.decode("utf-8-sig"))


# Only this class's own tests: the server tests it builds on run in test_ui.
for _name in dir(test_ui.UiServer):
    if _name.startswith("test_") and _name not in ListOnlyUi.__dict__:
        setattr(ListOnlyUi, _name, None)


if __name__ == "__main__":
    unittest.main()
