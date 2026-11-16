"""Real Delinea report layouts: template list, users list, the users report and its decisions."""

import unittest
from pathlib import Path

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw.reference import References, read_templates, read_users, reference_kind
from imw.store import Store
from imw.transform import Permissions
from imw.ui.server import looks_like_permissions

REPORTS = SAMPLES / "delinea_reports"
REPORT_SECRETS = ["Pw1!", "Pw2!", "Pw3!", "Pw4!", "Pw5!", "Pw6!", "JBSWY3DPEHPK3PXP", "111-222"]


class Kinds(unittest.TestCase):
    def test_each_report_is_recognised(self):
        want = {"allsecrets.csv": "templates", "lauserslist.csv": "users", "lagroups.csv": "groups",
                "secret-template-list.csv": "template_list", "whatroleassignmentsexist.csv": "roles",
                "whatrolepermissionassignmentsexist.csv": "roles", "secrets-export.csv": "",
                "whatfolderpermissionsexistforgroups.csv": "", "whatfolderscanalluserssee.csv": ""}
        for name, kind in want.items():
            self.assertEqual(reference_kind(REPORTS / name), kind, name)

    def test_permission_reports_only(self):
        perms = {f.name for f in REPORTS.glob("*.csv") if looks_like_permissions(f)}
        self.assertEqual(perms, {"whatfolderpermissionsexistforgroups.csv", "whatfolderscanalluserssee.csv"})


class Lookups(unittest.TestCase):
    def setUp(self):
        self.refs = References(read_templates(REPORTS / "allsecrets.csv"), read_users(REPORTS / "lauserslist.csv"))

    def test_template_by_name_and_folder(self):
        self.assertEqual(self.refs.template_for("DB admin", ("IT", "Servers", "Windows")), ("Windows Account", ""))
        self.assertEqual(self.refs.template_for("db ADMIN", ()), ("Windows Account", ""))
        self.assertEqual(self.refs.template_for("Twin", ("IT", "Web"))[0], "Web Password")
        self.assertEqual(self.refs.template_for("Twin", ("Unix", "Linux"))[0], "Unix Account (SSH)")
        tmpl, note = self.refs.template_for("Twin", ("Other",))
        self.assertEqual(tmpl, "")
        self.assertIn("different templates", note)
        self.assertIn("not in the template list", self.refs.template_for("Lost", ())[1])

    def test_full_name_to_upn(self):
        self.assertEqual(self.refs.upn_for("jane smith"), ("jane.smith@corp.example.com", ""))
        self.assertEqual(self.refs.upn_for("jane.smith@corp.example.com"), (None, ""))
        self.assertIn("not in the users list", self.refs.upn_for("Nobody Known")[1])
        two = References([], [("Pat Lee", "pat1@x.com", ""), ("Pat Lee", "pat2@x.com", "")])
        self.assertIn("2 users", two.upn_for("Pat Lee")[1])
        self.assertEqual(References().upn_for("Pat Lee"), (None, ""))


class UsersReport(unittest.TestCase):
    def test_direct_and_undecided(self):
        perms = Permissions([str(REPORTS / "whatfolderpermissionsexistforgroups.csv"),
                             str(REPORTS / "whatfolderscanalluserssee.csv")])
        rec = type("R", (), {"source_id": "x", "folder": ("Unix", "Linux"), "name": "n"})()
        grants, how = perms.resolve(rec)
        self.assertEqual(how, "folder")
        got = {(g.member, g.basis, g.hint) for g in grants}
        self.assertIn(("Unix Team", "", ""), got)
        self.assertIn(("Bob Jones", "direct", ""), got)                 # Edit: stronger than any group
        self.assertIn(("Jane Smith", "undecided", "Unix Team"), got)    # View: Unix Team has View too
        rec.folder = ("IT", "Web")
        got = {(g.member, g.basis, g.hint) for g in perms.resolve(rec)[0]}
        self.assertIn(("Jane Smith", "undecided", "CORP\\IT Admins"), got)

    def test_without_a_group_report_nothing_is_decided(self):
        perms = Permissions(str(REPORTS / "whatfolderscanalluserssee.csv"))
        rec = type("R", (), {"source_id": "x", "folder": ("Unix", "Linux"), "name": "n"})()
        self.assertEqual({g.basis for g in perms.resolve(rec)[0]}, {"undecided"})


class Convert(Base):
    def run_all(self, out="out"):
        args = ["-i", str(REPORTS / "secrets-export.csv"), "-i", str(REPORTS / "allsecrets.csv"),
                "-i", str(REPORTS / "lagroups.csv"),
                "--reference", str(REPORTS / "lauserslist.csv"),
                "-p", str(REPORTS / "whatfolderpermissionsexistforgroups.csv"),
                "-p", str(REPORTS / "whatfolderscanalluserssee.csv")]
        rc, text = self.run_cli("convert", "-o", str(self.tmp / out), "--force", *args)
        self.assertEqual(rc, 0, text)
        return self.tmp / out

    def test_end_to_end(self):
        out = self.run_all()
        review = {r["Record_ID"].rsplit(":", 1)[1]: r for r in read_csv(out / "review" / "Accounts_Review.csv")}
        self.assertEqual(review["row2"]["Source_Type"], "Web Password")
        self.assertEqual(review["row2"]["Platform_ID"], "GenericWebApp")
        self.assertEqual(review["row5"]["Source_Type"], "Unix Account (SSH)")
        self.assertEqual(review["row6"]["Status"], "ERROR")
        self.assertIn("not in the template list", review["row6"]["Notes"])
        members = read_csv(out / "review" / "SafeMembers_Review.csv")
        users = [m for m in members if m["Member_Type"] == "User"]
        self.assertEqual([(m["Source_Member"], m["Member_Name"]) for m in users],
                         [("Bob Jones", "bob.jones@corp.example.com")])
        uploaded = {m["MemberName"] for m in read_csv(out / "upload" / "SafeMembers.csv")}
        self.assertNotIn("jane.smith@corp.example.com", uploaded)
        decide = read_csv(out / "review" / "Users_To_Decide.csv")
        self.assertEqual({(d["Source_Member"], d["Member_Name"], d["Decision"]) for d in decide},
                         {("Jane Smith", "jane.smith@corp.example.com", "not decided"),
                          ("Nobody Known", "Nobody Known", "not decided")})
        self.assertIn("not in the users list", [d for d in decide if d["Source_Member"] == "Nobody Known"][0]["Notes"])
        for f in (out / "review").rglob("*.csv"):
            body = f.read_text(encoding="utf-8-sig")
            for s in REPORT_SECRETS:
                self.assertNotIn(s, body, f.name)


class Decisions(Base):
    def test_store_decisions(self):
        db = str(self.tmp / "m.db")
        rc, text = self.run_cli("ingest", "--db", db, "--insecure-plaintext-secrets",
                                "-i", str(REPORTS / "secrets-export.csv"), "-i", str(REPORTS / "allsecrets.csv"),
                                "--reference", str(REPORTS / "lauserslist.csv"),
                                "-p", str(REPORTS / "whatfolderpermissionsexistforgroups.csv"),
                                "-p", str(REPORTS / "whatfolderscanalluserssee.csv"))
        self.assertEqual(rc, 0, text)
        st = Store(db)
        from imw.config import load_config
        cfg = load_config()
        st.map(cfg)
        rows = st.db.execute("SELECT folder, member, decision FROM plan_undecided ORDER BY member, folder").fetchall()
        self.assertEqual([tuple(r) for r in rows],
                         [("\\IT\\Web", "Jane Smith", ""), ("\\Unix\\Linux", "Jane Smith", ""),
                          ("\\Unix\\Linux", "Nobody Known", "")])
        st.set_decisions([("\\IT\\Web", "Jane Smith")], "include", "owns the web portal")
        st.set_decisions([("\\Unix\\Linux", "nobody known")], "exclude")
        plan = st.map(cfg)
        jane = [m for (safe, _), m in plan.members.items() if m["member_name"] == "jane.smith@corp.example.com"]
        self.assertEqual([m["role"] for m in jane], ["Full"])
        self.assertIn("included by you", jane[0]["notes"][0])
        rows = dict(((r[0], r[1]), r[2]) for r in st.db.execute("SELECT folder, member, decision FROM plan_undecided"))
        self.assertEqual(rows[("\\Unix\\Linux", "Nobody Known")], "exclude")
        st.set_decisions([("\\IT\\Web", "Jane Smith")], "")
        plan = st.map(cfg)
        self.assertFalse([m for m in plan.members.values() if m["member_name"].startswith("jane")])
        # Loading the users list again replaces its rows instead of adding them twice.
        n = st.db.execute("SELECT COUNT(*) FROM ref_users").fetchone()[0]
        st.ingest_reference("users", REPORTS / "lauserslist.csv", read_users(REPORTS / "lauserslist.csv"))
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM ref_users").fetchone()[0], n)
        st.close()


if __name__ == "__main__":
    unittest.main()
