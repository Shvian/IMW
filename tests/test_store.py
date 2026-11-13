"""Tests for the local staging database workflow."""

import csv
import sys
import unittest

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw.protect import DpapiProtector, ProtectError, new_salt
from imw.store import Store, StoreError


class StoreFlow(Base):
    def setUp(self):
        super().setUp()
        self.db = str(self.tmp / "m.db")

    def ingest(self, *extra):
        rc, text = self.run_cli("ingest", "--db", self.db, "--insecure-plaintext-secrets",
                                "-i", str(SAMPLES / "delinea_export.csv"),
                                "-p", str(SAMPLES / "delinea_permissions.csv"), *extra)
        self.assertEqual(rc, 0, text)

    def map(self):
        rc, text = self.run_cli("map", "--db", self.db, "-c", str(SAMPLES / "config_delinea.json"))
        self.assertEqual(rc, 0, text)

    def test_full_flow_and_wave(self):
        self.ingest("-i", str(SAMPLES / "keepass_export.xml"))
        self.map()
        rc, _ = self.run_cli("set", "--db", self.db, "--where", "target_safe = 'IT-Backup'", "--migrate", "N")
        self.assertEqual(rc, 0)
        rc, _ = self.run_cli("set", "--db", self.db, "-r", "delinea:delinea_export:107", "--safe", "FIN:Portals")
        self.assertEqual(rc, 0)
        out = self.tmp / "wave1"
        rc, text = self.run_cli("extract", "--db", self.db, "-o", str(out), "--where", "source = 'delinea'",
                                "--include-secrets")
        self.assertEqual(rc, 0, text)
        accounts = {a["recordId"].split(":")[-1]: a for a in read_csv(out / "upload" / "Accounts.csv")}
        self.assertNotIn("102", accounts)                        # Migrate=N
        self.assertEqual(accounts["107"]["safeName"], "FIN-Portals")  # edit, cleaned
        self.assertEqual(accounts["101"]["secret"], "P@ssw0rd!1")
        self.assertTrue(all(a["recordId"].startswith("delinea:") for a in accounts.values()))
        review = read_csv(out / "review" / "Accounts_Review.csv")
        self.assertEqual(len(review), 12)                       # review always covers everything
        self.assert_no_secrets(out / "review")

    def test_query_cannot_read_secrets_or_write(self):
        self.ingest()
        self.map()
        st = Store(self.db)
        cols, rows = st.query("SELECT secret_enc FROM records")
        self.assertTrue(all(r[0] is None for r in rows))
        with self.assertRaises(StoreError):
            st.query("DELETE FROM records")
        with self.assertRaises(StoreError):
            st.query(f"ATTACH DATABASE '{self.tmp / 'x.db'}' AS x")
        raw = st.db.execute("SELECT secret_enc FROM records WHERE record_id LIKE '%:101'").fetchone()[0]
        self.assertEqual(raw, "plain:P@ssw0rd!1")
        st.close()

    def test_reingest_replaces_and_keeps_edits(self):
        self.ingest()
        self.map()
        self.run_cli("set", "--db", self.db, "-r", "delinea:delinea_export:101", "--platform", "WinDomainCustom")
        self.ingest()
        self.map()
        st = Store(self.db)
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM records").fetchone()[0], 8)
        row = st.db.execute("SELECT platform_id, platform_source FROM plan_accounts "
                            "WHERE record_id = 'delinea:delinea_export:101'").fetchone()
        self.assertEqual(tuple(row), ("WinDomainCustom", "override"))
        st.close()

    def test_import_review(self):
        self.ingest()
        self.map()
        out = self.tmp / "r"
        self.run_cli("extract", "--db", self.db, "-o", str(out))
        rows = read_csv(out / "review" / "Accounts_Review.csv")
        for r in rows:
            if r["Record_ID"].endswith(":108"):
                r["Migrate"] = "N"
        edited = self.tmp / "edited.csv"
        with open(edited, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        rc, text = self.run_cli("set", "--db", self.db, "--from-review", str(edited))
        self.assertEqual(rc, 0, text)
        self.assertIn("1 records", text)
        st = Store(self.db)
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM edits").fetchone()[0], 1)
        st.close()

    def test_no_secrets_mode(self):
        rc, _ = self.run_cli("ingest", "--db", self.db, "--no-secrets", "-i", str(SAMPLES / "delinea_export.csv"))
        self.assertEqual(rc, 0)
        self.map()
        rc, _ = self.run_cli("extract", "--db", self.db, "-o", str(self.tmp / "o"), "--include-secrets")
        self.assertEqual(rc, 2)                                   # nothing to decrypt
        rc, _ = self.run_cli("extract", "--db", self.db, "-o", str(self.tmp / "o"))
        self.assertEqual(rc, 0)

    @unittest.skipIf(sys.platform == "win32", "checks the non-Windows refusal")
    def test_dpapi_refused_off_windows(self):
        rc, _ = self.run_cli("ingest", "--db", self.db, "-i", str(SAMPLES / "delinea_export.csv"))
        self.assertEqual(rc, 2)
        with self.assertRaises(ProtectError):
            DpapiProtector(new_salt())

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI")
    def test_dpapi_round_trip(self):
        salt = new_salt()
        p = DpapiProtector(salt)
        blob = p.protect("S3cret!", "rec1")
        self.assertTrue(blob.startswith("dpapi:"))
        self.assertNotIn("S3cret", blob)
        self.assertEqual(p.unprotect(blob, "rec1"), "S3cret!")
        with self.assertRaises(ProtectError):
            p.unprotect(blob, "rec2")                             # bound to the record id
        with self.assertRaises(ProtectError):
            DpapiProtector(new_salt()).unprotect(blob, "rec1")    # bound to the database


if __name__ == "__main__":
    unittest.main()
