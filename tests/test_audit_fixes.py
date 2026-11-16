"""Regression tests for the 2026-11-13 security and logic audit."""

import csv
import sqlite3
import sys
import unittest
import zipfile
from collections import OrderedDict
from pathlib import Path
from unittest import mock

from test_imw import SAMPLES, Base, read_csv  # noqa: F401
from xlsx_writer import write_xlsx

from imw import csvsafe, safexml, xlsx
from imw.adapters.base import AdapterError
from imw.adapters.keepass import KeePassAdapter
from imw.adapters.rows import record_from_row
from imw.config import CONFIG_VERSION, DEFAULT_CONFIG, config_diff, config_from_dict, upgrade_config
from imw.model import SourceRecord
from imw.store import Store
from imw.transform import Permissions, build_plan, load_overrides
from imw.ui import server, tls
from imw.ui.auth import TestAuth


def rec(sid, name="", address="", username="u", folder=("IT",), **kw):
    r = SourceRecord(source="t", source_file="f", source_id=sid, source_ref=sid, name=name,
                     folder=folder, type="Windows", address=address, username=username, secret="x")
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# ------------------------------------------------------------------ security

class XmlAndXlsx(Base):
    BOMB = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><KeePassFile>&b;</KeePassFile>')

    def test_dtd_is_refused(self):
        with self.assertRaises(safexml.UnsafeXmlError):
            safexml.fromstring(self.BOMB)
        f = self.tmp / "bomb.xml"
        f.write_bytes(self.BOMB)
        with self.assertRaises(AdapterError):
            KeePassAdapter().read(f, config_from_dict({}))

    def test_normal_keepass_still_reads(self):
        recs = KeePassAdapter().read(SAMPLES / "keepass_export.xml", config_from_dict({}))
        self.assertTrue(recs)

    def _sheet(self, sheet_xml, extra=None):
        path = self.tmp / "t.xlsx"
        write_xlsx(path, {"S": [["Name", "Username"], ["a", "b"]]})
        with zipfile.ZipFile(path) as z:
            parts = {n: z.read(n) for n in z.namelist()}
        parts["xl/worksheets/sheet1.xml"] = sheet_xml.encode()
        parts.update(extra or {})
        with zipfile.ZipFile(path, "w") as z:
            for n, data in parts.items():
                z.writestr(n, data)
        return path

    def test_far_away_empty_cell_does_not_allocate(self):
        ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        path = self._sheet(
            f'<worksheet xmlns="{ns}"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>Name</t></is></c>'
            '<c r="XFD1" s="3"/></row>'
            '<row r="2"><c r="A2" t="inlineStr"><is><t>web01</t></is></c></row>'
            '<row r="1048576"><c r="XFD1048576" s="3"/></row>'
            '</sheetData></worksheet>')
        _, rows = xlsx.read_rows(path)
        self.assertEqual(rows, [["Name"], ["web01"]])

    def test_gap_rows_keep_their_numbers(self):
        path = self.tmp / "g.xlsx"
        write_xlsx(path, {"S": [["H"], [], [], ["x"]]})
        _, rows = xlsx.read_rows(path)
        self.assertEqual([list(r) for r in rows], [["H"], [], [], ["x"]])

    def test_xlsx_dtd_and_oversize_part_refused(self):
        ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        path = self._sheet(f'<!DOCTYPE x [<!ENTITY e "y">]><worksheet xmlns="{ns}"><sheetData/></worksheet>')
        with self.assertRaises(ValueError):
            xlsx.read_rows(path)
        path = self._sheet(f'<worksheet xmlns="{ns}"><sheetData/></worksheet>')
        with mock.patch.object(xlsx, "MAX_PART_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "unpacks to"):
                xlsx.read_rows(path)


class FormulaInjection(Base):
    def test_escape_roundtrip(self):
        for v in ("=1+1", "+x", "-y", "@SUM(A1)", "\tz", "\rz", "'=a", "''b"):
            self.assertEqual(csvsafe.unescape(csvsafe.escape(v)), v)
        self.assertEqual(csvsafe.escape("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(csvsafe.escape("plain"), "plain")
        self.assertEqual(csvsafe.escape("'quoted"), "'quoted")
        self.assertEqual(csvsafe.escape(5), 5)

    def test_review_escaped_upload_not(self):
        src = self.tmp / "in.csv"
        with open(src, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["Name", "Address", "Username", "Password", "Folder", "Comment"])
            w.writerow(["=HYPERLINK(\"http://x\")", "@host", "-admin", "-Secret=1", "IT", "+evil"])
        cfg = self.tmp / "cfg.json"
        cfg.write_text('{"default_platform": "WinServerLocal"}')
        out = self.convert(src, config=cfg, extra=["--include-secrets"])
        review = read_csv(out / "review" / "Accounts_Review.csv")[0]
        self.assertTrue(review["Account_Name"].startswith("'="))
        self.assertEqual(review["Address"], "'@host")
        self.assertEqual(review["Username"], "'-admin")
        self.assertEqual(review["Source.Comment"], "'+evil")
        acct = read_csv(out / "upload" / "Accounts.csv")[0]
        self.assertEqual(acct["userName"], "-admin")       # API data is left exactly as it is
        self.assertEqual(acct["secret"], "-Secret=1")
        self.assertEqual(acct["address"], "@host")
        # Feeding the review file back is not seen as a change.
        ov = load_overrides(out / "review" / "Accounts_Review.csv")
        row = next(iter(ov.values()))
        self.assertEqual(row["Username"], "-admin")
        self.assertTrue(row["Account_Name"].startswith("="))

    def test_query_csv_escaped(self):
        db = str(self.tmp / "m.db")
        src = self.tmp / "in.csv"
        src.write_text("Name,Address,Username,Password\n=1+1,h,u,p\n")
        rc, text = self.run_cli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", str(src))
        self.assertEqual(rc, 0, text)
        out = self.tmp / "q.csv"
        rc, text = self.run_cli("query", "--db", db, "SELECT name FROM records", "--csv", str(out))
        self.assertEqual(rc, 0, text)
        self.assertEqual(read_csv(out)[0]["name"], "'=1+1")


class LikeSearch(unittest.TestCase):
    def test_wildcards_are_literal(self):
        where, params = server.build_where({"filters": {"search": "svc_1%"}})
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE t (account_name, username, address, folder, record_id, target_safe)")
        for n in ("svc_1%x", "svcA1x", "svc_12"):
            db.execute("INSERT INTO t VALUES (?,?,?,?,?,?)", (n, "", "", "", n, ""))
        where = where.replace(f"({server.VIEWS['all'][1]})", "1=1")
        got = [r[0] for r in db.execute(f"SELECT account_name FROM t WHERE {where}", params)]
        self.assertEqual(got, ["svc_1%x"])


class EndSessionAndDelete(Base):
    def setUp(self):
        super().setUp()
        self.ws = self.tmp / "ws"
        self.app = server.App(self.ws, protector_flag="plain", authenticator=TestAuth("pw"))
        self.app.sid, self.app.unlocked = "s", True

    def test_secure_delete_in_chunks(self):
        f = self.tmp / "big.bin"
        f.write_bytes(b"\xff" * 2500)
        writes = []
        real_open = open

        class Spy:
            def __init__(self, fh):
                self.fh = fh

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.fh.close()

            def write(self, data):
                writes.append(len(data))
                return self.fh.write(data)

            def __getattr__(self, n):
                return getattr(self.fh, n)

        with mock.patch("builtins.open", lambda p, m="r", *a, **k: Spy(real_open(p, m, *a, **k))):
            server.secure_delete(f, chunk=1000)
        self.assertEqual(writes, [1000, 1000, 500])
        self.assertFalse(f.exists())

    def test_locked_file_still_ends_session(self):
        self.app.db_path.write_bytes(b"x" * 10)
        with mock.patch.object(server, "secure_delete", side_effect=PermissionError("in use")):
            r = self.app.api_end({"confirm": "DELETE DB", "delete_db": True})
        self.assertFalse(self.app.unlocked)
        self.assertIsNone(self.app.sid)
        self.assertFalse(r["database_deleted"])
        self.assertEqual(r["not_deleted"], ["migration.db"])


class TlsKeyStaysInWorkspace(Base):
    def test_temp_key_in_tls_folder(self):
        ws = self.tmp / "ws"
        seen = []
        real = tls.tempfile.mkdtemp

        def spy(*a, **k):
            d = real(*a, **k)
            seen.append(Path(d))
            return d

        with mock.patch.object(tls.tempfile, "mkdtemp", spy):
            tls.server_context(ws)
        self.assertTrue(seen)
        for d in seen:
            self.assertEqual(d.parent, (ws / "tls"))
            self.assertFalse(d.exists())


# ------------------------------------------------------------------ logic

class DuplicateIdPermissions(Base):
    def test_record_grants_kept_for_duplicate_id(self):
        perms_csv = self.tmp / "perms.csv"
        perms_csv.write_text("Folder Path,Secret Name,Secret ID,Group,Permission\n,,42,CORP\\Ops,Owner\n")
        perms = Permissions(str(perms_csv))
        src = self.tmp / "src.csv"
        src.write_text("x")
        st = Store(str(self.tmp / "m.db"), create=True, protector="plain")
        st.ingest("t", src, [rec("42", "a"), rec("42", "b")], perms=perms)
        recs = {r.name: r for r in st.load_records()}
        st.close()
        self.assertEqual(recs["b"].source_id, "42#2")
        for r in recs.values():
            self.assertEqual([g.member for g in r.grants], ["CORP\\Ops"])
            self.assertEqual(r.access_source, "record")

    def test_build_plan_duplicate_id(self):
        perms_csv = self.tmp / "perms.csv"
        perms_csv.write_text("Folder Path,Secret Name,Secret ID,Group,Permission\n,,42,CORP\\Ops,Owner\n")
        plan = build_plan([rec("42", "a"), rec("42", "b")], config_from_dict({}), Permissions(str(perms_csv)))
        self.assertEqual([[g.member for g in p.grants] for p in plan.accounts], [["CORP\\Ops"]] * 2)


class DuplicateIdsNotSuffixedTwice(Base):
    def test_build_plan_twice_is_stable(self):
        cfg = config_from_dict({})
        records = [rec("42", "a"), rec("42", "b"), rec("42#2", "c"), rec("42", "d")]
        ids = [p.rec.record_id for p in build_plan(records, cfg).accounts]
        self.assertEqual(len(set(ids)), 4)
        self.assertEqual([i.split(":")[-1] for i in ids], ["42", "42#3", "42#2", "42#4"])
        again = [p.rec.record_id for p in build_plan(records, cfg).accounts]
        self.assertEqual(again, ids)

    def test_store_records_not_resuffixed(self):
        src = self.tmp / "src.csv"
        src.write_text("x")
        st = Store(str(self.tmp / "m.db"), create=True, protector="plain")
        st.ingest("t", src, [rec("42", "a"), rec("42", "b")])
        loaded = st.load_records()
        st.close()
        plan = build_plan(loaded, config_from_dict({}))
        self.assertEqual(sorted(p.rec.source_id for p in plan.accounts), ["42", "42#2"])
        self.assertEqual(sum("suffixed in Record_ID" in w for p in plan.accounts for w in p.warnings), 1)


class ReviewRoundTrip(Base):
    def test_import_review_ignores_added_apostrophes(self):
        src = self.tmp / "in.csv"
        src.write_text("Name,Address,Username,Password\n=calc,@h,-adm,-pw\n")
        cfg = self.tmp / "cfg.json"
        cfg.write_text('{"default_platform": "WinServerLocal"}')
        db = str(self.tmp / "m.db")
        self.assertEqual(self.run_cli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", str(src))[0], 0)
        self.assertEqual(self.run_cli("map", "--db", db, "-c", str(cfg))[0], 0)
        out = self.tmp / "x"
        self.assertEqual(self.run_cli("extract", "--db", db, "-o", str(out), "--include-secrets")[0], 0)
        review = out / "review" / "Accounts_Review.csv"
        self.assertEqual(read_csv(review)[0]["Account_Name"], "'=calc")
        self.assertEqual(read_csv(out / "upload" / "Accounts.csv")[0]["secret"], "-pw")
        st = Store(db)
        try:
            self.assertEqual(st.import_review(review), 0)          # nothing changed, nothing imported
        finally:
            st.close()


class AccountNames(unittest.TestCase):
    def test_url_stripped_before_name(self):
        cfg = config_from_dict({"account_name": {"template": "{address}-{username}"}})
        records = [rec("1", address="https://fw01.example.com/login", username="admin")]
        first = build_plan(records, cfg).accounts[0].account_name
        again = build_plan(records, cfg).accounts[0].account_name
        self.assertEqual(first, "fw01.example.com-admin")
        self.assertEqual(again, first)

    def test_suffix_skips_existing_names(self):
        cfg = config_from_dict({"default_platform": "WinServerLocal"})
        plan = build_plan([rec("1", "admin"), rec("2", "admin"), rec("3", "admin_2"), rec("4", "admin")], cfg)
        names = [p.account_name for p in plan.accounts]
        safes = {p.safe for p in plan.accounts}
        self.assertEqual(len(safes), 1)
        self.assertEqual(names, ["admin", "admin_3", "admin_2", "admin_4"])
        self.assertEqual(len({n.lower() for n in names}), 4)


class GroupColumnCase(unittest.TestCase):
    def test_header_case_does_not_matter(self):
        row = OrderedDict([("Name", "a"), ("Username", "u"), ("Group", "CORP\\Ops"), ("ROLE", "Owner")])
        r = record_from_row(row, config_from_dict({}), source="table", source_file="f", row_ref="r2",
                            row_number=1, group_column="group", permission_column="role")
        self.assertEqual([(g.member, g.permission) for g in r.grants], [("CORP\\Ops", "Owner")])


class ConfigVersionKept(unittest.TestCase):
    def test_diff_keeps_version(self):
        cfg = config_from_dict({"default_platform": "X"})
        diff = config_diff(cfg)
        self.assertEqual(diff["config_version"], CONFIG_VERSION)
        self.assertEqual(config_diff(DEFAULT_CONFIG), {"config_version": CONFIG_VERSION})
        self.assertEqual(upgrade_config(diff), diff)            # current version: nothing to do


class AccessDeniedMessage(Base):
    def test_own_folder_is_not_blamed_on_another_user(self):
        from imw import owner
        ws = self.tmp / "ws"
        ws.mkdir()
        err = PermissionError(13, "Access is denied", str(ws / ".owner"))
        with mock.patch.object(owner.Path, "iterdir", side_effect=err):
            with self.assertRaises(owner.OwnerError) as ctx:
                owner.claim_workspace(ws)
        msg = str(ctx.exception)
        self.assertNotIn("belongs to another Windows user", msg)
        self.assertIn(".owner", msg)
        self.assertIn("Access is denied", msg)

    def test_other_owner_still_named(self):
        from imw import owner
        ws = self.tmp / "ws"
        ws.mkdir()
        with mock.patch.object(owner.Path, "iterdir", side_effect=PermissionError(13, "denied")), \
                mock.patch.object(owner, "path_owner_sid", return_value="S-1-5-21-9"):
            with self.assertRaisesRegex(owner.OwnerError, "belongs to another Windows user"):
                owner.claim_workspace(ws)


class WindowsAclCommands(Base):
    def test_files_inherit_instead_of_getting_folder_flags(self):
        from imw import owner
        ws = self.tmp / "ws"
        ws.mkdir()
        (ws / ".owner").write_text("{}")
        calls = []
        done = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(owner.sys, "platform", "win32"), \
                mock.patch.object(owner.subprocess, "run", side_effect=lambda c, **k: calls.append(c) or done):
            owner.restrict(ws, "S-1-5-21-1", recursive=True)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("/T", calls[0])                       # (OI)(CI) grant on the folder only
        self.assertIn("*S-1-5-21-1:(OI)(CI)F", calls[0])
        self.assertEqual(calls[1][1:4], [str(ws / "*"), "/reset", "/T"])


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class WindowsOnly(unittest.TestCase):
    def test_dpapi_roundtrip(self):
        from imw.protect import DpapiProtector
        p = DpapiProtector(b"salt")
        self.assertEqual(p.unprotect(p.protect("s3cret-ü", "r1"), "r1"), "s3cret-ü")

    def test_path_owner(self):
        from imw.owner import current_identity, path_owner_sid
        # An elevated session (a build server) makes new files owned by the Administrators group.
        self.assertIn(path_owner_sid(Path(__file__).parent), (current_identity()["sid"], "S-1-5-32-544"))


if __name__ == "__main__":
    unittest.main()
