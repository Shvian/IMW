"""Only the Windows user who created a workspace or database can open it."""

import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from imw import owner, store
from imw.store import Store, StoreError

IAN = {"sid": "S-1-5-21-1-1001", "domain": "CORP", "user": "ian", "display": "CORP\\ian"}
BOB = {"sid": "S-1-5-21-1-1002", "domain": "CORP", "user": "bob", "display": "CORP\\bob"}


def as_user(who):
    return mock.patch.multiple(owner, current_identity=lambda: who), mock.patch.object(store, "current_identity", lambda: who)


class Owner(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        if os.name == "nt":
            # Windows can't put the made-up SIDs of Ian and Bob on a real folder (icacls refuses unknown
            # accounts), and on an elevated build server new folders belong to Administrators: stand in for both.
            for p in (mock.patch.object(owner, "restrict", lambda *a, **k: "test"),
                      mock.patch.object(store, "restrict", lambda *a, **k: "test"),
                      mock.patch.object(owner, "path_owner_sid", lambda path: IAN["sid"])):
                p.start()
                self.addCleanup(p.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_as(self, who, fn):
        a, b = as_user(who)
        with a, b:
            return fn()

    def test_database_opens_only_for_its_creator(self):
        db = self.tmp / "m.db"
        self.run_as(IAN, lambda: Store(db, create=True, protector="none").close())
        self.run_as(IAN, lambda: Store(db).close())
        with self.assertRaises(StoreError) as cm:
            self.run_as(BOB, lambda: Store(db))
        self.assertIn("belongs to CORP\\ian", str(cm.exception))
        if os.name == "posix":
            self.assertEqual(db.stat().st_mode & 0o777, 0o600)

    def test_older_database_is_claimed_by_its_creator_only(self):
        db = self.tmp / "m.db"
        self.run_as(IAN, lambda: Store(db, create=True, protector="none").close())
        con = sqlite3.connect(db)
        con.execute("DELETE FROM meta WHERE key IN ('owner_sid', 'owner_name')")
        con.execute("UPDATE meta SET value = 'ian@host' WHERE key = 'created_by'")
        con.commit()
        con.close()
        with self.assertRaises(StoreError):
            self.run_as(BOB, lambda: Store(db))
        self.run_as(IAN, lambda: Store(db).close())          # claims it
        with self.assertRaises(StoreError):
            self.run_as(BOB, lambda: Store(db))
        con = sqlite3.connect(db)
        self.assertEqual(con.execute("SELECT value FROM meta WHERE key='owner_sid'").fetchone()[0], IAN["sid"])

    def test_workspace_is_locked_to_its_owner(self):
        ws = self.tmp / "ws"
        self.run_as(IAN, lambda: owner.claim_workspace(ws))
        (ws / "inbox").mkdir()
        (ws / "inbox" / "export.csv").write_text("x")
        self.run_as(IAN, lambda: owner.claim_workspace(ws))
        with self.assertRaises(owner.OwnerError) as cm:
            self.run_as(BOB, lambda: owner.claim_workspace(ws))
        self.assertIn("belongs to CORP\\ian", str(cm.exception))
        if os.name == "posix":
            self.assertEqual(ws.stat().st_mode & 0o777, 0o700)
            self.assertEqual((ws / "inbox" / "export.csv").stat().st_mode & 0o777, 0o600)

    def test_workspace_needs_an_empty_or_workspace_folder(self):
        ws = self.tmp / "docs"
        ws.mkdir()
        (ws / "holiday.jpg").write_text("x")
        with self.assertRaises(owner.OwnerError) as cm:
            self.run_as(IAN, lambda: owner.claim_workspace(ws))
        self.assertIn("holiday.jpg", str(cm.exception))

    def test_old_workspace_is_claimed_by_the_folder_owner_only(self):
        ws = self.tmp / "ws"
        (ws / "inbox").mkdir(parents=True)
        mine = {**IAN, "sid": f"uid:{os.getuid()}"} if os.name == "posix" else IAN
        with self.assertRaises(owner.OwnerError):
            self.run_as(BOB, lambda: owner.claim_workspace(ws))
        self.run_as(mine, lambda: owner.claim_workspace(ws))

    def test_ui_refuses_to_start_on_someone_elses_workspace(self):
        from imw.ui import server
        ws = self.tmp / "ws"
        self.run_as(IAN, lambda: owner.claim_workspace(ws))
        a, b = as_user(BOB)
        with a, b, mock.patch.object(server, "claim_workspace", owner.claim_workspace):
            with self.assertRaises(owner.OwnerError):
                server.App(ws, "plain", authenticator=object())

    def test_identity_is_not_taken_from_environment(self):
        with mock.patch.dict(os.environ, {"USERNAME": "someone-else", "USERDOMAIN": "EVIL"}):
            me = owner.current_identity()
        self.assertNotEqual(me["user"], "someone-else")


if __name__ == "__main__":
    unittest.main()
