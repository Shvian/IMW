"""Tests for the local web UI backend (no browser needed)."""

import http.client
import json
import shutil
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from test_pam2pc import SAMPLES, Base, read_csv  # noqa: F401

from pam2pc.ui import server, tls
from pam2pc.ui.auth import TestAuth

PASSWORD = "correct horse"


_CERT_DIR = None


def _shared_cert():
    """One certificate for the whole test run (making one takes about half a second)."""
    global _CERT_DIR
    if _CERT_DIR is None:
        _CERT_DIR = Path(tempfile.mkdtemp(prefix="pam2pc-cert-"))
        tls.ensure_certificate(_CERT_DIR)
    return _CERT_DIR / "tls"


class UiServer(Base):
    def setUp(self):
        super().setUp()
        self.ws = self.tmp / "ws"
        (self.ws / "inbox").mkdir(parents=True)
        shutil.copytree(_shared_cert(), self.ws / "tls")
        for f in ("delinea_export.csv", "delinea_permissions.csv", "keepass_export.xml"):
            shutil.copy(SAMPLES / f, self.ws / "inbox" / f)
        started = threading.Event()
        holder = {}

        def ready(url, httpd):
            holder.update(url=url, httpd=httpd)
            started.set()

        self.thread = threading.Thread(target=server.serve, kwargs=dict(
            workspace=self.ws, port=0, open_browser=False, protector_flag="plain", ready=ready,
            authenticator=TestAuth(PASSWORD)), daemon=True)
        with _Quiet():
            self.thread.start()
            started.wait(5)
        self.httpd = holder["httpd"]
        self.port = self.httpd.server_address[1]
        self.token = holder["url"].split("t=")[1]
        self.cookie = None
        self.tls = ssl.create_default_context(cafile=str(self.ws / "tls" / tls.CERT_NAME))

    def tearDown(self):
        if not getattr(self, "ended", False):
            self.httpd.shutdown()
        super().tearDown()

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=self.tls)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST":
            h["X-Pam2pc"] = "1"
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        data = r.read()
        if r.getheader("Set-Cookie"):
            self.cookie = r.getheader("Set-Cookie").split(";")[0]
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data

    def login(self, unlock=True):
        status, _ = self.req("GET", f"/?t={self.token}")
        self.assertEqual(status, 303)
        if unlock:
            self.assertEqual(self.req("POST", "/api/unlock", {"password": PASSWORD})[0], 200)

    def test_https_only(self):
        c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=self.tls)
        c.request("GET", f"/?t={self.token}", headers={"Host": f"127.0.0.1:{self.port}"})
        r = c.getresponse()
        self.assertEqual(r.status, 303)
        self.assertIn("Secure", r.getheader("Set-Cookie"))
        self.assertIn("HttpOnly", r.getheader("Set-Cookie"))
        self.cookie = r.getheader("Set-Cookie").split(";")[0]
        plain = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        with self.assertRaises((http.client.HTTPException, OSError)):
            plain.request("GET", "/api/session")
            plain.getresponse().read()
        self.assertEqual(self.req("GET", "/api/session")[0], 200)     # server still fine afterwards

    def test_sign_in_and_lock(self):
        self.login(unlock=False)
        st, s = self.req("GET", "/api/session")
        self.assertTrue(s["locked"])
        self.assertEqual(self.req("GET", "/api/state")[0], 423)                    # locked until sign-in
        self.assertEqual(self.req("POST", "/api/unlock", {"password": "nope"})[0], 400)
        self.assertEqual(self.req("POST", "/api/unlock", {"password": PASSWORD})[0], 200)
        self.assertEqual(self.req("GET", "/api/state")[0], 200)
        self.assertEqual(self.req("POST", "/api/lock", {})[0], 200)
        self.assertEqual(self.req("GET", "/api/state")[0], 423)
        self.req("POST", "/api/unlock", {"password": PASSWORD})
        app_last = server.time.time
        try:                                                                      # idle for 11 minutes
            server.time.time = lambda: app_last() + 11 * 60
            self.assertEqual(self.req("GET", "/api/state")[0], 423)
        finally:
            server.time.time = app_last
        for _ in range(server.MAX_FAILURES):
            self.req("POST", "/api/unlock", {"password": "nope"})
        self.assertEqual(self.req("POST", "/api/unlock", {"password": PASSWORD})[0], 429)  # slowed down

    def test_end_session_can_delete_database(self):
        self.login()
        self.req("POST", "/api/ingest", {"files": [{"name": "keepass_export.xml", "source": ""}]})
        self.assertTrue((self.ws / "migration.db").exists())
        self.assertEqual(self.req("POST", "/api/end", {"confirm": "end"})[0], 400)
        st, r = self.req("POST", "/api/end", {"confirm": "END SESSION", "delete_db": True})
        self.assertEqual((st, r["database_deleted"]), (200, True))
        self.assertFalse((self.ws / "migration.db").exists())
        self.ended = True

    def test_guards(self):
        self.assertEqual(self.req("GET", "/api/state")[0], 401)
        self.assertEqual(self.req("GET", f"/?t={self.token}", host="evil.example")[0], 403)
        self.login()
        self.assertEqual(self.req("GET", f"/?t={self.token}")[0], 200)     # token is one-time; cookie works
        self.assertEqual(self.req("GET", "/api/state")[0], 200)
        self.assertEqual(self.req("POST", "/api/ingest", {}, headers={"X-Pam2pc": ""})[0], 403)
        self.assertEqual(self.req("POST", "/api/ingest", {}, headers={"Origin": "http://evil.example"})[0], 403)
        plain_origin = {"Origin": f"http://127.0.0.1:{self.port}"}    # the http:// twin of this page
        self.assertEqual(self.req("POST", "/api/ingest", {}, headers=plain_origin)[0], 403)
        self.assertEqual(self.req("POST", "/api/inbox/delete", {"name": "../x"})[0], 400)
        self.cookie = "pam2pc_sid=forged"
        self.assertEqual(self.req("GET", "/api/state")[0], 401)

    def test_flow(self):
        self.login()
        st, r = self.req("POST", "/api/ingest", {"files": [{"name": "delinea_export.csv", "source": ""},
                                                           {"name": "keepass_export.xml", "source": ""}],
                                                 "permissions": ["delinea_permissions.csv"]})
        self.assertEqual(st, 200, r)
        self.assertEqual([x["records"] for x in r["results"]], [8, 4])
        st, r = self.req("POST", "/api/ingest", {"files": [{"name": "keepass_export.xml", "source": ""}]})
        st, state = self.req("GET", "/api/state")
        self.assertEqual(len(state["inputs"][0]["sha256"]), 64)
        self.assertIn("same content as load #2", state["inputs"][2]["repeat"])
        st, r = self.req("POST", "/api/config", {"patch": {"default_platform": "WinServerLocal"}})
        self.assertEqual(st, 200, r)
        self.assertEqual(json.loads((self.ws / "config.json").read_text()), {"default_platform": "WinServerLocal"})
        self.assertEqual(self.req("POST", "/api/config", {"patch": {"safe_rules": [
            {"safe_pattern": "(", "managingCPM": "x"}]}})[0], 400)

        st, cfg = self.req("GET", "/api/config")
        self.assertIn("Web Password", [t["name"] for t in cfg["hints"]["types"]])
        user = {"group_rules": [{"group": "CORP\\DBA-Team", "safe": "DB-Prod"}], "fallback_strategy": "folder_path"}
        self.assertEqual(self.req("POST", "/api/config", {"config": user})[0], 200)
        self.assertEqual(self.req("POST", "/api/config", {"config": {"group_rules": [{"safe": "X"}]}})[0], 400)
        saved = json.loads((self.ws / "config.json").read_text())
        self.assertEqual(set(saved), {"group_rules", "fallback_strategy"})        # only the changes are kept
        for bad in ({"custom_roles": {"Full": ["listAccounts"]}},
                    {"custom_roles": {"X": ["listAccounts", "requestsAuthorizationLevel1", "requestsAuthorizationLevel2"]}},
                    {"permission_map": {"View": "Nobody"}}):
            self.assertEqual(self.req("POST", "/api/config", {"config": dict(user, **bad)})[0], 400, bad)
        self.assertEqual(self.req("POST", "/api/config", {"config": user})[0], 200)

        st, d = self.req("POST", "/api/accounts", {"view": "all", "filters": {"search": "svc_sql"}})
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["rows"][0]["target_safe"], "DB-Prod")
        st, d = self.req("POST", "/api/accounts", {"view": "errors"})
        self.assertEqual(d["total"], 1)
        st, d = self.req("POST", "/api/accounts", {"view": "nope"})
        self.assertEqual(st, 400)
        st, d = self.req("POST", "/api/accounts", {"view": "all", "sort": "secret_enc; DROP TABLE records"})
        self.assertEqual(st, 200)                                              # unknown sort ignored

        st, r = self.req("POST", "/api/edit", {"view": "errors", "values": {"migrate": "N"}, "reason": "t"})
        self.assertEqual((st, r["changed"]), (200, 1))
        st, r = self.req("POST", "/api/edit", {"ids": ["delinea:delinea_export:107"],
                                               "values": {"target_safe": "FIN:Portals"}})
        self.assertEqual(st, 200)
        st, r = self.req("POST", "/api/edit", {"ids": ["x"], "values": {"secret_enc": "x"}})
        self.assertEqual(st, 400)
        st, rec = self.req("POST", "/api/record", {"id": "delinea:delinea_export:101"})
        self.assertNotIn("secret_enc", rec)
        self.assertNotIn("P@ssw0rd", json.dumps(rec))

        st, r = self.req("POST", "/api/extract", {"name": "w1", "include_secrets": True})
        self.assertEqual(st, 400)                                              # needs typed confirmation
        st, r = self.req("POST", "/api/extract", {"name": "w1", "include_secrets": True, "confirm": "INCLUDE SECRETS",
                                                  "scope": "filter", "view": "all", "filters": {"source": "delinea"}})
        self.assertEqual(st, 200, r)
        accounts = {a["recordId"].split(":")[-1]: a for a in read_csv(self.ws / "output" / "w1" / "upload" / "Accounts.csv")}
        self.assertEqual(accounts["107"]["safeName"], "FIN-Portals")
        self.assertEqual(accounts["101"]["secret"], "P@ssw0rd!1")
        self.assertTrue(all(k.startswith("delinea:") for k in (a["recordId"] for a in accounts.values())))
        st, r = self.req("POST", "/api/output/delete", {"name": "w1", "what": "upload"})
        self.assertEqual(st, 200)
        self.assertFalse((self.ws / "output" / "w1" / "upload").exists())
        self.assertTrue((self.ws / "output" / "w1" / "review").exists())

        st, r = self.req("POST", "/api/inbox/delete", {"name": "delinea_export.csv"})
        self.assertEqual(st, 200)
        self.assertFalse((self.ws / "inbox" / "delinea_export.csv").exists())
        st, a = self.req("GET", "/api/audit")
        self.assertIn("extract", [x["action"] for x in a["audit"]])
        self.assertIn("extract", [x["action"] for x in a["summary"]["by_action"]])
        st, text = self.req("GET", "/api/export/audit.csv")
        self.assertEqual(st, 200)
        self.assertTrue(text.decode("utf-8-sig").startswith("id,ts,user,host,action,detail"))
        st, text = self.req("GET", "/api/export/edits.csv")
        self.assertTrue(text.decode("utf-8-sig").startswith("record_id,field,value"))


    def test_members_platforms_and_sanitizing(self):
        dirty = (SAMPLES / "delinea_export.csv").read_text(encoding="utf-8-sig").replace("svc_sql", "svc\u200b_sql", 1)
        (self.ws / "inbox" / "delinea_export.csv").write_text(dirty, encoding="utf-8")
        self.login()
        st, r = self.req("POST", "/api/ingest", {"files": [{"name": "delinea_export.csv", "source": ""}],
                                                 "permissions": ["delinea_permissions.csv"]})
        self.assertEqual(st, 200, r)
        self.assertEqual(r["results"][0]["sanitized"], 1)
        st, d = self.req("POST", "/api/accounts", {"view": "sanitized"})
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["rows"][0]["username"], "svc_sql_prod")

        st, s = self.req("GET", "/api/safes")
        safes = [x["safe_name"] for x in s["safes"] if x["accounts_to_upload"]][:2]
        self.assertEqual(len(safes), 2)
        st, r = self.req("POST", "/api/members/edit", {"action": "add", "member_name": "PAM-Auditors",
                                                       "safes": safes, "search_in": "corp.example.com",
                                                       "member_type": "Group", "role": "Read only"})
        self.assertEqual((st, r["changed"]), (200, 2), r)
        self.assertEqual(self.req("POST", "/api/members/edit", {"action": "add", "member_name": "X",
                                                                "safes": safes, "role": "nope"})[0], 400)
        st, s = self.req("GET", "/api/safes")
        added = [m for m in s["members"] if m["member_name"] == "PAM-Auditors"]
        self.assertEqual(sorted(m["safe_name"] for m in added), sorted(safes))
        self.assertEqual({m["search_in"] for m in added}, {"corp.example.com"})
        victim = next(m for m in s["members"] if m["safe_name"] == safes[0] and m["member_name"] != "PAM-Auditors")
        st, r = self.req("POST", "/api/members/edit", {"action": "remove",
                                                       "pairs": [[safes[0], victim["member_name"]]]})
        self.assertEqual(st, 200, r)
        st, s = self.req("GET", "/api/safes")
        self.assertNotIn((safes[0], victim["member_name"]), {(m["safe_name"], m["member_name"]) for m in s["members"]})
        self.assertEqual(len(s["member_edits"]), 3)
        self.req("POST", "/api/members/edit", {"action": "undo", "pairs": [[safes[0], victim["member_name"]]]})
        st, s = self.req("GET", "/api/safes")
        self.assertIn((safes[0], victim["member_name"]), {(m["safe_name"], m["member_name"]) for m in s["members"]})

        st, d = self.req("POST", "/api/accounts", {"view": "all", "filters": {"search": "svc_sql"}})
        rid = d["rows"][0]["record_id"]
        st, r = self.req("POST", "/api/edit", {"ids": [rid], "values": {"platform_id": "(none)"}})
        self.assertEqual(st, 200, r)
        st, d = self.req("POST", "/api/accounts", {"view": "all", "filters": {"search": "svc_sql"}})
        self.assertEqual((d["rows"][0]["platform_id"], d["rows"][0]["status"]), ("", "ERROR"))
        self.assertIn("no platform", d["rows"][0]["notes"])
        st, r = self.req("POST", "/api/edit", {"ids": [rid], "values": {"platform_id": "Win Server/Local"}})
        st, d = self.req("POST", "/api/accounts", {"view": "all", "filters": {"search": "svc_sql"}})
        self.assertEqual(d["rows"][0]["platform_id"], "Win_Server_Local")

        st, r = self.req("POST", "/api/extract", {"name": "o1"})
        self.assertEqual(st, 200, r)
        up = self.ws / "output" / "o1" / "upload"
        cats = {c["column"]: c for c in read_csv(up / "FileCategories.csv")}
        self.assertIn("address", cats)
        self.assertTrue(read_csv(up / "PlatformProperties.csv"))
        members = read_csv(up / "SafeMembers.csv")
        self.assertEqual(sum(1 for m in members if m["memberName"] == "PAM-Auditors"), 2)


class _Quiet:
    """Silence the server's start-up prints during tests."""
    def __enter__(self):
        import io
        import sys
        self._old, sys.stdout = sys.stdout, io.StringIO()

    def __exit__(self, *exc):
        import sys
        sys.stdout = self._old


if __name__ == "__main__":
    unittest.main()
