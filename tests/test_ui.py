"""Tests for the local web UI backend (no browser needed)."""

import http.client
import json
import shutil
import threading
import unittest

from test_pam2pc import SAMPLES, Base, read_csv  # noqa: F401

from pam2pc.ui import server


class UiServer(Base):
    def setUp(self):
        super().setUp()
        self.ws = self.tmp / "ws"
        (self.ws / "inbox").mkdir(parents=True)
        for f in ("delinea_export.csv", "delinea_permissions.csv", "keepass_export.xml"):
            shutil.copy(SAMPLES / f, self.ws / "inbox" / f)
        started = threading.Event()
        holder = {}

        def ready(url, httpd):
            holder.update(url=url, httpd=httpd)
            started.set()

        self.thread = threading.Thread(target=server.serve, kwargs=dict(
            workspace=self.ws, port=0, open_browser=False, protector_flag="plain", ready=ready), daemon=True)
        with _Quiet():
            self.thread.start()
            started.wait(5)
        self.httpd = holder["httpd"]
        self.port = self.httpd.server_address[1]
        self.token = holder["url"].split("t=")[1]
        self.cookie = None

    def tearDown(self):
        self.httpd.shutdown()
        super().tearDown()

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
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

    def login(self):
        status, _ = self.req("GET", f"/?t={self.token}")
        self.assertEqual(status, 303)

    def test_guards(self):
        self.assertEqual(self.req("GET", "/api/state")[0], 401)
        self.assertEqual(self.req("GET", f"/?t={self.token}", host="evil.example")[0], 403)
        self.login()
        self.assertEqual(self.req("GET", f"/?t={self.token}")[0], 200)     # token is one-time; cookie works
        self.assertEqual(self.req("GET", "/api/state")[0], 200)
        self.assertEqual(self.req("POST", "/api/ingest", {}, headers={"X-Pam2pc": ""})[0], 403)
        self.assertEqual(self.req("POST", "/api/ingest", {}, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/inbox/delete", {"name": "../x"})[0], 400)
        self.cookie = "pam2pc_sid=forged"
        self.assertEqual(self.req("GET", "/api/state")[0], 401)

    def test_flow(self):
        self.login()
        st, r = self.req("POST", "/api/ingest", {"files": [{"name": "delinea_export.csv", "source": ""},
                                                           {"name": "keepass_export.xml", "source": ""}],
                                                 "permissions": "delinea_permissions.csv"})
        self.assertEqual(st, 200, r)
        self.assertEqual([x["records"] for x in r["results"]], [8, 4])

        st, cfg = self.req("GET", "/api/config")
        self.assertIn("Web Password", [t["name"] for t in cfg["hints"]["types"]])
        user = {"group_rules": [{"group": "CORP\\DBA-Team", "safe": "DB-Prod"}], "fallback_strategy": "folder_path"}
        self.assertEqual(self.req("POST", "/api/config", {"config": user})[0], 200)
        self.assertEqual(self.req("POST", "/api/config", {"config": {"group_rules": [{"safe": "X"}]}})[0], 400)

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
