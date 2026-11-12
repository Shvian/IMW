#!/usr/bin/env python3
"""
End-to-end and security test of the migration UI backend, against the Phase 2
mock APIs (phase2/tests/mock_apis.py). No real tenant or Delinea needed.

  python ui/tests/test_ui_backend.py

Covers the security model (one-time link, session cookie, Host/Origin/CSRF
checks, headers, idle expiry, no credentials in config, path traversal), upload
scrubbing, the guided flow (Phase 1, review edits, plan gate, rehearsal,
cleanup, migration, stop and resume without duplicates, retry), and that no
secret value or credential is ever written anywhere in the workspace.
"""
import csv
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "ui" / "server"))
import migration_ui  # noqa: E402

MOCK_PORT = 8765
MOCK = f"http://127.0.0.1:{MOCK_PORT}"
CA_SECRET, DL_SECRET = "test-secret", "delinea-test"
failures = []


def check(cond, msg, detail=None):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)
        if detail:
            print("       " + str(detail)[-1500:].replace("\n", "\n       "))


class Client:
    """Minimal HTTP client that keeps the session cookie and lets a test set any header."""

    def __init__(self, port):
        self.port, self.cookie = port, ""

    def req(self, method, path, body=None, headers=None, raw=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        h = {"Host": host or f"127.0.0.1:{self.port}", "X-Migration-UI": "1"}
        if self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if raw is not None:
            data = raw
            h["Content-Type"] = "application/octet-stream"
        elif body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        c.close()
        try:
            js = json.loads(payload)
        except ValueError:
            js = None
        return r.status, js, r.headers, payload

    def api(self, method, path, body=None, **kw):
        s, js, _, _ = self.req(method, "/api/" + path, body, **kw)
        return s, js

    def wait_job(self, job_id, timeout=240):
        t0 = time.time()
        while time.time() - t0 < timeout:
            s, js = self.api("GET", f"jobs/{job_id}/output?since=0", headers={"X-Poll": "1"})
            if js["job"]["state"] != "running":
                return js["job"], "\n".join(js["lines"])
            time.sleep(0.5)
        raise TimeoutError(job_id)

    def job(self, action, options=None, confirm=None, timeout=240):
        s, js = self.api("POST", "jobs", {"action": action, "options": options or {}, "confirm": confirm})
        if s != 200:
            return s, js, ""
        job, out = self.wait_job(js["id"], timeout)
        return s, job, out


def mock_get(path):
    return json.loads(urllib.request.urlopen(MOCK + path).read())


def mock_post(path, body):
    req = urllib.request.Request(MOCK + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req).read()


def main():
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    work = Path(tempfile.mkdtemp(prefix="ui_e2e_"))
    ws = work / "workspace"
    syn = work / "synthetic"
    subprocess.run([sys.executable, str(ROOT / "tools" / "generate_synthetic_delinea.py"), "--secrets", "120",
                    "--out", str(syn), "--with-values"], check=True, capture_output=True)
    mock = subprocess.Popen([sys.executable, str(ROOT / "phase2" / "tests" / "mock_apis.py"), str(MOCK_PORT)])
    for _ in range(50):
        if mock.poll() is not None:
            raise SystemExit(f"The mock API could not start; is port {MOCK_PORT} in use by another test?")
        try:
            mock_get("/_state")
            break
        except OSError:
            time.sleep(0.2)
    lines = []
    app, server = migration_ui.serve(str(ws), 0, False, 15, print_fn=lines.append)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = app.port
    link = next(l.strip() for l in lines if "/launch?token=" in l)
    token = link.split("token=")[1]
    c = Client(port)
    try:
        print("1. access control")
        s, js = c.api("GET", "overview")
        check(s == 401, "API refuses requests without a session")
        s, _, _, body = c.req("GET", "/")
        check(s == 401 and b"one-time link" in body, "page without a session explains how to get a link")
        s, _, _, _ = c.req("GET", "/launch?token=wrong")
        check(s == 403, "wrong launch token refused")
        s, _, hdr, _ = c.req("GET", f"/launch?token={token}", host=f"evil.example:{port}")
        check(s == 421, "wrong Host header refused (DNS rebinding)")
        s, _, hdr, _ = c.req("GET", f"/launch?token={token}")
        cookie = hdr.get("Set-Cookie", "")
        check(s == 303 and "HttpOnly" in cookie and "SameSite=Strict" in cookie, "launch link sets an HttpOnly, SameSite=Strict cookie")
        c.cookie = cookie.split(";")[0]
        s, _, _, _ = c.req("GET", f"/launch?token={token}")
        check(s == 403, "launch link works only once")
        s, js, hdr, _ = c.req("GET", "/api/overview")
        check(s == 200 and js["steps"], "session cookie grants access")
        csp = hdr.get("Content-Security-Policy", "")
        check("script-src 'self'" in csp and "frame-ancestors 'none'" in csp and hdr.get("X-Frame-Options") == "DENY",
              "strict security headers on every response")
        s, js = c.api("PUT", "session", {"operator": "Ian Tester"}, headers={"X-Migration-UI": None})
        check(s == 403, "state change without the custom header refused (CSRF)")
        s, js = c.api("PUT", "session", {"operator": "Ian Tester"}, headers={"Origin": "https://evil.example"})
        check(s == 403, "state change from another origin refused")
        s, js = c.api("PUT", "session", {"operator": "Ian Tester"}, headers={"Origin": f"http://127.0.0.1:{port}"})
        check(s == 200, "same-origin state change accepted")
        s, js = c.api("GET", "download?path=../../etc/passwd")
        check(s == 403, "download outside the workspace refused")
        s, _, _, body = c.req("GET", "/")
        check(s == 200 and b'<div id="root">' in body, "built UI is served")

        print("2. settings and credentials")
        mock_cfg = json.loads((ROOT / "phase2" / "tests" / "phase2_config_mock.json").read_text())
        s, js = c.api("GET", "config")
        cfg = js["phase2"]
        bad = json.loads(json.dumps(cfg))
        bad["cyberark"]["client_secret"] = "hunter2"
        s, js = c.api("PUT", "config/phase2", {"config": bad})
        check(s == 400 and "credential" in js["error"], "a credential in the config is refused")
        bad = json.loads(json.dumps(cfg))
        bad["verify_tls"] = False
        s, js = c.api("PUT", "config/phase2", {"config": bad})
        check(s == 400 and "verify_tls" in js["error"], "verify_tls=false is refused")
        bad = json.loads(json.dumps(cfg))
        bad["cyberark"]["api_base_url"] = "http://tenant.example.com/PasswordVault/API"
        s, js = c.api("PUT", "config/phase2", {"config": bad})
        check(s == 400 and "https" in js["error"], "plain http to a remote host is refused")
        for k in ("cyberark", "delinea"):
            cfg[k].update(mock_cfg[k])
        cfg["rate_recovery_seconds"] = 5
        cfg["directory_map"] = mock_cfg["directory_map"]
        fast = json.loads(json.dumps(cfg))
        fast["cyberark"]["max_calls_per_window"] = 6000
        s, js = c.api("PUT", "config/phase2", {"config": fast})
        check(s == 200 and any("at or above" in w for w in js["warnings"]), "limits above the 5000/5 min policy are flagged", js)
        s, js = c.api("PUT", "config/phase2", {"config": cfg})
        check(s == 200 and not any("at or above" in w for w in js["warnings"]),
              "mock settings saved; the 4900 per 5 min hard cap keeps them within policy", js)
        s, js = c.api("POST", "jobs", {"action": "preflight"})
        check(s == 409 and "credential" in js["error"], "a job needing a credential refuses to start without it")
        s, js = c.api("POST", "credentials", {"system": "cyberark", "value": "wrong-secret"})
        s, js = c.api("POST", "connections/test", {"system": "cyberark"})
        check(s == 200 and not js["ok"] and "AUTH" not in js["message"] and "wrong-secret" not in json.dumps(js),
              "failed sign-in reported without echoing the credential")
        c.api("POST", "credentials", {"system": "cyberark", "value": CA_SECRET})
        c.api("POST", "credentials", {"system": "delinea", "value": DL_SECRET})
        s, js = c.api("POST", "connections/test", {"system": "cyberark"})
        check(s == 200 and js["ok"], "CyberArk sign-in test OK")
        s, js = c.api("POST", "connections/test", {"system": "delinea"})
        check(s == 200 and js["ok"], "Delinea sign-in test OK")
        s, ov = c.api("GET", "overview")
        check(ov["session"]["credentials"] == {"cyberark": True, "delinea": True}
              and CA_SECRET not in json.dumps(ov) and DL_SECRET not in json.dumps(ov),
              "overview says credentials are set, without revealing them")
        s, job, out = c.job("preflight")
        check(job["exit_code"] in (0, 3) and "[OK        ] Authenticate service user" in out and not mock_get("/_state")["safes"],
              "tenant preflight runs read-only from the UI (the mock lacks some read APIs)", out)

        print("3. uploads are scrubbed before saving")
        s, js, _, _ = c.req("POST", "/api/files/export", raw=(syn / "delinea_export_synthetic.csv").read_bytes(),
                            headers={"X-Filename": "full_export.csv"})
        dropped = {d["name"] for d in js["dropped_columns"]}
        saved = (ws / "inputs" / "delinea_export.csv").read_text(encoding="utf-8-sig")
        check(s == 200 and {"Password", "Private Key"} <= dropped, f"secret columns removed ({sorted(dropped)})")
        check(js["secret_values_removed"] > 100 and js["warnings"], "plaintext values counted and the user warned")
        check("FAKE-" not in saved and "BEGIN OPENSSH" not in saved and "Secret ID" in saved,
              "saved export holds no secret values but keeps the Secret ID")
        check(js["sections"] == 7, "every template section kept")
        s, js, _, _ = c.req("POST", "/api/files/permissions", raw=(syn / "delinea_permissions_synthetic.csv").read_bytes(),
                            headers={"X-Filename": "perms.csv"})
        check(s == 200 and js["rows"] > 10, "permissions uploaded")
        s, js, _, _ = c.req("POST", "/api/files/permissions", raw=b"a,b\n1,2\n", headers={"X-Filename": "x.csv"})
        check(s == 400 and "Group" in js["error"], "a wrong permissions file is refused with a clear message")

        print("4. mapping rules and Phase 1")
        s, js = c.api("GET", "config")
        mcfg = js["mapping"]
        syn_rules = json.loads((syn / "mapping_config_synthetic.json").read_text())
        mcfg["group_rules"] = syn_rules["group_rules"]
        mcfg["fallback_strategy"] = syn_rules["fallback_strategy"]
        bad = dict(mcfg, group_rules=[{"group_pattern": "([", "safe": "X"}])
        s, js = c.api("PUT", "config/mapping", {"config": bad})
        check(s == 400 and "regex" in js["error"], "an invalid regex rule is refused", js)
        s, js = c.api("PUT", "config/mapping", {"config": mcfg})
        check(s == 200, "mapping rules saved", js)
        s, job, out = c.job("phase1")
        check(job["exit_code"] == 0 and (ws / "phase1_output" / "Migration_Review.csv").exists(), "Phase 1 generated the review files")

        print("5. review edits")
        s, js = c.api("GET", "review/accounts?filter=&limit=500")
        total = js["total"]
        check(total == 120, f"all accounts listed ({total})")
        cols = js["columns"]
        row0 = js["rows"][0]
        s, js = c.api("PUT", "review/accounts", {"changes": [{"row": row0["row"], "column": "Target CyberArk Safe",
                                                               "value": "Bad|Name"}]})
        check(s == 400 and "invalid" in js["error"], "invalid Safe name rejected")
        s, js = c.api("PUT", "review/accounts", {"changes": [{"row": 0, "column": "Delinea Secret ID", "value": "1"}]})
        check(s == 400, "non-editable column rejected")
        s, js = c.api("GET", "review/accounts?filter=&q=Legacy&limit=500")
        legacy = js["matched"]
        s, js = c.api("PUT", "review/accounts", {"bulk": {"column": "Migrate", "value": "N", "q": "Legacy", "filter": ""}})
        check(s == 200 and js["changed"] == legacy and legacy > 0, f"bulk-excluded the unmapped template ({legacy} rows)")
        s, js = c.api("GET", "review/safes")
        safes = js["safes"]
        target = next(x for x in safes if x["members"])
        s, js = c.api("POST", "review/rename-safe", {"old": target["safe"], "new": "WIN-Admins-Renamed"})
        check(s == 200 and js["renamed"]["Migration_Review.csv"] == target["accounts"]
              and js["renamed"].get("Safe_Members_Review.csv", 0) == target["members"],
              "renaming a Safe updates its accounts and members together")
        s, js = c.api("GET", "review/members?limit=500")
        mem_total = js["total"]
        s, js = c.api("PUT", "review/members", {"add_rows": [{"safe": "WIN-Admins-Renamed", "member": "CORP\\Ghost-Team",
                                                               "role": "Viewer"}]})
        check(s == 200 and js["changed"] == 1, "member added in the UI")
        check(any((ws / "history").iterdir()), "previous versions kept under history/")

        print("6. plan gate, rehearsal and cleanup")
        s, js = c.api("POST", "jobs", {"action": "migrate", "confirm": "MIGRATE"})
        check(s == 409 and "Plan" in js["error"], "migration refused before a clean plan")
        s, job, out = c.job("plan")
        check(job["exit_code"] == 0 and "No changes were made" in out, "plan is clean")
        c.api("PUT", "review/accounts", {"changes": [{"row": 0, "column": "Username", "value": "changed_after_plan"}]})
        s, js = c.api("POST", "jobs", {"action": "migrate", "confirm": "MIGRATE"})
        check(s == 409, "migration refused when the review changed after the plan")
        c.api("PUT", "review/accounts", {"changes": [{"row": 0, "column": "Username", "value": row0["values"][cols.index("Username")]}]})
        s, js = c.api("POST", "jobs", {"action": "rehearsal", "options": {"prefix": "TEST-"}, "confirm": "REHEARSE"})
        check(s == 400 and "ZZ" in js["error"], "rehearsal prefix must start with ZZ")
        s, js = c.api("POST", "jobs", {"action": "rehearsal", "options": {"prefix": "ZZTEST-"}})
        check(s == 400 and "REHEARSE" in js["error"], "rehearsal needs the typed confirmation")
        reads = mock_get("/_state")["secret_reads"]
        s, job, out = c.job("rehearsal", {"prefix": "ZZ-"}, "REHEARSE")
        st = mock_get("/_state")
        check(job["exit_code"] in (0, 3) and st["secret_reads"] == reads, f"rehearsal ran without contacting Delinea (exit {job['exit_code']})", out)
        check(st["safes"] and all(k.startswith("zz-") for k in st["safes"]), "rehearsal Safes are prefixed")
        check("Ghost-Team" in out, "rehearsal surfaced the unknown member group")
        s, js = c.api("GET", "progress?mode=rehearsal")
        check(js["ledger"] and js["ledger"]["stages"]["ACCOUNT"].get("DONE", 0) == total - legacy,
              "progress shows every included account done", js)
        s, js = c.api("POST", "jobs", {"action": "cleanup-rehearsal"})
        check(s == 400 and "DELETE" in js["error"], "cleanup needs the typed confirmation")
        s, job, out = c.job("cleanup-rehearsal", {}, "DELETE")
        check(job["exit_code"] == 0 and not mock_get("/_state")["safes"], "cleanup removed the rehearsal Safes")

        print("7. migration: stop, resume without duplicates, retry")
        s, job, out = c.job("plan")
        mock_post("/_control", {"limits": {"cyberark": 4, "delinea": 2}})
        s, js = c.api("POST", "jobs", {"action": "migrate", "confirm": "MIGRATE"})
        check(s == 200, "migration started after a clean plan")
        jid = js["id"]
        time.sleep(6)
        s, js = c.api("POST", "jobs", {"action": "plan"})
        check(s == 409, "a second job cannot start while one runs")
        s, js = c.api("POST", "jobs/current/stop")
        stopped, out = c.wait_job(jid, 60)
        check(stopped["outcome"] == "stopped" and "Interrupted" in out, "Stop interrupts the run cleanly")
        s, ov = c.api("GET", "overview")
        check(not ov["locks"]["production"], "the run lock was released")
        mock_post("/_control", {"limits": {"cyberark": 200, "delinea": 200}, "deny": []})
        s, job, out = c.job("migrate", {}, "MIGRATE")
        st = mock_get("/_state")
        names = [(a["safeName"].lower(), a["name"].lower()) for a in st["accounts"]]
        s, led = c.api("GET", "ledger?mode=production&stage=ACCOUNT&limit=500")
        results = {}
        for r in led["rows"]:
            results[r["status"] + "/" + str(r["result"])] = results.get(r["status"] + "/" + str(r["result"]), 0) + 1
        check(len(names) == len(set(names)) == total - legacy, f"resumed run finished every account once ({len(names)})",
              {"unique": len(set(names)), "ledger": results, "safes": len(st["safes"])})
        got = mock_get("/_received_secrets")
        check(sum(1 for v in got.values() if str(v).startswith("Synth!")) >= total - legacy - 5,
              "accounts received their Delinea secrets just in time", {k: v for k, v in list(got.items())[:5]})
        check(job["exit_code"] == 3 and "Ghost-Team" in out, "the unknown member is reported as a failure")
        s, js = c.api("GET", "ledger?mode=production&status=FAILED")
        check(js["total"] == 1 and js["rows"][0]["hint"], "the failure is listed with a fix hint")
        before = len(mock_get("/_state")["accounts"])
        s, job, out = c.job("migrate", {"only_failed": True}, "MIGRATE")
        check(len(mock_get("/_state")["accounts"]) == before, "retry of failures sent nothing twice")
        s, job, out = c.job("probe-delinea", {"per_template": 1})
        check(job["exit_code"] == 0 and "authentication OK" in out, "Delinea probe runs from the UI")
        s, job, out = c.job("report", {"mode": "production"})
        check(job["exit_code"] == 0 and list((ws / "state" / "production").glob("migration_report_*.csv")), "ledger report exported")

        print("8. audit")
        for log in ("production", "rehearsal", "ui"):
            s, js = c.api("POST", "audit/verify", {"log": log})
            check(js["ok"], f"{log} audit chain intact: {js['message']}")
        events = [json.loads(l)["event"] for l in (ws / "ui_audit.jsonl").read_text().splitlines()]
        want = {"ui_session_start", "ui_operator_set", "ui_credential_set", "ui_config_saved", "ui_file_uploaded",
                "ui_review_edited", "ui_safe_renamed", "ui_job_start", "ui_job_end", "ui_connection_test"}
        check(want <= set(events), "UI audit records sessions, credentials set, uploads, edits, jobs and tests")
        s, _, _, payload = c.req("GET", "/api/download?path=phase1_output/Migration_Review.csv")
        check(s == 200 and b"Delinea Secret ID" in payload, "review file downloads")
        s, js = c.api("GET", "audit?log=ui&limit=5")
        check(js["entries"][0]["event"] == "ui_download", "downloads are audited")

        print("9. no secret anywhere on disk")
        leaks = []
        values = [CA_SECRET.encode(), DL_SECRET.encode(), b"Synth!", b"FAKE-", b"BEGIN OPENSSH", b"wrong-secret"]
        for p in ws.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                leaks += [f"{p.relative_to(ws)}: {v.decode()}" for v in values if v in data]
        check(not leaks, "no credential or secret value in any workspace file" + (f": {leaks[:5]}" if leaks else ""))

        print("10. session idle expiry drops credentials")
        app.session.idle_seconds = 1
        time.sleep(1.6)
        s, js = c.api("GET", "overview")
        check(s == 401 and not app.session.has("cyberark") and not app.session.has("delinea"),
              "idle session ended and credentials dropped")
        token2 = app.session.new_launch_token()
        app.session.idle_seconds = 900
        s, _, hdr, _ = c.req("GET", f"/launch?token={token2}")
        c.cookie = hdr.get("Set-Cookie", "").split(";")[0]
        s, ov = c.api("GET", "overview")
        check(s == 200 and ov["session"]["credentials"] == {"cyberark": False, "delinea": False},
              "a fresh link starts a clean session")
    finally:
        server.shutdown()
        app.shutdown("test finished")
        mock.terminate()

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for f in failures:
            print("  - " + f)
        return 1
    print("All UI backend checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
