"""Drive the Python and the .NET Workbench web servers through the same API calls and compare the answers.

    python dotnet/tests/parity/ui_parity.py [--imw path/to/IMW.dll|IMW.exe] [--keep] [-v]

Each server gets its own workspace with the same export files in its inbox, runs with a test
password (IMW_UI_TEST_PASSWORD) and plain-text secrets (test data only), and is driven over HTTPS
exactly as the browser page drives it. Status codes and JSON bodies must match after replacing the
parts that differ by nature: the workspace folder, timestamps, the port and the session token.
"""

import argparse
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples"
PASSWORD = "parity-pw"
INBOX = ["delinea_export.csv", "delinea_permissions.csv", "keepass_export.xml", "accounts_inventory.csv",
         "delinea_export.xml", "accounts_by_group.xlsx"]


class Side:
    def __init__(self, name, cmd, ws):
        self.name, self.ws = name, ws
        (ws / "inbox").mkdir(parents=True)
        for f in INBOX:
            shutil.copy(SAMPLES / f, ws / "inbox" / f)
        env = dict(os.environ, IMW_UI_TEST_PASSWORD=PASSWORD, IMW_UI_NO_OPEN="1", PYTHONPATH=str(ROOT))
        self.proc = subprocess.Popen(cmd + ["ui", "-w", str(ws), "--no-browser", "--insecure-plaintext-secrets"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=ws.parent)
        self.lines = []
        url = None
        deadline = time.time() + 60
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            self.lines.append(line.rstrip("\n"))
            m = re.search(r"Open this link \(works once\): (\S+)", line)
            if m:
                url = m.group(1)
            if line.startswith("Sign in as"):
                break
        if not url:
            raise SystemExit(f"{name} did not start:\n" + "\n".join(self.lines) + self.proc.stderr.read())
        self.url = url
        self.port = int(re.search(r":(\d+)/", url).group(1))
        self.token = url.split("t=")[1]
        self.cookie = None
        self.tls = ssl.create_default_context(cafile=str(ws / "tls" / "workbench.crt"))

    def req(self, method, path, body=None, headers=None, raw=None):
        c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=60, context=self.tls)
        h = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST":
            h["X-IMW"] = "1"
            h["Content-Type"] = "application/json"
        for k, v in (headers or {}).items():
            if v is None:
                h.pop(k, None)
            else:
                h[k] = v.replace("{port}", str(self.port))
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        c.request(method, path.replace("{token}", self.token), data, h)
        r = c.getresponse()
        payload = r.read()
        if r.getheader("Set-Cookie"):
            self.cookie = r.getheader("Set-Cookie").split(";")[0]
        info = {"status": r.status, "type": r.getheader("Content-Type"), "csp": r.getheader("Content-Security-Policy"),
                "nosniff": r.getheader("X-Content-Type-Options"), "frame": r.getheader("X-Frame-Options"),
                "cache": r.getheader("Cache-Control"), "location": r.getheader("Location"),
                "cookie": re.sub(r"imw_sid=[^;]+", "imw_sid=<SID>", r.getheader("Set-Cookie") or ""),
                "disposition": re.sub(r"\d{8}-\d{6}", "<STAMP>", r.getheader("Content-Disposition") or "")}
        if (r.getheader("Content-Type") or "").startswith("application/json"):
            info["json"] = json.loads(payload)
        else:
            info["bytes"] = payload
        c.close()
        return info

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(\+00:00|Z)?")
STAMP = re.compile(r"\b20\d{6}-\d{6}\b")


def normalize(value, side):
    ws = str(side.ws)
    if isinstance(value, dict):
        return {k: normalize(v, side) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v, side) for v in value]
    if isinstance(value, str):
        s = value.replace(ws, "<WS>").replace(ws.replace("\\", "\\\\"), "<WS>")
        s = TS.sub("<TS>", s)
        s = STAMP.sub("<STAMP>", s)
        s = s.replace(str(side.port), "<PORT>").replace("python -m imw ", "IMW ")
        try:                         # audit details and labels hold JSON text: compare it as data
            inner = json.loads(s)
            if isinstance(inner, (dict, list)):
                return {"<json>": normalize(inner, side)}
        except ValueError:
            pass
        return s
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def diff(a, b, path="", out=None, limit=20):
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}.{k}: only in {'python' if k in a else 'dotnet'} "
                           f"({json.dumps(a.get(k, b.get(k)))[:150]})")
            else:
                diff(a[k], b[k], f"{path}.{k}", out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: {len(a)} items in python, {len(b)} in dotnet")
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, f"{path}[{i}]", out, limit)
    elif a != b:
        out.append(f"{path}: python {json.dumps(a)[:200]} | dotnet {json.dumps(b)[:200]}")
    return out


# Messages that come straight from the regex engine or the runtime differ in wording by nature.
LOOSE_PATHS = (".json.error",)


def steps():
    """(label, method, path, body or callable(state) -> body, options)."""
    ok = {}
    S = []

    def add(label, method, path, body=None, **opt):
        S.append((label, method, path, body, opt))

    add("no cookie", "GET", "/api/state")
    add("page without session", "GET", "/")
    add("bad token", "GET", "/?t=nope")
    add("launch", "GET", "/?t={token}")
    add("token used twice", "GET", "/?t={token}", opt_keep_cookie=True)
    add("page", "GET", "/")
    add("app.js", "GET", "/app.js")
    add("theme.js", "GET", "/theme.js")
    add("other file", "GET", "/server.py")
    add("session locked", "GET", "/api/session")
    add("state while locked", "GET", "/api/state")
    add("bad host", "GET", "/api/session", headers={"Host": "evil.example:{port}"})
    add("bad origin", "POST", "/api/ping", {}, headers={"Origin": "https://evil.example"})
    add("missing header", "POST", "/api/ping", {}, headers={"X-IMW": None})
    add("wrong password", "POST", "/api/unlock", {"password": "nope"})
    add("empty password", "POST", "/api/unlock", {})
    add("unlock", "POST", "/api/unlock", {"password": PASSWORD})
    add("session open", "GET", "/api/session")
    add("unknown api", "GET", "/api/nothing")
    add("bad json", "POST", "/api/ping", raw=b"{nope")
    add("list body", "POST", "/api/ping", raw=b"[]")
    add("state empty", "GET", "/api/state")
    add("config empty", "GET", "/api/config")
    add("accounts without db", "POST", "/api/accounts", {})
    add("naming preview empty", "POST", "/api/naming/preview", {"config": {}})
    add("rules preview empty", "POST", "/api/rules/preview", {"kind": "safes", "config": {}})
    add("members preview empty", "POST", "/api/members/preview", {})
    add("config save first", "POST", "/api/config", {"patch": {"safe_prefix": "P-"}})
    add("ingest nothing", "POST", "/api/ingest", {})
    add("ingest outside inbox", "POST", "/api/ingest", {"files": [{"name": "../ws.txt"}]})
    add("ingest bad perms", "POST", "/api/ingest", {"files": [{"name": "keepass_export.xml"}], "permissions": ["nope.csv"]})
    add("ingest delinea", "POST", "/api/ingest", {"files": [{"name": "delinea_export.csv", "source": "delinea"}],
                                                  "permissions": ["delinea_permissions.csv"]})
    add("ingest more", "POST", "/api/ingest", {"files": [{"name": "keepass_export.xml"}, {"name": "accounts_inventory.csv"},
                                                         {"name": "delinea_export.xml"}, {"name": "accounts_by_group.xlsx"}]})
    add("ingest again", "POST", "/api/ingest", {"files": [{"name": "keepass_export.xml"}]})
    add("state", "GET", "/api/state")
    add("config", "GET", "/api/config")
    add("safes", "GET", "/api/safes")
    add("audit", "GET", "/api/audit")
    for view in ("all", "upload", "review", "review_open", "approved", "errors", "excluded", "renamed_safes", "no_access",
                 "no_secret", "fallback", "duplicates", "otp", "edited", "sanitized"):
        add(f"accounts {view}", "POST", "/api/accounts", {"view": view})
    add("accounts bad view", "POST", "/api/accounts", {"view": "nope"})
    add("accounts sorted", "POST", "/api/accounts", {"view": "all", "sort": "username", "desc": True})
    add("accounts bad sort", "POST", "/api/accounts", {"sort": "secret_enc; DROP", "page": "0"})
    add("accounts page 1", "POST", "/api/accounts", {"page": 1})
    add("accounts search", "POST", "/api/accounts", {"filters": {"search": "svc_"}})
    add("accounts search 2", "POST", "/api/accounts", {"filters": {"search": "corp"}})
    add("accounts filter", "POST", "/api/accounts", {"filters": {"source": "keepass", "status": "OK"}})
    add("record", "POST", "/api/record", lambda st: {"id": st["first_id"]})
    add("record missing", "POST", "/api/record", {"id": "nope"})
    add("naming preview", "POST", "/api/naming/preview", lambda st: {"config": st["config"]})
    add("naming preview bad", "POST", "/api/naming/preview", {"config": []})
    for kind in ("safes", "members", "platforms", "accounts"):
        add(f"rules preview {kind}", "POST", "/api/rules/preview", {"kind": kind, "patch": {"safe_prefix": "X-"}})
    add("rules preview limit", "POST", "/api/rules/preview", {"kind": "accounts", "patch": {}, "limit": 3})
    add("safes preview", "POST", "/api/safes/preview", {"patch": {"safe_prefix": ""}})
    add("rules preview bad kind", "POST", "/api/rules/preview", {"kind": "nope", "config": {}})
    add("rules preview bad role", "POST", "/api/rules/preview",
        {"kind": "safes", "patch": {"custom_roles": {"Viewer": ["listAccounts"]}}})
    for field in ("address_domain", "type", "platform", "column:Owner Team", "column:", "nope"):
        add(f"rules values {field}", "POST", "/api/rules/values", {"field": field})
    add("members preview", "POST", "/api/members/preview",
        {"patch": {"domain_map": [{"from": "CORP", "to": "corp.example.com", "kinds": ["users", "groups"]}]}})
    add("members preview bad", "POST", "/api/members/preview", {"patch": {"platform_rules": [{"pattern": "(", "platform": "X"}]}})
    add("config save", "POST", "/api/config", {"patch": {"safe_prefix": "", "default_platform": "WinDomain"}})
    add("config save bad group rule", "POST", "/api/config", {"patch": {"group_rules": [{"group": "x"}]}})
    add("config save bad role", "POST", "/api/config", {"patch": {"custom_roles": {"Auditors": []}}})
    add("config save bad pattern", "POST", "/api/config", {"patch": {"safe_rules": [{"safe_pattern": "[", "description": "x"}]}})
    add("config save not object", "POST", "/api/config", {"config": [1]})
    add("config save layers", "POST", "/api/config", {"patch": {"standard_members": {
        "apply_to": "no_source_members", "members": [{"name": "{safe}-Users", "role": "Full", "member_type": "Group"}]}}})
    add("config after save", "GET", "/api/config")
    add("edit bad field", "POST", "/api/edit", {"ids": ["x"], "values": {"secret": "x"}})
    add("edit bad migrate", "POST", "/api/edit", {"ids": ["x"], "values": {"migrate": "maybe"}})
    add("edit unknown id", "POST", "/api/edit", {"ids": ["nope"], "values": {"migrate": "N"}})
    add("edit exclude", "POST", "/api/edit", lambda st: {"ids": st["ids"][:2], "values": {"migrate": "N"}, "reason": "test"})
    add("edit rename", "POST", "/api/edit", lambda st: {"ids": st["ids"][2:3], "values": {"account_name": "renamed\u0007 one"}})
    add("edit rename many", "POST", "/api/edit", lambda st: {"ids": st["ids"][3:5], "values": {"account_name": "x"}})
    add("edit by view", "POST", "/api/edit", {"view": "errors", "values": {"platform_id": "UnixSSH"}})
    add("edit safe", "POST", "/api/edit", lambda st: {"ids": st["ids"][5:7], "values": {"target_safe": "My Safe*1"}})
    add("approve", "POST", "/api/approve", {"view": "review"})
    add("unapprove", "POST", "/api/approve", lambda st: {"ids": st["ids"][:10], "approve": False, "reason": "again"})
    add("approve none", "POST", "/api/approve", {"view": "approved", "filters": {"search": "zzzz-nothing"}})
    add("members change", "POST", "/api/members/change", lambda st: {"key": st["member_key"], "member_name": "Renamed-Group",
                                                                     "member_type": "group", "search_in": "CORP"})
    add("members change empty", "POST", "/api/members/change", {"key": "x", "member_name": ""})
    add("members change bad type", "POST", "/api/members/change", {"key": "x", "member_name": "y", "member_type": "robot"})
    add("members change undo", "POST", "/api/members/change", lambda st: {"key": st["member_key"], "undo": True})
    add("safes change", "POST", "/api/safes/change", lambda st: {"key": st["safe"], "settings": {
        "new_name": "Renamed Safe", "description": "desc\u200b here", "retention_kind": "days", "retention_value": "30",
        "olacEnabled": "true"}, "reason": "r"})
    add("safes change bad retention", "POST", "/api/safes/change", lambda st: {"key": st["safe"], "settings": {
        "retention_kind": "versions", "retention_value": "1000"}})
    add("safes change long cpm", "POST", "/api/safes/change", lambda st: {"key": st["safe"], "settings": {
        "managingCPM": "C" * 21}})
    add("members edit add", "POST", "/api/members/edit", lambda st: {"action": "add", "safes": [st["safe2"]],
                                                                     "member_name": "NewAdmins", "role": "Full",
                                                                     "member_type": "Group", "search_in": "Vault"})
    add("members edit bad role", "POST", "/api/members/edit", lambda st: {"action": "add", "safes": [st["safe2"]],
                                                                          "member_name": "X", "role": "nope"})
    add("members edit remove", "POST", "/api/members/edit", lambda st: {"action": "remove", "pairs": [[st["safe2"], "NewAdmins"]]})
    add("members edit none", "POST", "/api/members/edit", {"action": "add", "safes": []})
    add("safes after changes", "GET", "/api/safes")
    add("state after changes", "GET", "/api/state")
    add("extract", "POST", "/api/extract", {"name": "wave 1"})
    add("extract exists", "POST", "/api/extract", {"name": "wave 1"})
    add("extract replace filtered", "POST", "/api/extract", {"name": "wave 1", "replace": True, "scope": "filter",
                                                            "view": "upload", "filters": {"source": "delinea"}})
    add("extract secrets unconfirmed", "POST", "/api/extract", {"name": "wave 2", "include_secrets": True})
    add("extract secrets", "POST", "/api/extract", {"name": "wave/../2!", "include_secrets": True, "confirm": "INCLUDE SECRETS"})
    add("state with outputs", "GET", "/api/state")
    add("export audit", "GET", "/api/export/audit.csv")
    add("export edits", "GET", "/api/export/edits.csv")
    add("export convention", "GET", "/api/export/convention.csv")
    add("export other", "GET", "/api/export/secrets.csv")
    add("open folder", "POST", "/api/open", {"which": "output", "name": "wave 1"})
    add("open folder bad", "POST", "/api/open", {"which": "c:"})
    add("output delete upload", "POST", "/api/output/delete", {"name": "wave2"})
    add("output delete bad", "POST", "/api/output/delete", {"name": "../inbox"})
    add("output delete all", "POST", "/api/output/delete", {"name": "wave 1", "what": "all"})
    add("inbox delete", "POST", "/api/inbox/delete", {"name": "accounts_by_group.xlsx"})
    add("inbox delete missing", "POST", "/api/inbox/delete", {"name": "nope.csv"})
    add("audit end", "GET", "/api/audit")
    add("lock", "POST", "/api/lock", {})
    add("locked state", "GET", "/api/state")
    add("locked export", "GET", "/api/export/audit.csv")
    add("unlock again", "POST", "/api/unlock", {"password": PASSWORD})
    add("end unconfirmed", "POST", "/api/end", {})
    add("end delete unconfirmed", "POST", "/api/end", {"delete_db": True, "confirm": "END SESSION"})
    add("end", "POST", "/api/end", {"delete_db": True, "confirm": "DELETE DB"})
    add("after end", "GET", "/api/state")
    return S


def learn(label, info, st):
    """Values later steps need, taken from the Python side's answers."""
    j = info.get("json")
    if label == "accounts all" and j:
        st["ids"] = [r["record_id"] for r in j["rows"]]
        st["first_id"] = st["ids"][0]
    if label == "config" and j:
        st["config"] = j["config"]
    if label == "safes" and j:
        safes = [s["safe_name"] for s in j["safes"]]
        st["safe"], st["safe2"] = safes[0], safes[-1]
        people = [p for p in j["people"] if p["safes"]]
        st["member_key"] = people[0]["key"] if people else "x"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--imw", default=str(ROOT / "dotnet/src/Imw/bin/Debug/net10.0/IMW.dll"))
    ap.add_argument("--keep", action="store_true", help="Keep the work folder")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    imw = Path(args.imw)
    dotnet_cmd = ["dotnet", str(imw)] if imw.suffix == ".dll" else [str(imw)]
    work = Path(tempfile.mkdtemp(prefix="imw-ui-parity-")).resolve()
    py = net = None
    failures = 0
    try:
        py = Side("python", [sys.executable, "-m", "imw"], work / "py" / "ws")
        net = Side("dotnet", dotnet_cmd, work / "net" / "ws")
        start_py = [normalize(x, py) for x in py.lines]
        start_net = [normalize(x, net) for x in net.lines]
        start_py = [re.sub(r"SHA-256 \S+|t=\S+", "<X>", x) for x in start_py]
        start_net = [re.sub(r"SHA-256 \S+|t=\S+", "<X>", x) for x in start_net]
        if start_py != start_net:
            failures += 1
            print("start-up text differs:\n  python " + "\n  python ".join(start_py) + "\n  dotnet " + "\n  dotnet ".join(start_net))
        state = {}
        for label, method, path, body, opt in steps():
            if callable(body):
                body = body(state)
            results = []
            for side in (py, net):
                if label == "no cookie" or label == "bad token":
                    side.cookie = None
                info = side.req(method, path, body, opt.get("headers"), opt.get("raw"))
                if label in ("launch",) and info["status"] == 303:
                    pass
                results.append(info)
            learn(label, results[0], state)
            a, b = (dict(r) for r in results)
            for r, side in ((a, py), (b, net)):
                if "bytes" in r:
                    r["bytes"] = normalize(r["bytes"].decode("utf-8", "replace"), side)
                if "json" in r:
                    r["json"] = normalize(r["json"], side)
            problems = [p for p in diff(a, b) if not (p.startswith(LOOSE_PATHS) and a["status"] == b["status"] == 400
                                                     and "pattern" in json.dumps(a.get("json")))]
            if problems:
                failures += 1
                print(f"DIFF {label}: {method} {path}")
                for p in problems:
                    print("    " + p)
            elif args.verbose:
                print(f"ok   {label}: {a['status']}")
        time.sleep(1.5)
        for side in (py, net):
            code = side.proc.poll()
            if code is None:
                failures += 1
                print(f"{side.name} still running after End session")
        print(f"{failures} difference(s)")
        return 1 if failures else 0
    finally:
        for side in (py, net):
            if side:
                side.stop()
        if args.keep:
            print(f"work folder: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
