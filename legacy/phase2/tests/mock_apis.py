#!/usr/bin/env python3
"""
Mock of the CyberArk Identity token + Privilege Cloud REST API and the Delinea
Secret Server token + secret field API, for testing Phase 2 without a tenant.

  python tests/mock_apis.py 8765

CyberArk:  http://127.0.0.1:8765/oauth2/platformtoken, /PasswordVault/API/...
Delinea:   http://127.0.0.1:8765/SecretServer/oauth2/token, /SecretServer/api/v1/secrets/{id}/fields/{slug}

Test behaviours:
  - Both sides return 429 when called faster than STATE["limits"] per second (POST /_control to change).
  - Account addresses containing "reject" -> CyberArk 400.
  - Account addresses containing "flaky" -> created, but the response is a 500 (lost response).
  - Delinea secret IDs listed in DENY -> 403. Toggle with POST /_control {"deny": [...]}.
  - Secrets are kept only to check that the right value arrived (GET /_state hides them).
"""
import json
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"token_ttl": 900, "tokens": {}, "refresh_tokens": {}, "token_grants": [], "limits": {"cyberark": 50, "delinea": 20}, "safes": {}, "members": {}, "accounts": [], "deny": [106], "hits": {"cyberark": [], "delinea": []},
         "throttled": {"cyberark": 0, "delinea": 0}, "secret_reads": 0}
PLATFORMS = ["WinDomain", "WinServerLocal", "UnixSSH", "UnixSSHKeys", "MSSql", "GenericWebApp"]
SECRETS = {101: "P@ssw0rd!1", 102: "Bkp#2024x", 103: "R00t!web01", 104: "0ra#Cl3",
           105: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----\n",
           106: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
           107: "V3nd0r!", 108: "Fw@dm1n", 109: "Fl4ky!svc"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=None, headers=None, raw=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if raw is not None:
            self.wfile.write(raw.encode())
        elif body is not None:
            self.wfile.write(json.dumps(body).encode())

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n).decode() if n else ""

    def _limited(self, side):
        now = time.time()
        hits = [t for t in STATE["hits"][side] if now - t < 1.0]
        STATE["hits"][side] = hits + [now]
        if len(hits) >= STATE["limits"][side]:
            STATE["throttled"][side] += 1
            self._send(429, {"ErrorMessage": "Too many requests"}, {"Retry-After": "1"})
            return True
        return False

    def _issue(self, side, refresh=False):
        n = len(STATE["token_grants"]) + 1
        tok = f"{side}-token-{n}"
        STATE["tokens"][tok] = time.time() + STATE["token_ttl"]
        STATE["token_grants"].append(side + (":refresh" if refresh else ":login"))
        body = {"access_token": tok, "token_type": "Bearer", "expires_in": STATE["token_ttl"]}
        if side == "dl":  # Delinea issues refresh tokens; CyberArk client_credentials does not
            rt = f"dl-refresh-{n}"
            STATE["refresh_tokens"][rt] = True
            body["refresh_token"] = rt
        return body

    def _authed(self, token):
        got = (self.headers.get("Authorization") or "")[7:]
        if not got.startswith(token) or STATE["tokens"].get(got, 0) < time.time():
            self._send(401, {"ErrorCode": "PASWS006E", "ErrorMessage": "unauthorized"})
            return False
        return True

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/_control":
            STATE.update(json.loads(self._body()))
            return self._send(200, {"ok": True})
        side = "delinea" if u.path.startswith("/SecretServer") else "cyberark"
        if self._limited(side):
            return
        if u.path == "/oauth2/platformtoken":
            form = urllib.parse.parse_qs(self._body())
            if form.get("client_secret") == ["test-secret"]:
                return self._send(200, self._issue("ca"))
            return self._send(401, {"error": "invalid_client"})
        if u.path in ("/CDirectoryService/GetDirectoryServices", "/UserMgmt/DirectoryServiceQuery"):
            if not self._authed("ca-token"):
                return
            if u.path.startswith("/CDirectory"):
                return self._send(200, {"success": True, "Result": {"Results": [
                    {"Row": {"DisplayName": "corp.example.com", "directoryServiceUuid": "uuid-ad"}},
                    {"Row": {"DisplayName": "CyberArk Cloud Directory", "directoryServiceUuid": "uuid-cd"}}]}})
            q = json.loads(self._body() or "{}")
            want = json.loads(q.get("group", "{}"))["_or"][0]["DisplayName"]["_like"]
            rows = [] if want.lower().startswith("ghost") else [{"Row": {"DisplayName": want, "SystemName": want + "@corp.example.com"}}]
            return self._send(200, {"success": True, "Result": {"Group": {"Results": rows}}})
        if u.path == "/SecretServer/oauth2/token":
            form = urllib.parse.parse_qs(self._body())
            if form.get("grant_type") == ["refresh_token"]:
                if STATE["refresh_tokens"].pop(form.get("refresh_token", [""])[0], None):
                    return self._send(200, self._issue("dl", refresh=True))
                return self._send(400, {"error": "invalid_grant"})
            if form.get("password") == ["delinea-test"]:
                return self._send(200, self._issue("dl"))
            return self._send(400, {"error": "invalid_grant"})
        if not self._authed("ca-token"):
            return
        parts = u.path.split("/")[3:]
        body = json.loads(self._body() or "{}")
        if parts == ["Safes"]:
            name = body["safeName"]
            if name.lower() in STATE["safes"]:
                return self._send(409, {"ErrorCode": "SFWS0002E", "ErrorMessage": "Safe already exists"})
            STATE["safes"][name.lower()] = dict(body, safeUrlId=name)
            STATE["members"][name.lower()] = []
            return self._send(201, {"safeName": name, "safeUrlId": name})
        if len(parts) == 3 and parts[0] == "Safes" and parts[2] == "Members":
            safe = urllib.parse.unquote(parts[1]).lower()
            if body.get("memberName", "").lower().startswith("ghost"):
                return self._send(404, {"ErrorCode": "SFWS0016E", "ErrorMessage": "Member does not exist in directory"})
            STATE["members"].setdefault(safe, []).append(body)
            return self._send(201, body)
        if parts == ["Accounts"]:
            if "reject" in body.get("address", ""):
                return self._send(400, {"ErrorCode": "PASWS027E", "ErrorMessage": "Mock rejection of account data"})
            acct = dict(body, id=f"{len(STATE['accounts']) + 1}_3")
            STATE["accounts"].append(acct)
            if "flaky" in body.get("address", "") and not acct.get("_flaked"):
                acct["_flaked"] = True
                return self._send(500, {"ErrorMessage": "Internal error (response lost)"})
            return self._send(201, {k: v for k, v in acct.items() if k != "secret"})
        self._send(404, {"ErrorMessage": "not found"})

    def do_DELETE(self):
        if self._limited("cyberark") or not self._authed("ca-token"):
            return
        parts = urllib.parse.urlparse(self.path).path.split("/")[3:]
        if len(parts) == 2 and parts[0] == "Accounts":
            before = len(STATE["accounts"])
            STATE["accounts"] = [a for a in STATE["accounts"] if a["id"] != urllib.parse.unquote(parts[1])]
            return self._send(204 if len(STATE["accounts"]) < before else 404)
        if len(parts) == 2 and parts[0] == "Safes":
            safe = urllib.parse.unquote(parts[1]).lower()
            if any(a["safeName"].lower() == safe for a in STATE["accounts"]):
                return self._send(409, {"ErrorMessage": "Safe contains accounts"})
            STATE["safes"].pop(safe, None)
            STATE["members"].pop(safe, None)
            return self._send(204)
        self._send(404, {"ErrorMessage": "not found"})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/_received_secrets":  # test-only: name -> secret that arrived
            return self._send(200, {a["name"]: a["secret"] for a in STATE["accounts"]})
        if u.path == "/_state":
            view = dict(STATE, accounts=[{k: v for k, v in a.items() if k != "secret"} for a in STATE["accounts"]])
            view.pop("hits")
            return self._send(200, view)
        side = "delinea" if u.path.startswith("/SecretServer") else "cyberark"
        if self._limited(side):
            return
        q = urllib.parse.parse_qs(u.query)
        if side == "delinea":
            if not self._authed("dl-token"):
                return
            parts = u.path.split("/")  # /SecretServer/api/v1/secrets/{id}/fields/{slug}
            sid = int(parts[5])
            if sid in STATE["deny"]:
                return self._send(403, {"message": "Access Denied: user does not have View permission on this secret"})
            if sid >= 900000:
                return self._send(404, {"message": "Secret not found"})
            STATE["secret_reads"] += 1
            # Unknown IDs (synthetic data) get a deterministic synthetic value.
            return self._send(200, raw=json.dumps(SECRETS.get(sid, f"Synth!{sid}")))
        if not self._authed("ca-token"):
            return
        parts = u.path.split("/")[3:]
        if parts == ["Platforms", "targets"]:
            return self._send(200, {"Total": len(PLATFORMS), "Platforms": [{"PlatformID": p} for p in PLATFORMS]})
        if len(parts) == 2 and parts[0] == "Safes":
            safe = urllib.parse.unquote(parts[1]).lower()
            if safe in STATE["safes"]:
                return self._send(200, STATE["safes"][safe])
            return self._send(404, {"ErrorCode": "SFWS0007E", "ErrorMessage": "Safe not found"})
        if len(parts) == 3 and parts[2] == "Members":
            safe = urllib.parse.unquote(parts[1]).lower()
            return self._send(200, {"value": STATE["members"].get(safe, [])})
        if parts == ["Accounts"]:
            flt = q.get("filter", [""])[0]
            safe = flt.split("eq", 1)[1].strip().lower() if "eq" in flt else ""
            vals = [{k: v for k, v in a.items() if k != "secret"} for a in STATE["accounts"]
                    if a["safeName"].lower() == safe]
            return self._send(200, {"value": vals, "count": len(vals)})
        self._send(404, {"ErrorMessage": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
