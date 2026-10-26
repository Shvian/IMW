#!/usr/bin/env python3
"""
Delinea Secret Server -> CyberArk Privilege Cloud migration
PHASE 2: Online API Execution (fetches each secret only when it is sent)

Reads the reviewed Phase 1 files, which hold NO secret values, and for each
account fetches the secret from the Delinea REST API, sends it straight to
CyberArk, and drops it. Secrets live only in process memory for one request
and are never written to disk, logs or the state ledger.

Fixed order of operations:
  1. Create Safes            POST /PasswordVault/API/Safes
  2. Add Safe Members        POST /PasswordVault/API/Safes/{safe}/Members
  3. Onboard Accounts        GET  Delinea /api/v1/secrets/{id}/fields/{slug}
                             POST /PasswordVault/API/Accounts

Audit, resume and no duplicates:
  - State ledger (SQLite, no secrets) records every Safe, member and account
    with its status, attempts, CyberArk id, last error and a fix-it hint.
  - Audit log (JSON Lines, append-only, SHA-256 hash-chained) records every
    action and outcome with operator, host and run id. `verify-audit` checks
    the chain for tampering or truncation.
  - Re-running skips anything already DONE in the ledger. Anything not DONE is
    checked against CyberArk before it is created, and create calls are never
    blindly retried after an ambiguous failure (timeout/5xx): the script checks
    whether the object was created first. So a crash or re-run cannot create
    a duplicate.

Commands:
  plan          validate inputs, compare with the ledger, show what a run would do (no changes)
  run           execute (use --only-failed to retry just the failures)
  status        summary of the ledger, with every failure, its error and a hint
  report        export the ledger to CSV for sign-off
  verify-audit  verify the audit log hash chain
  preflight     read-only checks against the real CyberArk tenant (auth, platforms,
                directories, groups, existing Safe names); no changes
  probe-delinea migration day: read one secret per template/field to prove API access
                and field slugs; prints only success and length, never the value
  run --rehearsal-prefix ZZTEST-
                full flow against the real CyberArk tenant with FAKE secrets, in
                prefixed test Safes, with its own state dir; no Delinea access needed
  cleanup-rehearsal
                delete the accounts and Safes a rehearsal created (only those)

Standard library only (Python 3.8+).
"""

import argparse
import csv
import getpass
import hashlib
import json
import logging
import os
import signal
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import secrets as pysecrets
import shutil
import string
import subprocess
import tempfile
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("phase2")

ALL_PERMISSIONS = [
    "useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
    "updateAccountContent", "updateAccountProperties",
    "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
    "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe",
    "manageSafeMembers", "backupSafe", "viewAuditLog", "viewSafeMembers",
    "accessWithoutConfirmation", "createFolders", "deleteFolders",
    "moveAccountsAndFolders", "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
]


def _perms(*granted):
    return {p: p in granted for p in ALL_PERMISSIONS}


DEFAULT_CONFIG = {
    "cyberark": {
        # https://<identity-tenant-id>.id.cyberark.cloud/oauth2/platformtoken
        "token_url": "https://EXAMPLE.id.cyberark.cloud/oauth2/platformtoken",
        # https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API
        "api_base_url": "https://EXAMPLE.privilegecloud.cyberark.cloud/PasswordVault/API",
        # Service user (OAuth confidential client), e.g. "migration-svc@cyberark.cloud.12345"
        "client_id": "",
        "client_secret_env": "CYBERARK_CLIENT_SECRET",
        # Client-side limits for all calls to CyberArk (token, reads, creates).
        # requests_per_minute paces calls evenly; the window cap is a hard ceiling.
        "requests_per_minute": 950,
        "max_calls_per_window": 4900,
        "window_seconds": 300,
    },
    "delinea": {
        # Secret Server base URL, e.g. https://ss.example.com/SecretServer or https://tenant.secretservercloud.com
        "base_url": "https://EXAMPLE/SecretServer",
        # Default: <base_url>/oauth2/token. For Delinea Platform use its token URL and client_credentials.
        "token_url": "",
        # "password" (Secret Server local API user) or "client_credentials" (Delinea Platform)
        "grant_type": "password",
        "username": "",
        "password_env": "DELINEA_PASSWORD",
        "client_id": "",
        "client_secret_env": "DELINEA_CLIENT_SECRET",
        # Extra query parameters for the field call, if your secrets need them
        # (e.g. auto-checkout/comment). Verify the names against your Secret Server version.
        "field_query": {},
        # Client-side limits for all calls to Delinea, same meaning as for CyberArk.
        "requests_per_minute": 950,
        "max_calls_per_window": 4900,
        "window_seconds": 300,
    },
    "verify_tls": True,
    "request_timeout_seconds": 60,
    "max_retries": 6,
    # On HTTP 429 the client halves its rate (down to min_rate_fraction of the configured limit)
    # and creeps back up after rate_recovery_seconds without another 429.
    "min_rate_fraction": 0.1,
    "rate_recovery_seconds": 120,
    "safe_defaults": {
        "description": "Migrated from Delinea Secret Server",
        "managingCPM": "",
        "numberOfDaysRetention": 7,
        "olacEnabled": False,
    },
    # Delinea "DOMAIN\\Group" -> CyberArk memberName + searchIn directory.
    "directory_map": {"CORP": "corp.example.com", "*": "Vault"},
    "strip_domain_prefix": True,
    "role_permissions": {
        "Owner": _perms(*[p for p in ALL_PERMISSIONS if not p.startswith("requestsAuthorization")]),
        "Editor": _perms("useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
                         "updateAccountContent", "updateAccountProperties",
                         "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
                         "renameAccounts", "unlockAccounts", "viewAuditLog", "viewSafeMembers",
                         "accessWithoutConfirmation", "createFolders", "deleteFolders",
                         "moveAccountsAndFolders"),
        "User": _perms("useAccounts", "retrieveAccounts", "listAccounts", "viewAuditLog",
                       "accessWithoutConfirmation"),
        "Viewer": _perms("listAccounts"),
    },
    "account_defaults": {
        "automaticManagementEnabled": False,
        "manualManagementReason": "Migrated from Delinea - CPM management pending cutover",
    },
    # Delinea column in Migration_Review.csv -> CyberArk platformAccountProperties key
    "account_property_map": {},
    "safe_name_max_length": 28,
    "safe_name_invalid_chars": "\\/:*?\"<>|",
}

NO_MERGE = ("directory_map", "role_permissions", "account_property_map")
SECRET_TYPES = {"password", "key"}
EXIT_OK, EXIT_ERROR, EXIT_INVALID, EXIT_FAILURES = 0, 1, 2, 3


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    with open(path, encoding="utf-8") as fh:
        user = json.load(fh)
    for k, v in user.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(cfg.get(k), dict) and k not in NO_MERGE:
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def write_default_config(path):
    out = OrderedDict([("_comment", "Phase 2 config. Credentials are read from the env vars named "
                                    "*_env (or prompted for); never put them in this file.")])
    out.update(DEFAULT_CONFIG)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"Wrote default config to {path}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Errors and fix-it hints
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, system, status, message, body=None, ambiguous=False):
        super().__init__(f"{system} HTTP {status}: {message}")
        self.system = system
        self.status = status
        self.message = str(message)[:500]
        self.body = body if isinstance(body, dict) else {}
        # True when the request may have been applied (timeout, connection drop, 5xx on a create).
        self.ambiguous = ambiguous

    @property
    def code(self):
        return str(self.body.get("ErrorCode") or self.body.get("errorCode") or "")


def hint_for(err, stage):
    """A plain-language next step for an error."""
    s, m = err.status, err.message.lower()
    if err.system == "PRECHECK":
        return "Fix this row in the reviewed CSV (or the tenant), then run --only-failed."
    if err.system == "SCRIPT":
        return "Unexpected script error; send the run log to the migration engineer. Nothing was created for this object."
    if err.system == "DELINEA":
        if s == 401:
            return "Delinea rejected the API credentials. Check delinea.username / password env var or client credentials."
        if s == 403:
            return ("The Delinea API account cannot view this secret. Grant it View on the folder "
                    "or secret (or exempt it from approval/checkout), then run --only-failed.")
        if s == 404:
            return ("Secret ID or field slug not found in Delinea. Check 'Delinea Secret ID' and "
                    "'Delinea Secret Field' (template field slug) in Migration_Review.csv.")
        if any(w in m for w in ("comment", "checkout", "check out", "approval", "doublelock", "double lock")):
            return ("The secret needs a comment, checkout, approval or DoubleLock. Exempt the migration "
                    "API account, or set delinea.field_query, then run --only-failed.")
        if s == 429:
            return ("Still rate-limited by Delinea after all retries. Lower delinea.requests_per_minute "
                    "and run --only-failed.")
        if s == 0:
            return "Cannot reach Delinea. Check delinea.base_url, DNS, proxy and firewall from this host."
        return "Delinea returned an error. Check the message, fix the cause and run --only-failed."
    if s == 401:
        return "CyberArk rejected the token. Check cyberark.client_id / client secret and the token URL."
    if s == 403:
        return ("The CyberArk service user lacks rights. It needs Privilege Cloud Administrator, or "
                "Manage Safe / Manage Safe Members / Add Accounts on this Safe.")
    if stage == "MEMBER" and (s == 404 or "not found" in m or "doesn't exist" in m or "does not exist" in m):
        return ("Group not found in the directory. Check directory_map (searchIn) and that the group "
                "is synced to CyberArk Identity, then run --only-failed.")
    if "platform" in m:
        return "The platform ID is not active in the tenant. Activate it, or fix 'Target Platform ID', then run --only-failed."
    if s == 429:
        return ("Still rate-limited after all retries. Lower cyberark.requests_per_minute and "
                "run --only-failed.")
    if s >= 500:
        return "CyberArk service error. Wait and run --only-failed; the script checks for partial creates first."
    if s == 0:
        return "Cannot reach CyberArk. Check the API URL, DNS, proxy and firewall from this host."
    if s == 400:
        return "CyberArk rejected the request data. Fix the row in Migration_Review.csv and run --only-failed."
    return "Check the message, fix the cause and run --only-failed."


# --------------------------------------------------------------------------- #
# HTTP clients
# --------------------------------------------------------------------------- #
class RateLimiter:
    """
    Spaces requests to at most `per_minute`, per system. Adaptive: a 429 halves
    the rate (floor: min_fraction of the limit); each quiet recovery period
    without a 429 doubles it back toward the limit.
    """

    def __init__(self, system, per_minute, min_fraction=0.1, recovery_seconds=120,
                 window_cap=None, window_seconds=300):
        self.system = system
        self.window_cap = int(window_cap) if window_cap else None
        self.window_seconds = window_seconds
        self.calls = deque()
        self.peak = 0
        self.limit = max(float(per_minute), 1.0)
        self.rate = self.limit
        self.floor = self.limit * min_fraction
        self.recovery = recovery_seconds
        self.next_at = 0.0
        self.last_429 = 0.0
        self.waited = 0.0
        self.throttled = 0

    def wait(self):
        now = time.monotonic()
        if self.rate < self.limit and self.last_429 and now - self.last_429 > self.recovery:
            self.rate = min(self.limit, self.rate * 2)
            self.last_429 = now
            log.info("%s rate restored to %.0f/min", self.system, self.rate)
        if now < self.next_at:
            pause = self.next_at - now
            self.waited += pause
            time.sleep(pause)
            now = self.next_at
        if self.window_cap:
            # Hard ceiling: never more than window_cap calls in any window_seconds.
            while self.calls and now - self.calls[0] >= self.window_seconds:
                self.calls.popleft()
            if len(self.calls) >= self.window_cap:
                pause = self.window_seconds - (now - self.calls[0]) + 0.01
                log.warning("%s window cap reached (%d calls / %ss): pausing %.1fs", self.system,
                            self.window_cap, self.window_seconds, pause)
                self.waited += pause
                time.sleep(pause)
                now = time.monotonic()
                while self.calls and now - self.calls[0] >= self.window_seconds:
                    self.calls.popleft()
            self.calls.append(now)
            self.peak = max(self.peak, len(self.calls))
        self.next_at = now + 60.0 / self.rate

    def backoff(self, retry_after=None):
        self.throttled += 1
        self.last_429 = time.monotonic()
        new = max(self.floor, self.rate / 2)
        if new < self.rate:
            log.warning("%s returned 429: slowing to %.0f/min", self.system, new)
        self.rate = new
        if retry_after:
            self.next_at = max(self.next_at, time.monotonic() + retry_after)


class HttpClient:
    SYSTEM = "HTTP"
    RATE_KEY = None

    def __init__(self, cfg):
        self.cfg = cfg
        self.timeout = cfg["request_timeout_seconds"]
        self.token = None
        self.token_expiry = 0
        self.refresh_token = None
        self.token_url = None
        self.renewals = {"refresh_token": 0, "reauthenticate": 0, "refresh_failed": 0}
        self.ssl_ctx = None
        rl = cfg[self.RATE_KEY]
        self.limiter = RateLimiter(self.SYSTEM, rl["requests_per_minute"], cfg["min_rate_fraction"],
                                   cfg["rate_recovery_seconds"], rl.get("max_calls_per_window"),
                                   rl.get("window_seconds", 300))
        if not cfg["verify_tls"]:
            import ssl
            log.warning("TLS verification is OFF. Use only against a test mock.")
            self.ssl_ctx = ssl._create_unverified_context()

    def authenticate(self):
        raise NotImplementedError

    def refresh_form(self):
        """Form for an OAuth2 refresh_token grant; subclasses add client fields if needed."""
        return {"grant_type": "refresh_token", "refresh_token": self.refresh_token}

    def renew(self):
        """
        Keep the session alive for long runs. Uses the refresh token when the
        server issued one; otherwise (or if the refresh is refused, e.g. the
        refresh token itself expired) signs in again with the stored credential.
        """
        if self.refresh_token and self.token_url:
            try:
                self._post_form(self.token_url, self.refresh_form(), purpose="refresh")
                self.renewals["refresh_token"] += 1
                return
            except ApiError as e:
                self.renewals["refresh_failed"] += 1
                log.warning("%s refresh token refused (%s); signing in again", self.SYSTEM, e)
                self.refresh_token = None
        self.authenticate()
        if self.renewals.get("_initial_done"):
            self.renewals["reauthenticate"] += 1
        self.renewals["_initial_done"] = 1

    def _post_form(self, url, form, purpose="sign-in"):
        data = urllib.parse.urlencode(form).encode()
        retries = self.cfg["max_retries"]
        for attempt in range(1, retries + 1):
            self.limiter.wait()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                    body = json.loads(resp.read().decode() or "{}")
                break
            except urllib.error.HTTPError as e:
                if (e.code == 429 or e.code >= 500) and attempt < retries:
                    if e.code == 429:
                        self.limiter.backoff(min(2 ** attempt, 60))
                    else:
                        time.sleep(min(2 ** attempt, 60))
                    log.warning("%s token endpoint HTTP %s, retry %d/%d", self.SYSTEM, e.code, attempt, retries)
                    continue
                raise ApiError(self.SYSTEM, e.code, f"{purpose} failed") from None
            except (urllib.error.URLError, OSError) as e:
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 60))
                    continue
                raise ApiError(self.SYSTEM, 0, f"cannot reach token URL: {getattr(e, 'reason', e)}") from None
        token = body.get("access_token")
        if not token:
            raise ApiError(self.SYSTEM, 0, f"no access_token in {purpose} response")
        self.token = token
        self.token_url = url
        if body.get("refresh_token"):
            self.refresh_token = body["refresh_token"]
        ttl = int(body.get("expires_in", 900))
        # Renew early: 60s before expiry, or at 80% of the lifetime for short-lived tokens.
        self.token_expiry = time.time() + ttl - min(60, ttl * 0.2)
        log.info("%s %s OK (token valid %ss, refresh token %s)", self.SYSTEM, purpose, ttl,
                 "issued" if self.refresh_token else "not issued")

    def request(self, method, url, body=None, query=None, idempotent=True, raw=False):
        """
        Retries 429 always (the request was refused, so nothing was applied).
        Retries 5xx and network errors only for idempotent calls; for a create
        it raises an ambiguous ApiError so the caller checks before retrying.
        """
        if query:
            url += "?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
        data = json.dumps(body).encode() if body is not None else None
        refreshed = False
        retries = self.cfg["max_retries"]
        for attempt in range(1, retries + 1):
            if not self.token or time.time() >= self.token_expiry:
                self.renew()
            self.limiter.wait()
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                    content = resp.read().decode()
                    if raw:
                        return resp.status, content
                    return resp.status, json.loads(content) if content.strip() else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                try:
                    err = json.loads(text) if text.strip() else {}
                except ValueError:
                    err = {"message": text[:300]}
                if not isinstance(err, dict):
                    err = {"message": str(err)[:300]}
                msg = (err.get("ErrorMessage") or err.get("message") or err.get("Message")
                       or err.get("Details") or e.reason or "")
                if e.code == 401 and not refreshed:
                    log.info("%s 401 (token revoked or expired early), renewing", self.SYSTEM)
                    self.token, refreshed = None, True
                    continue
                if e.code == 429 or (e.code >= 500 and idempotent):
                    if attempt < retries:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        ra = int(ra) if ra and ra.isdigit() else None
                        if e.code == 429:
                            self.limiter.backoff(ra or min(2 ** attempt, 60))
                            log.warning("%s %s -> HTTP 429, retry %d/%d", self.SYSTEM, method, attempt, retries)
                        else:
                            wait = ra or min(2 ** attempt, 60)
                            log.warning("%s %s -> HTTP %s, retry %d/%d in %ss", self.SYSTEM, method,
                                        e.code, attempt, retries, wait)
                            time.sleep(wait)
                        continue
                raise ApiError(self.SYSTEM, e.code, msg, err, ambiguous=(e.code >= 500 and not idempotent)) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as e:
                reason = getattr(e, "reason", e)
                if not idempotent:
                    raise ApiError(self.SYSTEM, 0, f"network error during create: {reason}", ambiguous=True) from None
                if attempt < retries:
                    wait = min(2 ** attempt, 60)
                    log.warning("%s %s -> %s, retry %d/%d in %ss", self.SYSTEM, method, reason,
                                attempt, retries, wait)
                    time.sleep(wait)
                    continue
                raise ApiError(self.SYSTEM, 0, f"network error: {reason}") from None
        raise ApiError(self.SYSTEM, 0, f"gave up after {retries} attempts")


class DelineaClient(HttpClient):
    SYSTEM = "DELINEA"
    RATE_KEY = "delinea"

    def __init__(self, cfg, credential):
        super().__init__(cfg)
        self.d = cfg["delinea"]
        self.base = self.d["base_url"].rstrip("/")
        self.credential = credential

    def authenticate(self):
        url = self.d.get("token_url") or self.base + "/oauth2/token"
        if self.d["grant_type"] == "client_credentials":
            form = {"grant_type": "client_credentials", "client_id": self.d["client_id"],
                    "client_secret": self.credential}
            if self.d.get("scope"):
                form["scope"] = self.d["scope"]
        else:
            form = {"grant_type": "password", "username": self.d["username"], "password": self.credential}
        self._post_form(url, form)

    def refresh_form(self):
        form = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}
        if self.d["grant_type"] == "client_credentials":
            form["client_id"] = self.d["client_id"]
        return form

    def get_secret_field(self, secret_id, slug):
        """Returns the field value as a str. Held only by the caller, for one request."""
        url = f"{self.base}/api/v1/secrets/{int(secret_id)}/fields/{urllib.parse.quote(slug, safe='')}"
        _, content = self.request("GET", url, query=self.d.get("field_query") or None, raw=True)
        # Text fields come back JSON-encoded ("value"); file fields come back raw.
        if content.startswith('"'):
            try:
                return json.loads(content)
            except ValueError:
                pass
        return content


class CyberArkClient(HttpClient):
    SYSTEM = "CYBERARK"
    RATE_KEY = "cyberark"

    def __init__(self, cfg, credential):
        super().__init__(cfg)
        self.c = cfg["cyberark"]
        self.base = self.c["api_base_url"].rstrip("/")
        self.credential = credential

    def refresh_form(self):
        return {"grant_type": "refresh_token", "refresh_token": self.refresh_token, "client_id": self.c["client_id"]}

    def authenticate(self):
        self._post_form(self.c["token_url"], {"grant_type": "client_credentials",
                                              "client_id": self.c["client_id"],
                                              "client_secret": self.credential})

    @staticmethod
    def _sid(name):
        return urllib.parse.quote(name, safe="")

    def get_safe(self, name):
        try:
            return self.request("GET", f"{self.base}/Safes/{self._sid(name)}")[1]
        except ApiError as e:
            if e.status == 404:
                return None
            raise

    def create_safe(self, name, defaults):
        return self.request("POST", f"{self.base}/Safes", {"safeName": name, **defaults}, idempotent=False)[1]

    def member_names(self, safe):
        _, body = self.request("GET", f"{self.base}/Safes/{self._sid(safe)}/Members", query={"limit": 1000})
        return {m.get("memberName", "").lower() for m in body.get("value", [])}

    def add_member(self, safe, member, search_in, permissions):
        body = {"memberName": member, "searchIn": search_in, "memberType": "Group", "permissions": permissions}
        return self.request("POST", f"{self.base}/Safes/{self._sid(safe)}/Members", body, idempotent=False)[1]

    def find_account(self, safe, username, address, name, secret_type=None, claimed=()):
        """The account this row already created, or a pre-existing equivalent to adopt.

        An exact name match wins. A username+address match counts only when it has the same
        secret type and no other Delinea secret in the ledger already owns it, so a password
        and an SSH key for root@host, or two secrets for the same login, stay separate accounts.
        """
        query = {"search": " ".join(x for x in (username, address) if x),
                 "filter": f"safeName eq {safe}", "limit": 1000}
        _, body = self.request("GET", f"{self.base}/Accounts", query=query)
        values = body.get("value", [])
        for a in values:
            if name and a.get("name", "").lower() == name.lower():
                return a
        for a in values:
            if a.get("id") in claimed:
                continue
            if secret_type and str(a.get("secretType") or secret_type).lower() != secret_type:
                continue
            if (a.get("userName", "").lower() == username.lower()
                    and a.get("address", "").lower() == (address or "").lower()):
                return a
        return None

    def add_account(self, body):
        return self.request("POST", f"{self.base}/Accounts", body, idempotent=False)[1]

    def accounts_in_safe(self, safe):
        _, body = self.request("GET", f"{self.base}/Accounts", query={"filter": f"safeName eq {safe}", "limit": 1000})
        return body.get("value", [])

    def delete_account(self, account_id):
        self.request("DELETE", f"{self.base}/Accounts/{urllib.parse.quote(str(account_id), safe='')}")

    def delete_safe(self, name):
        self.request("DELETE", f"{self.base}/Safes/{self._sid(name)}")

    def identity_post(self, path, body):
        """Calls a CyberArk Identity API on the token host (used read-only by preflight)."""
        u = urllib.parse.urlparse(self.c["token_url"])
        return self.request("POST", f"{u.scheme}://{u.netloc}{path}", body)[1]

    def platform_ids(self):
        try:
            _, body = self.request("GET", f"{self.base}/Platforms/targets")
        except ApiError as e:
            log.warning("Could not list platforms (%s); platform check skipped", e)
            return None
        plats = body.get("Platforms") or body.get("platforms") or body.get("value") or []
        return {str(p.get("PlatformID") or p.get("platformId") or "").lower() for p in plats}


# --------------------------------------------------------------------------- #
# Audit log (append-only JSON Lines, SHA-256 hash chain) and state ledger
# --------------------------------------------------------------------------- #
GENESIS = "0" * 64


def _entry_hash(entry):
    payload = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _last_hash(path):
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        buf = b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            lines = [l for l in buf.splitlines() if l.strip()]
            if len(lines) > 1 or pos == 0:
                return json.loads(lines[-1])["hash"]
    return GENESIS


class AuditLog:
    def __init__(self, path, run_id, operator, host):
        self.path = Path(path)
        self.run_id, self.operator, self.host = run_id, operator, host
        self.prev = _last_hash(self.path)
        self.fh = open(self.path, "a", encoding="utf-8")

    def write(self, event, **fields):
        entry = OrderedDict(ts=utcnow(), run_id=self.run_id, operator=self.operator, host=self.host, event=event)
        entry.update(fields)
        entry["prev_hash"] = self.prev
        entry["hash"] = _entry_hash(entry)
        self.fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.prev = entry["hash"]

    def close(self):
        self.fh.close()


def verify_audit(path):
    prev, n = GENESIS, 0
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("prev_hash") != prev:
                return False, f"line {n}: chain broken (prev_hash does not match line {n - 1})"
            if _entry_hash(e) != e.get("hash"):
                return False, f"line {n}: entry altered (hash mismatch)"
            prev = e["hash"]
    return True, f"{n} entries, chain intact, last hash {prev}"


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, command TEXT, started TEXT, finished TEXT, operator TEXT, host TEXT,
  review_sha256 TEXT, members_sha256 TEXT, outcome TEXT);
CREATE TABLE IF NOT EXISTS objects (
  obj_key TEXT PRIMARY KEY, stage TEXT, safe TEXT, object TEXT,
  status TEXT,          -- PENDING | IN_PROGRESS | DONE | FAILED
  result TEXT,          -- CREATED | EXISTS | ADOPTED (DONE only)
  attempts INTEGER DEFAULT 0, cyberark_id TEXT, delinea_secret_id TEXT, source_line TEXT,
  error_system TEXT, http_status INTEGER, error_code TEXT, last_error TEXT, hint TEXT,
  first_seen TEXT, updated TEXT, last_run_id TEXT);
"""


class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def get(self, key):
        return self.db.execute("SELECT * FROM objects WHERE obj_key=?", (key,)).fetchone()

    def ensure(self, key, stage, safe, obj, secret_id="", line=""):
        self.db.execute("INSERT OR IGNORE INTO objects (obj_key, stage, safe, object, status, delinea_secret_id, "
                        "source_line, first_seen, updated) VALUES (?,?,?,?, 'PENDING', ?,?,?,?)",
                        (key, stage, safe, obj, secret_id, line, utcnow(), utcnow()))
        self.db.commit()

    def set(self, key, run_id, status, result=None, cyberark_id=None, err=None, hint=None, bump=False):
        cols = {"status": status, "updated": utcnow(), "last_run_id": run_id}
        if result is not None:
            cols["result"] = result
        if cyberark_id is not None:
            cols["cyberark_id"] = cyberark_id
        if err is not None:
            cols.update(error_system=err.system, http_status=err.status, error_code=err.code,
                        last_error=err.message, hint=hint)
        elif status == "DONE":
            cols.update(error_system=None, http_status=None, error_code=None, last_error=None, hint=None)
        sets = ", ".join(f"{c}=?" for c in cols) + (", attempts=attempts+1" if bump else "")
        self.db.execute(f"UPDATE objects SET {sets} WHERE obj_key=?", (*cols.values(), key))
        self.db.commit()

    def run_start(self, run_id, command, operator, host, review_sha, members_sha):
        self.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
                        (run_id, command, utcnow(), None, operator, host, review_sha, members_sha, "RUNNING"))
        self.db.commit()

    def run_end(self, run_id, outcome):
        self.db.execute("UPDATE runs SET finished=?, outcome=? WHERE run_id=?", (utcnow(), outcome, run_id))
        self.db.commit()

    def all(self):
        return self.db.execute("SELECT * FROM objects ORDER BY CASE stage WHEN 'SAFE' THEN 1 "
                               "WHEN 'MEMBER' THEN 2 ELSE 3 END, safe, object").fetchall()


class RunLock:
    """Stops two runs from working on the same ledger at once."""

    def __init__(self, path, force=False):
        self.path = Path(path)
        if force and self.path.exists():
            self.path.unlink()
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise SystemExit(f"Another run holds {self.path} ({self.path.read_text().strip()}). "
                             "If that run is dead, re-run with --force-unlock.")
        with os.fdopen(fd, "w") as fh:
            fh.write(f"pid {os.getpid()} on {socket.gethostname()} since {utcnow()}")

    def release(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------- #
# Inputs and validation
# --------------------------------------------------------------------------- #
def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def is_yes(v):
    return str(v or "Y").strip().upper() in ("Y", "YES", "TRUE", "1")


def safe_name_problems(name, cfg):
    p = []
    if not name.strip():
        p.append("empty Safe name")
    if len(name) > cfg["safe_name_max_length"]:
        p.append(f"Safe name over {cfg['safe_name_max_length']} chars")
    bad = sorted({c for c in name if c in cfg["safe_name_invalid_chars"]})
    if bad:
        p.append("Safe name has invalid chars " + " ".join(bad))
    if name != name.strip():
        p.append("Safe name has leading/trailing spaces")
    return p


def account_problems(r, cfg, platforms):
    p = safe_name_problems(r.get("Target CyberArk Safe", ""), cfg)
    plat = r.get("Target Platform ID", "").strip()
    if not plat or plat.upper().startswith("UNMAPPED"):
        p.append("no Target Platform ID")
    elif platforms is not None and plat.lower() not in platforms:
        p.append(f"platform '{plat}' is not active in the tenant")
    if not r.get("Username", "").strip():
        p.append("no Username")
    sid = r.get("Delinea Secret ID", "").strip()
    if not sid.isdigit():
        p.append("missing or non-numeric 'Delinea Secret ID'")
    if not r.get("Delinea Secret Field", "").strip():
        p.append("no 'Delinea Secret Field' (field slug)")
    if r.get("Secret Type", "").strip().lower() not in SECRET_TYPES:
        p.append(f"Secret Type must be password or key, got '{r.get('Secret Type', '')}'")
    if "Secret" in r:
        p.append("review file has a 'Secret' column; regenerate it with the current Phase 1")
    return p


def member_target(name, cfg):
    dmap = {k.lower(): v for k, v in cfg["directory_map"].items()}
    domain, _, short = name.rpartition("\\")
    if not domain and "@" in name:
        short, _, domain = name.partition("@")
    search_in = dmap.get(domain.lower()) or dmap.get(domain.split(".")[0].lower()) or dmap.get("*", "Vault")
    member = short if (domain and cfg["strip_domain_prefix"]) else name
    return member, search_in


def key_safe(safe):
    return f"SAFE|{safe.lower()}"


def key_member(safe, member):
    return f"MEMBER|{safe.lower()}|{member.lower()}"


def key_account(r):
    return f"ACCOUNT|{r['Delinea Secret ID'].strip()}"


def load_inputs(args, cfg):
    rows = [r for r in read_csv(args.review) if is_yes(r.get("Migrate"))]
    members = read_csv(args.members) if args.members else []
    if args.safe:
        wanted = {s.lower() for s in args.safe}
        rows = [r for r in rows if r.get("Target CyberArk Safe", "").lower() in wanted]
        members = [m for m in members if m.get("Target CyberArk Safe", "").lower() in wanted]
    prefix = getattr(args, "rehearsal_prefix", None)
    if prefix:
        maxlen = cfg["safe_name_max_length"]
        mapped = {}
        for r in rows + members:
            orig = r["Target CyberArk Safe"]
            r["Target CyberArk Safe"] = (prefix + orig)[:maxlen].rstrip()
            mapped.setdefault(r["Target CyberArk Safe"], set()).add(orig)
        clashes = {k: v for k, v in mapped.items() if len(v) > 1}
        if clashes:
            raise SystemExit("Rehearsal prefix makes these Safes collide after truncation to "
                             f"{maxlen} chars: {clashes}. Use a shorter prefix (e.g. ZZ-).")
    safes = list(OrderedDict.fromkeys(r["Target CyberArk Safe"] for r in rows))
    members = [m for m in members if m["Target CyberArk Safe"] in safes]
    seen, dupes = set(), []
    for r in rows:
        sid = r.get("Delinea Secret ID", "").strip()
        if sid and sid in seen:
            dupes.append(sid)
        seen.add(sid)
    return rows, members, safes, dupes


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, ledger, audit, run_id, cyberark, delinea, cfg, only_failed, rehearsal=False):
        self.rehearsal = rehearsal
        self.ledger, self.audit, self.run_id = ledger, audit, run_id
        self.ca, self.dl, self.cfg = cyberark, delinea, cfg
        self.only_failed = only_failed
        self.counts = OrderedDict()

    def _count(self, stage, outcome):
        self.counts[(stage, outcome)] = self.counts.get((stage, outcome), 0) + 1

    def _should_process(self, key):
        row = self.ledger.get(key)
        if row["status"] == "DONE":
            self._count(row["stage"], "ALREADY_DONE")
            return False
        if self.only_failed and row["status"] not in ("FAILED", "IN_PROGRESS"):
            return False
        return True

    def _done(self, key, stage, safe, obj, result, cid=None, note=""):
        self.ledger.set(key, self.run_id, "DONE", result=result, cyberark_id=cid, bump=True)
        self.audit.write("object", stage=stage, obj_key=key, safe=safe, object=obj, outcome=result,
                         cyberark_id=cid, message=note)
        self._count(stage, result)
        log.info("[%s] %-8s %s / %s %s", stage, result, safe, obj, f"({note})" if note else "")

    def _fail(self, key, stage, safe, obj, err, secret=None):
        if secret and secret in err.message:
            err.message = err.message.replace(secret, "***")
        hint = hint_for(err, stage)
        self.ledger.set(key, self.run_id, "FAILED", err=err, hint=hint, bump=True)
        self.audit.write("object", stage=stage, obj_key=key, safe=safe, object=obj, outcome="FAILED",
                         system=err.system, http_status=err.status, error_code=err.code,
                         message=err.message, hint=hint)
        self._count(stage, "FAILED")
        log.warning("[%s] FAILED   %s / %s: %s %s %s | %s", stage, safe, obj, err.system,
                    err.status or "", err.message, hint)

    def _invalid(self, key, stage, safe, obj, reason):
        self._fail(key, stage, safe, obj, ApiError("PRECHECK", 0, reason))

    # 1. Safes --------------------------------------------------------------
    def safes(self, safes):
        log.info("=== Stage 1: Safes (%d) ===", len(safes))
        for safe in safes:
            key = key_safe(safe)
            self.ledger.ensure(key, "SAFE", safe, safe)
            if not self._should_process(key):
                continue
            try:
                existing = self.ca.get_safe(safe)
                if existing:
                    self._done(key, "SAFE", safe, safe, "EXISTS", existing.get("safeUrlId"))
                    continue
                self.ledger.set(key, self.run_id, "IN_PROGRESS")
                try:
                    created = self.ca.create_safe(safe, self.cfg["safe_defaults"])
                    self._done(key, "SAFE", safe, safe, "CREATED", created.get("safeUrlId"))
                except ApiError as e:
                    if e.status == 409 or (e.ambiguous and self.ca.get_safe(safe)):
                        self._done(key, "SAFE", safe, safe, "EXISTS", note="found after create error")
                    else:
                        raise
            except ApiError as e:
                self._fail(key, "SAFE", safe, safe, e)

    def safe_ready(self, safe):
        row = self.ledger.get(key_safe(safe))
        return row is not None and row["status"] == "DONE"

    # 2. Members ------------------------------------------------------------
    def members(self, members):
        log.info("=== Stage 2: Safe members (%d) ===", len(members))
        roles = self.cfg["role_permissions"]
        cache = {}
        for m in members:
            safe = m["Target CyberArk Safe"]
            member, search_in = member_target(m["Member_Name"], self.cfg)
            role = m.get("CyberArk_Role", "")
            key = key_member(safe, member)
            label = f"{member} ({search_in}) as {role}"
            self.ledger.ensure(key, "MEMBER", safe, label)
            if not self._should_process(key):
                continue
            if not self.safe_ready(safe):
                self._invalid(key, "MEMBER", safe, label, "Safe is not created yet (see SAFE failures)")
                continue
            if role not in roles:
                self._invalid(key, "MEMBER", safe, label, f"no role_permissions entry for role '{role}'")
                continue
            try:
                if safe not in cache:
                    cache[safe] = self.ca.member_names(safe)
                if member.lower() in cache[safe]:
                    self._done(key, "MEMBER", safe, label, "EXISTS", note="permissions not changed")
                    continue
                self.ledger.set(key, self.run_id, "IN_PROGRESS")
                try:
                    self.ca.add_member(safe, member, search_in, roles[role])
                    cache[safe].add(member.lower())
                    self._done(key, "MEMBER", safe, label, "CREATED")
                except ApiError as e:
                    if e.status == 409 or (e.ambiguous and member.lower() in self.ca.member_names(safe)):
                        self._done(key, "MEMBER", safe, label, "EXISTS", note="found after create error")
                    else:
                        raise
            except ApiError as e:
                self._fail(key, "MEMBER", safe, label, e)

    # 3. Accounts -----------------------------------------------------------
    def _body(self, r, secret):
        cfg = self.cfg
        body = {
            "name": r["Account Name"].strip(),
            "address": r.get("Address", "").strip(),
            "userName": r["Username"].strip(),
            "platformId": r["Target Platform ID"].strip(),
            "safeName": r["Target CyberArk Safe"],
            "secretType": r["Secret Type"].strip().lower(),
            "secret": secret,
            "secretManagement": {"automaticManagementEnabled": bool(cfg["account_defaults"]["automaticManagementEnabled"])},
        }
        if not body["secretManagement"]["automaticManagementEnabled"]:
            body["secretManagement"]["manualManagementReason"] = cfg["account_defaults"]["manualManagementReason"]
        props = {dst: r[src].strip() for src, dst in cfg["account_property_map"].items() if r.get(src, "").strip()}
        if props:
            body["platformAccountProperties"] = props
        if not body["name"]:
            body.pop("name")
        return body

    def accounts(self, rows, platforms):
        log.info("=== Stage 3: Accounts (%d) ===", len(rows))
        # CyberArk account IDs already owned by a Delinea secret in this ledger -> that secret's key.
        owners = {r["cyberark_id"]: r["obj_key"] for r in self.ledger.db.execute(
            "SELECT obj_key, cyberark_id FROM objects WHERE stage='ACCOUNT' AND status='DONE' AND cyberark_id IS NOT NULL")}
        for i, r in enumerate(rows, 1):
            safe, name = r["Target CyberArk Safe"], r.get("Account Name", "")
            sid, line = r.get("Delinea Secret ID", "").strip(), r.get("Delinea_Source_Line", "")
            if not sid:
                log.warning("[ACCOUNT] SKIPPED  %s / %s: no Delinea Secret ID (cannot track or fetch)", safe, name)
                self._count("ACCOUNT", "UNTRACKABLE")
                continue
            key = key_account(r)
            label = f"{name} [Delinea #{sid}]"
            self.ledger.ensure(key, "ACCOUNT", safe, label, sid, line)
            prior = self.ledger.get(key)
            if prior["status"] == "DONE" and prior["safe"] != safe:
                log.warning("[ACCOUNT] %s was already migrated to Safe '%s'; now mapped to '%s'. "
                            "Not migrated again; move it in CyberArk if needed.", label, prior["safe"], safe)
            if not self._should_process(key):
                continue
            problems = account_problems(r, self.cfg, platforms)
            if problems:
                self._invalid(key, "ACCOUNT", safe, label, "; ".join(problems))
                continue
            if not self.safe_ready(safe):
                self._invalid(key, "ACCOUNT", safe, label, "Safe is not created yet (see SAFE failures)")
                continue
            secret = None
            stype = r["Secret Type"].strip().lower()
            claimed = {cid for cid, owner in owners.items() if owner != key}
            try:
                existing = self.ca.find_account(safe, r["Username"], r.get("Address", ""), name, stype, claimed)
                if existing:
                    owners[existing.get("id")] = key
                    self._done(key, "ACCOUNT", safe, label, "ADOPTED", existing.get("id"),
                               note="already in CyberArk; not changed")
                    continue
                # Fetch at send time only. The value lives in this frame for one request.
                if self.rehearsal:
                    secret = fake_secret(r["Secret Type"].strip().lower())
                    self.audit.write("fake_secret", stage="ACCOUNT", obj_key=key, outcome="OK",
                                     message="rehearsal: random value, Delinea not contacted")
                else:
                    secret = self.dl.get_secret_field(sid, r["Delinea Secret Field"].strip())
                if not secret:
                    raise ApiError("DELINEA", 0, f"field '{r['Delinea Secret Field']}' is empty in Delinea")
                if not self.rehearsal:
                    self.audit.write("secret_read", stage="ACCOUNT", obj_key=key, delinea_secret_id=sid,
                                     field=r["Delinea Secret Field"].strip(), outcome="OK")
                self.ledger.set(key, self.run_id, "IN_PROGRESS")
                try:
                    created = self.ca.add_account(self._body(r, secret))
                    owners[created.get("id")] = key
                    self._done(key, "ACCOUNT", safe, label, "CREATED", created.get("id"))
                except ApiError as e:
                    found = (self.ca.find_account(safe, r["Username"], r.get("Address", ""), name, stype, claimed)
                             if e.ambiguous else None)
                    if found:
                        owners[found.get("id")] = key
                        self._done(key, "ACCOUNT", safe, label, "CREATED", found.get("id"),
                                   note="confirmed after ambiguous create error")
                    else:
                        raise
            except ApiError as e:
                self._fail(key, "ACCOUNT", safe, label, e, secret)
            except Exception as e:  # noqa: BLE001 - one bad account must not stop the run
                self._fail(key, "ACCOUNT", safe, label, ApiError("SCRIPT", 0, f"unexpected {type(e).__name__}: {e}"), secret)
            finally:
                secret = None
            if i % 50 == 0:
                log.info("... %d/%d accounts processed (CyberArk %.0f/min%s)", i, len(rows), self.ca.limiter.rate,
                         f", Delinea {self.dl.limiter.rate:.0f}/min" if self.dl else "")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def credential(env_name, prompt):
    return os.environ.get(env_name) or getpass.getpass(prompt)


def state_paths(args):
    d = Path(args.state_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d / "migration_state.db", d / "audit_log.jsonl", d / "run.lock"


def setup_logging(state_dir, verbose, run_id):
    log_dir = Path(state_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"phase2_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{run_id[:8]}.log"
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(path, encoding="utf-8")])
    return path


def precheck_files(rows, safes, members, dupes, cfg):
    errors = []
    for s in safes:
        p = safe_name_problems(s, cfg)
        if p:
            errors.append(f"Safe '{s}': {'; '.join(p)}")
    if dupes:
        errors.append("Delinea Secret ID appears more than once: " + ", ".join(sorted(set(dupes))))
    if rows and "Secret" in rows[0]:
        errors.append("Migration_Review.csv has a 'Secret' column (old Phase 1 format). Regenerate it.")
    return errors


def cmd_plan(args, cfg):
    setup_logging(args.state_dir, args.verbose, "plan")
    rows, members, safes, dupes = load_inputs(args, cfg)
    errors = precheck_files(rows, safes, members, dupes, cfg)
    db_path, _, _ = state_paths(args)
    ledger = Ledger(db_path)
    plan = OrderedDict()

    def tally(stage, key, problems=None):
        row = ledger.get(key)
        state = row["status"] if row else "NEW"
        if problems:
            state = "WILL FAIL PRE-CHECK"
        plan[(stage, state)] = plan.get((stage, state), 0) + 1

    for s in safes:
        tally("SAFE", key_safe(s))
    for m in members:
        tally("MEMBER", key_member(m["Target CyberArk Safe"], member_target(m["Member_Name"], cfg)[0]))
    for r in rows:
        if r.get("Delinea Secret ID", "").strip():
            tally("ACCOUNT", key_account(r), account_problems(r, cfg, None))
    print(f"\nPlan for {len(safes)} Safes, {len(members)} members, {len(rows)} accounts (Migrate=Y)")
    for (stage, state), n in plan.items():
        print(f"  {stage:8} {state:20} {n}")
    for r in rows:
        p = account_problems(r, cfg, None)
        if p:
            print(f"  pre-check: line {r.get('Delinea_Source_Line', '?')} {r.get('Account Name', '')}: {'; '.join(p)}")
    for e in errors:
        print(f"  BLOCKER: {e}")
    print("\nDONE objects are skipped by `run`; NEW/PENDING/FAILED are processed. No changes were made.")
    return EXIT_INVALID if errors else EXIT_OK


def cmd_run(args, cfg):
    run_id = str(uuid.uuid4())
    log_path = setup_logging(args.state_dir, args.verbose, run_id)
    db_path, audit_path, lock_path = state_paths(args)
    rows, members, safes, dupes = load_inputs(args, cfg)
    errors = precheck_files(rows, safes, members, dupes, cfg)
    if errors:
        for e in errors:
            log.error("BLOCKER: %s", e)
        log.error("Nothing was sent. Fix the reviewed CSVs and run again.")
        return EXIT_INVALID
    stages = [s.strip().lower() for s in args.stages.split(",") if s.strip()]
    if set(stages) - {"safes", "members", "accounts"}:
        log.error("Unknown stage in --stages: %s", args.stages)
        return EXIT_INVALID

    marker = Path(args.state_dir) / "REHEARSAL"
    if args.rehearsal_prefix:
        if not args.rehearsal_prefix.upper().startswith("ZZ"):
            log.error("Rehearsal prefix must start with ZZ (e.g. ZZTEST-) so test Safes cannot be mistaken for real ones.")
            return EXIT_INVALID
        if db_path.exists() and not marker.exists():
            log.error("%s holds a production ledger. Use a separate --state-dir for rehearsals.", args.state_dir)
            return EXIT_INVALID
        marker.write_text(json.dumps({"prefix": args.rehearsal_prefix, "created": utcnow()}))
    elif marker.exists():
        log.error("%s is a rehearsal state dir. Use a separate --state-dir for the real migration.", args.state_dir)
        return EXIT_INVALID

    operator = args.operator or getpass.getuser()
    host = socket.gethostname()
    lock = RunLock(lock_path, args.force_unlock)
    ledger = Ledger(db_path)
    audit = AuditLog(audit_path, run_id, operator, host)
    review_sha = sha256_file(args.review)
    members_sha = sha256_file(args.members) if args.members else ""
    ledger.run_start(run_id, " ".join(sys.argv[1:]), operator, host, review_sha, members_sha)
    audit.write("run_start", command=" ".join(sys.argv[1:]), review_sha256=review_sha,
                members_sha256=members_sha, stages=stages, only_failed=args.only_failed,
                safes=len(safes), members=len(members), accounts=len(rows))
    outcome = "ERROR"
    try:
        ca = CyberArkClient(cfg, credential(cfg["cyberark"]["client_secret_env"], "CyberArk client secret: "))
        dl = None
        if "accounts" in stages and not args.rehearsal_prefix:
            d = cfg["delinea"]
            env = d["client_secret_env"] if d["grant_type"] == "client_credentials" else d["password_env"]
            dl = DelineaClient(cfg, credential(env, "Delinea API credential: "))
        try:
            ca.renew()
            if dl:
                dl.renew()
        except ApiError as e:
            log.error("%s | %s", e, hint_for(e, "AUTH"))
            audit.write("auth_failed", system=e.system, http_status=e.status, message=e.message)
            return EXIT_ERROR
        audit.write("auth_ok", systems=["CYBERARK"] + (["DELINEA"] if dl else []))
        platforms = ca.platform_ids() if "accounts" in stages else None

        print(f"\nRun {run_id}: {len(safes)} Safes, {len(members)} members, {len(rows)} accounts; "
              f"stages {', '.join(stages)}{'; only failed' if args.only_failed else ''}.")
        if not args.yes and input("Type MIGRATE to continue: ").strip() != "MIGRATE":
            audit.write("run_aborted", reason="operator did not confirm")
            outcome = "ABORTED"
            return EXIT_ERROR

        if args.rehearsal_prefix:
            audit.write("rehearsal", prefix=args.rehearsal_prefix,
                        message="fake secrets, prefixed test Safes, Delinea not contacted")
            print(f"REHEARSAL: Safes prefixed '{args.rehearsal_prefix}', random fake secrets. "
                  "Remove afterwards with cleanup-rehearsal.")
        runner = Runner(ledger, audit, run_id, ca, dl, cfg, args.only_failed, rehearsal=bool(args.rehearsal_prefix))
        if "safes" in stages:
            runner.safes(safes)
        if "members" in stages:
            runner.members(members)
        if "accounts" in stages:
            runner.accounts(rows, platforms)

        rate_stats = {c.SYSTEM: {"throttled_429": c.limiter.throttled, "waited_seconds": round(c.limiter.waited, 1),
                                 "final_rate_per_min": round(c.limiter.rate),
                                 "peak_calls_in_window": c.limiter.peak,
                                 "token_refreshes": c.renewals["refresh_token"],
                                 "token_reauths": c.renewals["reauthenticate"],
                                 "refresh_refused": c.renewals["refresh_failed"],
                                 "window_cap": c.limiter.window_cap} for c in (ca, dl) if c}
        audit.write("rate_limits", **rate_stats)
        for sysname, st in rate_stats.items():
            print(f"  {sysname}: {st['throttled_429']} x 429, {st['waited_seconds']}s paced, "
                  f"ended at {st['final_rate_per_min']}/min, peak {st['peak_calls_in_window']} calls "
                  f"in any window (cap {st['window_cap']}); token renewals: {st['token_refreshes']} by refresh "
                  f"token, {st['token_reauths']} by re-sign-in")
        failed = sum(n for (_, o), n in runner.counts.items() if o == "FAILED")
        outcome = "COMPLETED_WITH_FAILURES" if failed else "COMPLETED"
        print("\nThis run:")
        for (stage, o), n in runner.counts.items():
            print(f"  {stage:8} {o:13} {n}")
        print_status(ledger, brief=True)
        print(f"\nAudit log: {audit_path}\nRun log:   {log_path}\nLedger:    {db_path}")
        if failed:
            print("\nNext step: fix the causes listed above (see the hints), then re-run the SAME command "
                  "with --only-failed. Finished objects are never sent twice.")
        return EXIT_FAILURES if failed else EXIT_OK
    except KeyboardInterrupt:
        outcome = "INTERRUPTED"
        log.error("Interrupted. Safe to re-run: finished objects are skipped, in-progress ones are re-checked.")
        return EXIT_ERROR
    finally:
        audit.write("run_end", outcome=outcome)
        ledger.run_end(run_id, outcome)
        audit.close()
        lock.release()


def print_status(ledger, brief=False):
    rows = ledger.all()
    summary = OrderedDict()
    for r in rows:
        k = (r["stage"], r["status"] + (f"/{r['result']}" if r["status"] == "DONE" and r["result"] else ""))
        summary[k] = summary.get(k, 0) + 1
    print("\nLedger (all runs):")
    for (stage, st), n in sorted(summary.items()):
        print(f"  {stage:8} {st:20} {n}")
    failed = [r for r in rows if r["status"] in ("FAILED", "IN_PROGRESS")]
    if failed:
        print(f"\nOutstanding ({len(failed)}):")
        for r in failed[: (25 if brief else None)]:
            where = f"{r['error_system'] or ''} {r['http_status'] or ''} {r['error_code'] or ''}".strip()
            print(f"  [{r['stage']}] {r['safe']} / {r['object']} (attempts {r['attempts']})")
            print(f"      error: {where}: {r['last_error'] or r['status']}")
            print(f"      fix:   {r['hint'] or 'Re-run with --only-failed; it will be re-checked first.'}")
        if brief and len(failed) > 25:
            print(f"  ... {len(failed) - 25} more; run `status` for the full list")


def cmd_status(args, cfg):
    db_path, _, _ = state_paths(args)
    print_status(Ledger(db_path))
    return EXIT_OK


def cmd_report(args, cfg):
    db_path, _, _ = state_paths(args)
    ledger = Ledger(db_path)
    out = Path(args.out or Path(args.state_dir) / f"migration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    rows = ledger.all()
    with open(out, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        cols = rows[0].keys() if rows else []
        w.writerow(cols)
        for r in rows:
            w.writerow([r[c] for c in cols])
    runs = ledger.db.execute("SELECT * FROM runs ORDER BY started").fetchall()
    print(f"Wrote {out} ({len(rows)} objects, {len(runs)} runs recorded)")
    return EXIT_OK


def cmd_verify(args, cfg):
    _, audit_path, _ = state_paths(args)
    ok, msg = verify_audit(audit_path)
    print(("OK: " if ok else "FAILED: ") + msg)
    return EXIT_OK if ok else EXIT_ERROR


# --------------------------------------------------------------------------- #
# Rehearsal helpers
# --------------------------------------------------------------------------- #
def fake_secret(secret_type):
    """Random throwaway value for rehearsals. Never a real credential."""
    if secret_type == "key" and shutil.which("ssh-keygen"):
        d = tempfile.mkdtemp(prefix="zztest_key_")
        try:
            path = os.path.join(d, "k")
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "zztest-rehearsal", "-f", path],
                           check=True, capture_output=True)
            with open(path) as fh:
                return fh.read()
        finally:
            shutil.rmtree(d, ignore_errors=True)
    alphabet = string.ascii_letters + string.digits + "!#%+-_=@"
    return "ZZ" + "".join(pysecrets.choice(alphabet) for _ in range(30))


def cmd_cleanup_rehearsal(args, cfg):
    run_id = str(uuid.uuid4())
    setup_logging(args.state_dir, args.verbose, run_id)
    db_path, audit_path, lock_path = state_paths(args)
    marker = Path(args.state_dir) / "REHEARSAL"
    if not marker.exists():
        log.error("%s is not a rehearsal state dir; refusing to delete anything.", args.state_dir)
        return EXIT_INVALID
    prefix = json.loads(marker.read_text())["prefix"]
    ledger = Ledger(db_path)
    # Only Safes this rehearsal CREATED, and only with the rehearsal prefix. Never by search.
    targets = [r["safe"] for r in ledger.all() if r["stage"] == "SAFE" and r["status"] == "DONE"
               and r["result"] == "CREATED" and r["safe"].startswith(prefix)]
    if not targets:
        print("Nothing to clean up.")
        return EXIT_OK
    print(f"Will delete all accounts in, then delete, these {len(targets)} rehearsal Safes:")
    for t in targets:
        print(f"  {t}")
    if not args.yes and input("Type DELETE to continue: ").strip() != "DELETE":
        print("Aborted.")
        return EXIT_ERROR
    lock = RunLock(lock_path, args.force_unlock)
    audit = AuditLog(audit_path, run_id, args.operator or getpass.getuser(), socket.gethostname())
    audit.write("cleanup_start", prefix=prefix, safes=targets)
    ca = CyberArkClient(cfg, credential(cfg["cyberark"]["client_secret_env"], "CyberArk client secret: "))
    left = 0
    try:
        ca.renew()
        for safe in targets:
            try:
                for a in ca.accounts_in_safe(safe):
                    ca.delete_account(a["id"])
                    audit.write("cleanup", stage="ACCOUNT", safe=safe, object=a.get("name"), outcome="DELETED")
                ca.delete_safe(safe)
                audit.write("cleanup", stage="SAFE", safe=safe, outcome="DELETED")
                ledger.set(key_safe(safe), run_id, "DONE", result="DELETED")
                log.info("[CLEANUP] deleted %s", safe)
            except ApiError as e:
                left += 1
                audit.write("cleanup", stage="SAFE", safe=safe, outcome="FAILED", http_status=e.status, message=e.message)
                log.warning("[CLEANUP] could not delete %s: %s. Deleted accounts are kept for the Safe's "
                            "retention period; re-run cleanup-rehearsal after it passes.", safe, e)
    except ApiError as e:
        log.error("%s | %s", e, hint_for(e, "AUTH"))
        return EXIT_ERROR
    finally:
        audit.write("cleanup_end", remaining=left)
        audit.close()
        lock.release()
    print(f"Cleanup finished: {len(targets) - left} deleted, {left} remaining.")
    return EXIT_FAILURES if left else EXIT_OK


# --------------------------------------------------------------------------- #
# Preflight (read-only, real tenant) and Delinea probe (migration day)
# --------------------------------------------------------------------------- #
def cmd_preflight(args, cfg):
    setup_logging(args.state_dir, args.verbose, "preflight")
    results = []

    def record(check, status, detail):
        results.append({"check": check, "status": status, "detail": detail})
        print(f"  [{status:10}] {check}: {detail}")

    print("Preflight against CyberArk (read-only, no changes)")
    ca = CyberArkClient(cfg, credential(cfg["cyberark"]["client_secret_env"], "CyberArk client secret: "))
    try:
        ca.renew()
        record("Authenticate service user", "OK", cfg["cyberark"]["client_id"])
    except ApiError as e:
        record("Authenticate service user", "FAIL", f"{e} | {hint_for(e, 'AUTH')}")
        return _preflight_done(args, results)

    try:
        ca.request("GET", f"{ca.base}/Safes", query={"limit": 1})
        record("List Safes (API rights)", "OK", "service user can call the Safes API")
    except ApiError as e:
        record("List Safes (API rights)", "FAIL", f"{e} | {hint_for(e, 'SAFE')}")

    platforms = ca.platform_ids()
    wanted = set(args.platform or [])
    if args.mapping_config:
        wanted |= set(json.load(open(args.mapping_config, encoding="utf-8")).get("platform_map", {}).values())
    rows, members, safes = [], [], []
    if args.review:
        rows, members, safes, _ = load_inputs(args, cfg)
        wanted |= {r["Target Platform ID"] for r in rows if r.get("Target Platform ID")}
    if platforms is None:
        record("Platforms", "WARN", "could not list platforms; check manually")
    else:
        record("Platforms listed", "OK", f"{len(platforms)} active platforms in tenant")
        for p in sorted(x for x in wanted if not x.upper().startswith("UNMAPPED")):
            record(f"Platform {p}", "OK" if p.lower() in platforms else "FAIL",
                   "active" if p.lower() in platforms else "not active in tenant; import/activate it or fix the mapping")

    # Directories and groups via CyberArk Identity (best-effort: API shapes vary by tenant version).
    dirs = {}
    try:
        body = ca.identity_post("/CDirectoryService/GetDirectoryServices", {})
        for res in (body.get("Result") or {}).get("Results", []):
            row = res.get("Row", {})
            for k in ("DisplayName", "Name", "Service"):
                if row.get(k):
                    dirs[str(row[k]).lower()] = row.get("directoryServiceUuid") or row.get("ID")
        record("Identity directories", "OK" if dirs else "WARN",
               ", ".join(sorted(dirs)) or "none returned; check the service user's Identity rights")
    except ApiError as e:
        record("Identity directories", "UNVERIFIED", f"cannot query Identity ({e}); confirm directory names manually")
    for src, name in cfg["directory_map"].items():
        if name.lower() == "vault":
            continue
        if dirs:
            record(f"directory_map {src} -> {name}", "OK" if name.lower() in dirs else "FAIL",
                   "found" if name.lower() in dirs else "no such directory in Identity; fix directory_map")
    groups = list(args.group or []) + [m["Member_Name"] for m in members]
    for g in OrderedDict.fromkeys(groups):
        member, search_in = member_target(g, cfg)
        uuid_ = dirs.get(search_in.lower())
        if not uuid_:
            record(f"Group {g}", "UNVERIFIED", f"directory '{search_in}' not resolved; group not checked")
            continue
        try:
            q = {"directoryServices": [uuid_],
                 "group": json.dumps({"_or": [{"DisplayName": {"_like": member}}, {"SystemName": {"_like": member}}]}),
                 "Args": {"PageNumber": 1, "PageSize": 10, "Limit": 10, "Caching": -1}}
            body = ca.identity_post("/UserMgmt/DirectoryServiceQuery", q)
            hits = ((body.get("Result") or {}).get("Group") or {}).get("Results", [])
            names = {str(h.get("Row", {}).get(k, "")).lower() for h in hits for k in ("DisplayName", "SystemName")}
            ok = any(member.lower() == n or n.startswith(member.lower() + "@") for n in names)
            record(f"Group {g}", "OK" if ok else "FAIL",
                   f"found in {search_in}" if ok else f"not found in {search_in}; check the name and directory sync")
        except ApiError as e:
            record(f"Group {g}", "UNVERIFIED", f"group query failed ({e.status}); check in the portal")

    for safe in safes:
        try:
            exists = ca.get_safe(safe)
            record(f"Safe name {safe}", "WARN" if exists else "OK",
                   "ALREADY EXISTS: the migration would add members/accounts into it" if exists else "free")
        except ApiError as e:
            record(f"Safe name {safe}", "UNVERIFIED", str(e))
    st = ca.limiter
    record("Rate limiting", "OK" if not st.throttled else "WARN",
           f"{st.throttled} x 429 during preflight; client cap {cfg['cyberark']['requests_per_minute']}/min")
    return _preflight_done(args, results)


def _preflight_done(args, results):
    out = Path(args.state_dir) / f"preflight_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"ts": utcnow(), "results": results}, indent=2))
    fails = [r for r in results if r["status"] == "FAIL"]
    unv = [r for r in results if r["status"] == "UNVERIFIED"]
    print(f"\n{len(results)} checks: {len(fails)} FAIL, {len(unv)} UNVERIFIED. Report: {out}")
    return EXIT_FAILURES if fails else EXIT_OK


def cmd_probe_delinea(args, cfg):
    """Read one secret per (template, field) to prove access. Never prints or stores values."""
    setup_logging(args.state_dir, args.verbose, "probe")
    rows, _, _, _ = load_inputs(args, cfg)
    picks = OrderedDict()
    for r in rows:
        k = (r.get("Delinea_Template", ""), r.get("Delinea Secret Field", ""))
        picks.setdefault(k, [])
        if len(picks[k]) < args.per_template and r.get("Delinea Secret ID", "").strip().isdigit():
            picks[k].append(r)
    d = cfg["delinea"]
    env = d["client_secret_env"] if d["grant_type"] == "client_credentials" else d["password_env"]
    dl = DelineaClient(cfg, credential(env, "Delinea API credential: "))
    _, audit_path, _ = state_paths(args)
    audit = AuditLog(audit_path, str(uuid.uuid4()), args.operator or getpass.getuser(), socket.gethostname())
    bad = 0
    try:
        dl.renew()
        print("Delinea authentication OK")
        for (tmpl, field), sample in picks.items():
            for r in sample:
                sid = r["Delinea Secret ID"].strip()
                try:
                    value = dl.get_secret_field(sid, field)
                    kind = "key-like" if value.lstrip().startswith("-----BEGIN") else "text"
                    print(f"  OK    {tmpl} / {field} (secret #{sid}): {len(value)} chars, {kind}")
                    audit.write("probe", delinea_secret_id=sid, field=field, outcome="OK", length=len(value))
                    value = None
                except ApiError as e:
                    bad += 1
                    print(f"  FAIL  {tmpl} / {field} (secret #{sid}): {e} | {hint_for(e, 'ACCOUNT')}")
                    audit.write("probe", delinea_secret_id=sid, field=field, outcome="FAILED",
                                http_status=e.status, message=e.message)
    except ApiError as e:
        print(f"Delinea authentication FAILED: {e} | {hint_for(e, 'AUTH')}")
        return EXIT_ERROR
    finally:
        audit.close()
    print(f"\nProbed {sum(len(v) for v in picks.values())} secrets across {len(picks)} template/field pairs; {bad} failed.")
    return EXIT_FAILURES if bad else EXIT_OK


def _break_is_interrupt():
    """Ctrl+Break (Windows) and SIGTERM stop a run like Ctrl+C, so the UI's Stop button exits cleanly."""
    def handler(signum, frame):
        raise KeyboardInterrupt
    for name in ("SIGBREAK", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), handler)


def main(argv=None):
    _break_is_interrupt()
    ap = argparse.ArgumentParser(description="Phase 2: load reviewed Phase 1 output into CyberArk Privilege Cloud")
    ap.add_argument("--write-default-config", metavar="PATH")
    sub = ap.add_subparsers(dest="command")

    def common(p, needs_inputs=True):
        p.add_argument("--config", required=True)
        p.add_argument("--state-dir", default="migration_state",
                       help="Ledger, audit log and run logs (keep it for the whole migration)")
        p.add_argument("-v", "--verbose", action="store_true")
        if needs_inputs:
            p.add_argument("--review", required=True, help="Reviewed Migration_Review.csv")
            p.add_argument("--members", help="Reviewed Safe_Members_Review.csv")
            p.add_argument("--safe", action="append", help="Limit to this Safe (repeatable), for pilots")

    common(sub.add_parser("plan", help="Validate and show what a run would do; no changes"))
    p_run = sub.add_parser("run", help="Execute the migration")
    common(p_run)
    p_run.add_argument("--stages", default="safes,members,accounts")
    p_run.add_argument("--only-failed", action="store_true", help="Retry only objects that FAILED or were interrupted")
    p_run.add_argument("--yes", action="store_true", help="Skip the MIGRATE confirmation")
    p_run.add_argument("--operator", help="Name recorded in the audit log (default: OS user)")
    p_run.add_argument("--force-unlock", action="store_true", help="Clear a lock left by a dead run")
    p_run.add_argument("--rehearsal-prefix", metavar="ZZTEST-",
                       help="Rehearsal: prefix every Safe, use random fake secrets, never contact Delinea")
    p_pre = sub.add_parser("preflight", help="Read-only checks against the real CyberArk tenant")
    common(p_pre, needs_inputs=False)
    p_pre.add_argument("--review", help="Optional Migration_Review.csv: check its Safes and platforms")
    p_pre.add_argument("--members", help="Optional Safe_Members_Review.csv: check its groups")
    p_pre.add_argument("--mapping-config", help="Optional Phase 1 mapping_config.json: check platform_map IDs")
    p_pre.add_argument("--platform", action="append", help="Platform ID to check (repeatable)")
    p_pre.add_argument("--group", action="append", help="Delinea-style group name to look up, e.g. CORP\\Unix-Admins")
    p_pre.add_argument("--safe", action="append")
    p_probe = sub.add_parser("probe-delinea", help="Migration day: prove Delinea API access per template/field")
    common(p_probe)
    p_probe.add_argument("--per-template", type=int, default=1)
    p_probe.add_argument("--operator")
    p_clean = sub.add_parser("cleanup-rehearsal", help="Delete the Safes and accounts a rehearsal created")
    common(p_clean, needs_inputs=False)
    p_clean.add_argument("--yes", action="store_true")
    p_clean.add_argument("--operator")
    p_clean.add_argument("--force-unlock", action="store_true")
    common(sub.add_parser("status", help="Show ledger summary and outstanding failures"), needs_inputs=False)
    p_rep = sub.add_parser("report", help="Export the ledger to CSV")
    common(p_rep, needs_inputs=False)
    p_rep.add_argument("--out")
    common(sub.add_parser("verify-audit", help="Verify the audit log hash chain"), needs_inputs=False)

    args = ap.parse_args(argv)
    if args.write_default_config:
        write_default_config(args.write_default_config)
        return EXIT_OK
    if not args.command:
        ap.print_help()
        return EXIT_INVALID
    cfg = load_config(args.config)
    return {"plan": cmd_plan, "run": cmd_run, "status": cmd_status, "report": cmd_report,
            "verify-audit": cmd_verify, "preflight": cmd_preflight, "probe-delinea": cmd_probe_delinea,
            "cleanup-rehearsal": cmd_cleanup_rehearsal}[args.command](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
