"""Local web UI for the staging database: python -m imw ui

Security model
  * Listens on 127.0.0.1 only, over HTTPS with a self-signed certificate made for this
    computer (see tls.py); the Host and Origin headers must match.
  * The start-up link carries a one-time token that is exchanged for an HttpOnly,
    SameSite=Strict session cookie. Changes also need a custom request header.
  * Nothing is shown until the Windows user who started the tool signs in with their
    password (checked by Windows; see auth.py). After 10 minutes without activity, or
    with Lock session, the page locks again and needs the password.
  * End session (typed confirmation) stops the Workbench, optionally deleting the database.
  * No API returns a secret value. Secrets are only decrypted by the Output step
    when "include secrets" is chosen, straight into upload/Accounts.csv.
  * Runs in-process as the signed-in user, so DPAPI works as for the CLI.
  * The page's script is served as /app.js and /theme.js; the Content-Security-Policy
    allows no inline script, so markup that slipped past esc() still cannot run code.
"""

import csv
import io
import json
import logging
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
from html import escape as html_escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__, csvsafe
from ..adapters import ADAPTERS, AdapterError, detect_adapter, get_adapter
from ..config import (ALL_PERMISSIONS, DEFAULT_CONFIG, PERMISSION_PRESETS, STANDARD_MEMBER_SET, config_diff,
                      all_roles, config_from_dict, load_config, resolve_role)
from ..model import SourceRecord
from ..naming import DEFAULT_PLATFORM_CODES, Namer, address_domain
from ..protect import ProtectError
from ..reference import KIND_HELP, KINDS, USED_KINDS, read_templates, read_users, reference_kind
from ..store import Store, StoreError, run_extract, sha256_file
from ..transform import (target_for, PERM_GROUP_COLUMNS, PERM_ROLE_COLUMNS, PERM_USER_COLUMNS, STANDARD_PLACEHOLDERS, Permissions,
                         apply_member_override, clean_line, member_target,
                         normalize_member_type, safe_settings, sanitize_safe_name)
from .auth import get_authenticator
from .tls import fingerprint, server_context, trust_certificate
from .winfront import bring_to_front
from ..writers import convention_rows
from ..owner import claim_workspace, peer_is_owner

log = logging.getLogger("imw.ui")
PRODUCT = "Idira Migration Workbench"
STATIC = Path(__file__).parent / "static"
# The only files served besides index.html (a fixed list: no path from the request reaches the disk).
STATIC_SCRIPTS = {"/app.js": "app.js", "/theme.js": "theme.js"}
IDLE_SECONDS = 10 * 60          # auto-lock
MAX_FAILURES = 5                # then a growing wait between attempts
PAGE_SIZE = 200
EDITABLE = ("migrate", "target_safe", "platform_id", "account_name")

# The review menu: label -> SQL condition on the accounts view.
VIEWS = {
    "all": ("All accounts", "1=1"),
    "upload": ("Will be uploaded", "migrate = 'Y' AND status <> 'ERROR'"),
    "review": ("Needs a look", "status = 'REVIEW'"),
    "review_open": ("Needs a look, not approved yet", "status = 'REVIEW' AND COALESCE(approved, '') <> 'Y'"),
    "approved": ("Needs a look, approved by you", "status = 'REVIEW' AND approved = 'Y'"),
    "errors": ("Errors (not uploaded)", "status = 'ERROR'"),
    "excluded": ("Left out by you", "migrate = 'N'"),
    "renamed_safes": ("Safe name was changed", "valid_safe_name = 'FALSE'"),
    "no_access": ("No access groups", "access_groups = ''"),
    "no_secret": ("Empty secret", "has_secret = 'N'"),
    "fallback": ("Safe named by the convention (no rule matched)", "safe_mapping_source LIKE 'fallback:%'"),
    "duplicates": ("Possible duplicates (same username and address)", "notes LIKE '%possible duplicate%'"),
    "otp": ("One-time password in the source", "notes LIKE '%one-time password (OTP)%'"),
    "edited": ("Changed by you", "record_id IN (SELECT record_id FROM edits)"),
    "sanitized": ("Forbidden characters changed", "(notes LIKE '%forbidden characters%' OR valid_safe_name = 'FALSE' "
                  "OR record_id IN (SELECT record_id FROM records WHERE notes_json LIKE '%forbidden characters%'))"),
}
FILTER_COLUMNS = {"safe": "target_safe", "source": "source", "platform": "platform_id",
                  "status": "status", "type": "source_type"}
SORTABLE = {"target_safe", "account_name", "username", "address", "platform_id", "status", "folder",
            "source", "record_id"}


class UiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def build_where(body):
    """Turn a menu choice and filters into a parameterised WHERE clause."""
    view = body.get("view") or "all"
    if view not in VIEWS:
        raise UiError(f"unknown view {view}")
    parts, params = [f"({VIEWS[view][1]})"], []
    for key, col in FILTER_COLUMNS.items():
        val = (body.get("filters") or {}).get(key)
        if val:
            parts.append(f"{col} = ?")
            params.append(val)
    search = ((body.get("filters") or {}).get("search") or "").strip()
    if search:
        # % and _ are wildcards in LIKE; the search is plain text, so escape them (a bulk edit
        # of the rows found for "svc_" must not also change "svc1").
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        cols = ("account_name", "username", "address", "folder", "record_id", "target_safe")
        parts.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")")
        params += [like] * len(cols)
    return " AND ".join(parts), params


def check_roles(cfg):
    """Custom roles and the permission map must make sense before they are saved."""
    for name, perms in (cfg.get("custom_roles") or {}).items():
        if not str(name).strip():
            raise UiError("Every custom role needs a name.")
        if any(name.lower() == p.lower() for p in PERMISSION_PRESETS):
            raise UiError(f"'{name}' is a built-in preset name; give your custom role another name.")
        bad = [p for p in perms if p not in ALL_PERMISSIONS]
        if bad:
            raise UiError(f"Custom role '{name}' has unknown permissions: {', '.join(bad)}")
        if not perms:
            raise UiError(f"Custom role '{name}' has no permissions ticked.")
        if "requestsAuthorizationLevel1" in perms and "requestsAuthorizationLevel2" in perms:
            raise UiError(f"Custom role '{name}': pick authorization level 1 or level 2, not both.")
    for word, role in cfg["permission_map"].items():
        if not resolve_role(role, cfg):
            raise UiError(f"Source permission '{word}' maps to '{role}', which is not a preset or custom role.")


def compare_inputs(inputs):
    """Mark files loaded more than once: same name with the same or different content, or the
    same content under another name (which loads every record twice)."""
    for i, cur in enumerate(inputs):
        name = Path(cur["path"]).name.lower()
        notes = []
        for prev in inputs[:i]:
            pname = Path(prev["path"]).name
            if pname.lower() == name:
                same = prev["sha256"] == cur["sha256"]
                notes.append(f"{'same content as' if same else 'different content from'} load #{prev['id']}")
            elif prev["sha256"] == cur["sha256"]:
                notes.append(f"same content as load #{prev['id']} ({pname}); records are loaded twice")
        cur["file"] = Path(cur["path"]).name
        cur["repeat"] = "; ".join(notes)
    return inputs


def _line(v, cleaned):
    """One typed value without control or invisible characters; notes in cleaned when any went."""
    raw = str(v if v is not None else "").strip()
    out = clean_line(raw)
    if out != raw:
        cleaned.append(raw)
    return out


def clean_safe_settings(cfg):
    """Safe settings typed on the pages or in the JSON: no control or invisible characters.
    Returns how many values changed."""
    cleaned = []
    for body in [cfg.get("safe_defaults") or {}] + list(cfg.get("safe_rules") or []):
        for k in ("description", "location", "managingCPM"):
            if isinstance(body.get(k), str):
                body[k] = _line(body[k], cleaned)
    return len(cleaned)


def check_settings(cfg):
    """Regexes and Safe settings must be usable before they are saved."""
    import re as _re

    def rx(pattern, where):
        try:
            _re.compile(pattern or "")
        except _re.error as exc:
            raise UiError(f"{where}: '{pattern}' is not a valid pattern ({exc}).")
    for name, layer in (cfg["safe_convention"].get("layers") or {}).items():
        if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise UiError(f"Placeholder name '{name}' can only use letters, digits and _.")
        if name in ("folder", "folder_leaf", "type", "convention", "folder_abbrev"):
            raise UiError(f"{{{name}}} is a built-in placeholder; pick another name.")
        for r in layer.get("rules") or []:
            rx(r.get("pattern"), f"{{{name}}} rule")
            if r.get("field2"):
                rx(r.get("pattern2"), f"{{{name}}} rule")
    for src in cfg.get("directory_sources") or []:
        if str(src.get("match", "")).lower().startswith("re:"):
            rx(src["match"][3:], "Directory source match")
        if src.get("find"):
            rx(src["find"], "Directory source find")
    for row in cfg.get("domain_map") or []:
        to = str(row.get("to") or "").strip().lstrip("@")
        if not str(row.get("from") or "").strip():
            raise UiError("Each domain conversion row needs the source domain(s) it converts, or *.")
        if to and not _re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*", to):
            raise UiError(f"'{to}' is not a domain name (for example corp.example.com).")
    for rule in cfg.get("safe_rules") or []:
        rx(rule.get("safe_pattern"), "Safe settings rule")
        if str(rule.get("numberOfVersionsRetention", "")).strip() and str(rule.get("numberOfDaysRetention", "")).strip():
            raise UiError("A Safe keeps either a number of versions or a number of days, not both.")
    d = cfg["safe_defaults"]
    if str(d.get("numberOfVersionsRetention", "")).strip() and str(d.get("numberOfDaysRetention", "")).strip():
        raise UiError("Safes keep either a number of versions or a number of days, not both.")
    for rule in cfg.get("platform_rules") or []:
        rx(rule.get("pattern"), "Platform rule")
    std = cfg.get("standard_members") or {}
    if (std.get("apply_to") or "no_source_members") not in ("no_source_members", "all", "off"):
        raise UiError("Standard member groups: 'add to' must be no_source_members, all or off.")
    seen = set()
    for row in std.get("members") or []:
        name = clean_line(row.get("name"))
        if not name:
            raise UiError("Every standard member group row needs a name pattern, for example {safe}-Users.")
        bad = [p for p in STANDARD_PLACEHOLDERS.findall(name) if p != "safe"]
        if bad or name.count("{") != name.count("}"):
            raise UiError(f"Standard member group '{name}': the only placeholder is {{safe}}.")
        if (row.get("member_type") or "Group").strip().lower() not in ("user", "group", "role"):
            raise UiError(f"Standard member group '{name}': the member type must be User, Group or Role.")
        if not resolve_role(row.get("role"), cfg):
            raise UiError(f"Standard member group '{name}': pick a role (a preset or one of your custom roles).")
        if name.lower() in seen:
            raise UiError(f"The standard member group '{name}' is listed twice.")
        seen.add(name.lower())


def looks_like_permissions(path):
    """A CSV whose header has a group/user column and a permission column, and no password column
    (the Workbench layout, or a Delinea folder-permissions report)."""
    if path.suffix.lower() != ".csv" or reference_kind(path):
        return False
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            header = [h.strip().lower() for h in fh.readline().split(",")]
    except OSError:
        return False
    header = [h.strip('"').strip() for h in header]
    who = {c.lower() for c in PERM_GROUP_COLUMNS + PERM_USER_COLUMNS}
    roles = {c.lower() for c in PERM_ROLE_COLUMNS}
    return (any(h in who for h in header) and any(h in roles for h in header)
            and not any("password" in h for h in header))


def secure_delete(path, chunk=1 << 20):
    """Overwrite then delete. Best effort: SSDs and some file systems keep old copies.
    Writes zeros in 1 MB blocks, so a large file does not need its size in memory."""
    size = path.stat().st_size
    zeros = b"\0" * min(chunk, size or 1)
    with open(path, "r+b") as fh:
        left = size
        while left > 0:
            n = fh.write(zeros[:min(left, len(zeros))])
            left -= n
        fh.flush()
        os.fsync(fh.fileno())
    path.unlink()


class App:
    def __init__(self, workspace, protector_flag=None, authenticator=None):
        self.ws = Path(workspace).resolve()
        self.inbox = self.ws / "inbox"
        self.output = self.ws / "output"
        self.db_path = self.ws / "migration.db"
        try:
            has_db = self.db_path.exists()
        except PermissionError:
            has_db = False                       # claim_workspace explains
        if has_db:
            Store(self.db_path).close()          # refuses another user's database before anything starts
        # Only the Windows user who created the workspace may use it; it is locked to that user.
        self.owner = claim_workspace(self.ws)
        for d in (self.inbox, self.output):
            d.mkdir(parents=True, exist_ok=True)
        self.config_path = self.ws / "config.json"
        self.protector_flag = protector_flag
        self.lock = threading.RLock()
        self.launch_token = secrets.token_urlsafe(32)
        self.sid = None
        self.last_seen = 0.0
        self.unlocked = False
        self.auth = authenticator or get_authenticator()
        self.failures = 0
        self.wait_until = 0.0
        self.httpd = None
        self.peer_check = peer_is_owner

    # -- helpers ----------------------------------------------------------
    def store(self, create=False):
        if not self.db_path.exists() and not create:
            raise UiError("No data yet. Start with step 1, Load exports.", 409)
        protector = None
        if create and not self.db_path.exists():
            if self.protector_flag:
                protector = self.protector_flag
            elif sys.platform != "win32":
                raise UiError("Secrets are protected with Windows DPAPI, which needs Windows. Start the "
                              "UI with --no-secrets or --insecure-plaintext-secrets on this machine.")
        return Store(self.db_path, create=create, protector=protector)

    def config(self):
        if self.config_path.exists():
            return load_config(self.config_path)
        return load_config(None)

    def user_config(self):
        if self.config_path.exists():
            return json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        return {}

    # -- API --------------------------------------------------------------
    def api_state(self, _body):
        state = {"version": __version__, "workspace": str(self.ws), "inbox": str(self.inbox),
                 "output": str(self.output), "has_db": self.db_path.exists(),
                 "sources": {k: v.description for k, v in ADAPTERS.items()},
                 "inbox_files": [], "outputs": [], "views": {k: v[0] for k, v in VIEWS.items()},
                 "kinds": {k: {"label": v, "help": KIND_HELP[k], "used": k in USED_KINDS} for k, v in KINDS.items()}}
        for f in sorted(self.inbox.iterdir()):
            if f.is_file():
                try:
                    guess = detect_adapter(f).name
                except AdapterError:
                    guess = ""
                ref = reference_kind(f)
                perm = looks_like_permissions(f)
                kind = ref or ("permissions" if perm else "accounts" if guess else "")
                state["inbox_files"].append({"name": f.name, "size": f.stat().st_size, "guess": guess,
                                             "permissions": perm, "kind": kind})
        for d in sorted(self.output.iterdir(), reverse=True):
            if d.is_dir():
                man = d / "manifest.json"
                info = json.loads(man.read_text()) if man.exists() else {}
                state["outputs"].append({"name": d.name, "created": info.get("created_utc", ""),
                                         "secrets": info.get("includes_secrets", False),
                                         "counts": info.get("counts", {}),
                                         "has_upload": (d / "upload").exists()})
        if state["has_db"]:
            st = self.store()
            try:
                state["protector"] = st.meta("protector")
                state["mapped"] = st.meta("mapped_utc")
                state["records"] = st.db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                state["inputs"] = compare_inputs([dict(r) for r in st.db.execute(
                    "SELECT id, source, path, sha256, records, permissions_path, permissions_sha256, "
                    "loaded_utc, loaded_by FROM inputs ORDER BY id")])
                counts = {r[0]: r[1] for r in st.db.execute(
                    "SELECT status, COUNT(*) FROM plan_accounts GROUP BY status")}
                state["status_counts"] = counts
                state["approved"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_accounts WHERE status = 'REVIEW' AND approved = 'Y'").fetchone()[0]
                state["excluded"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'N'").fetchone()[0]
                state["to_upload"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'Y' AND status <> 'ERROR'").fetchone()[0]
                state["safes"] = st.db.execute("SELECT COUNT(*) FROM plan_safes").fetchone()[0]
                state["invalid_safes"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_safes WHERE valid_safe_name = 'FALSE'").fetchone()[0]
                state["edits"] = st.db.execute("SELECT COUNT(DISTINCT record_id) FROM edits").fetchone()[0]
                state["sanitized"] = st.db.execute(
                    "SELECT COUNT(*) FROM accounts WHERE " + VIEWS["sanitized"][1]).fetchone()[0]
                state["member_edits"] = st.db.execute("SELECT COUNT(*) FROM member_edits").fetchone()[0]
                state["undecided"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_undecided WHERE decision = ''").fetchone()[0]
                state["undecided_all"] = st.db.execute("SELECT COUNT(*) FROM plan_undecided").fetchone()[0]
                state["references"] = {k: st.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                                       for k, t in (("templates", "ref_templates"), ("users", "ref_users"))}
                state["stale"] = bool(st.db.execute(
                    "SELECT COUNT(*) FROM records WHERE record_id NOT IN (SELECT record_id FROM plan_accounts)"
                ).fetchone()[0])
            finally:
                st.close()
            self._mark_loaded(state)
        return state

    def _mark_loaded(self, state):
        """Tell the Load page which inbox files are already loaded, with the same or changed content."""
        known = {}
        for i in state.get("inputs") or []:
            known[Path(i["path"]).name.lower()] = i["sha256"]
            for pth, sha in zip((i.get("permissions_path") or "").split(" | "), (i.get("permissions_sha256") or "").split(" | ")):
                if pth:
                    known[Path(pth).name.lower()] = sha
        cache = self.__dict__.setdefault("_sha_cache", {})
        for f in state["inbox_files"]:
            sha = known.get(f["name"].lower())
            if not sha:
                continue
            path = self.inbox / f["name"]
            try:
                st = path.stat()
                key = (str(path), st.st_size, st.st_mtime_ns)
                if key not in cache:
                    cache[key] = sha256_file(path)
                f["loaded"] = "same" if cache[key] == sha else "changed"
            except OSError:
                pass

    def api_ingest(self, body):
        files = body.get("files") or []
        refs = body.get("references") or []
        if not files and not refs:
            raise UiError("Pick at least one export file.")
        cfg = self.config()
        perm_names = body.get("permissions") or []
        if isinstance(perm_names, str):
            perm_names = [perm_names]
        perm_paths = [self._inbox_file(n) for n in perm_names]
        try:
            perms = Permissions([str(p) for p in perm_paths]) if perm_paths else None
        except (ValueError, OSError) as exc:
            raise UiError(f"Permissions file: {exc}")
        results = []
        st = self.store(create=True)
        try:
            for f in refs:
                path = self._inbox_file(f["name"])
                kind = f.get("kind") or reference_kind(path)
                if kind not in USED_KINDS:
                    raise UiError(f"{path.name} is not a template list or users list")
                rows = (read_templates if kind == "templates" else read_users)(path)
                n = st.ingest_reference(kind, path, rows)
                results.append({"name": f["name"], "source": kind, "records": n, "replaced": 0, "sanitized": 0})
            for f in files:
                path = self._inbox_file(f["name"])
                adapter = get_adapter(f["source"]) if f.get("source") else detect_adapter(path)
                records = list(adapter.read(path, cfg))
                n, replaced = st.ingest(adapter.name, path, records, perms, [str(p) for p in perm_paths])
                result = {"name": f["name"], "source": adapter.name, "records": n, "replaced": replaced,
                          "sanitized": st.last_sanitized}
                # A spreadsheet whose headers the Workbench didn't recognise: offer the column picker.
                missing = [k for k in ("username", "address") if records and not any(getattr(r, k) for r in records)]
                if missing and hasattr(adapter, "column_report"):
                    headers, current = adapter.column_report(path, cfg)
                    result["columns"] = {"missing": missing, "headers": headers, "current": current}
                results.append(result)
            st.map(cfg, str(self.config_path) if self.config_path.exists() else None)
        except (AdapterError, ValueError, OSError, ProtectError, StoreError) as exc:
            raise UiError(f"{exc}")
        finally:
            st.close()
        return {"results": results, "protector": self.protector_flag or "dpapi"}

    def api_undecided(self, _body):
        """Users from the users report who may get their access through a group (one row per
        folder, Safe and user), with your decision."""
        if not self.db_path.exists():
            return {"rows": []}
        st = self.store()
        try:
            rows = [dict(r) for r in st.db.execute(
                "SELECT folder, safe_name, member, member_name, permission, groups, accounts, decision, notes "
                "FROM plan_undecided ORDER BY groups, member, folder")]
        finally:
            st.close()
        return {"rows": rows}

    def api_decide(self, body):
        items = [(i.get("folder") or "", i.get("member") or "") for i in body.get("items") or []]
        if not items:
            raise UiError("Tick at least one user first.")
        decision = body.get("decision") or ""
        st = self.store()
        try:
            n = st.set_decisions(items, decision, body.get("reason") or "")
            st.map(self.config(), str(self.config_path) if self.config_path.exists() else None)
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": n}

    def _inbox_file(self, name):
        path = (self.inbox / name).resolve()
        if path.parent != self.inbox or not path.is_file():
            raise UiError(f"{name} is not in the inbox folder")
        return path

    def api_inbox_delete(self, body):
        path = self._inbox_file(body.get("name", ""))
        secure_delete(path)
        return {"deleted": path.name}

    def api_config_get(self, _body):
        cfg = self.config()
        hints = {"types_without_platform": [], "groups": [], "folders": [], "columns": []}
        used_platforms = []
        if self.db_path.exists():
            st = self.store()
            try:
                hints["types_without_platform"] = [r[0] for r in st.db.execute(
                    "SELECT DISTINCT source_type FROM plan_accounts WHERE platform_id = '' "
                    "ORDER BY 1")]
                hints["groups"] = [{"name": r[0], "accounts": r[1]} for r in st.db.execute(
                    "SELECT member, COUNT(DISTINCT record_id) FROM grants GROUP BY lower(member) "
                    "ORDER BY 2 DESC LIMIT 200")]
                hints["folders"] = [{"name": r[0], "accounts": r[1]} for r in st.db.execute(
                    "SELECT folder, COUNT(*) FROM records GROUP BY folder ORDER BY 1 LIMIT 500")]
                hints["types"] = [{"name": r[0], "accounts": r[1]} for r in st.db.execute(
                    "SELECT type, COUNT(*) FROM records GROUP BY type ORDER BY 2 DESC")]
                used_platforms = [r[0] for r in st.db.execute(
                    "SELECT DISTINCT platform_id FROM plan_accounts WHERE platform_id <> ''")]
                hints["columns"] = self._source_columns(st)
                hints["records"] = st.db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                hints["without_folder"] = st.db.execute(
                    "SELECT COUNT(*) FROM records WHERE folder_json IN ('', '[]')").fetchone()[0]
                hints["with_grants"] = st.db.execute("SELECT COUNT(DISTINCT record_id) FROM grants").fetchone()[0]
            finally:
                st.close()
        hints["platforms"] = self._platform_ids(cfg, used_platforms)
        return {"config": cfg, "defaults": DEFAULT_CONFIG, "hints": hints, "saved": self.config_path.exists(),
                "presets": PERMISSION_PRESETS, "permissions": ALL_PERMISSIONS,
                "standard_member_set": STANDARD_MEMBER_SET}

    @staticmethod
    def _source_columns(st):
        """Every extra source column in the loaded records (the columns not used for the
        name, address, username, folder...), with how many records have a value in it."""
        counts = {}
        for (extra,) in st.db.execute("SELECT extra_json FROM records"):
            for k, v in json.loads(extra or "{}").items():
                n = counts.setdefault(k, [0, 0])
                n[0] += 1
                n[1] += 1 if str(v or "").strip() else 0
        return [{"name": k, "records": n[0], "filled": n[1]}
                for k, n in sorted(counts.items(), key=lambda kv: kv[0].lower())]

    @staticmethod
    def _platform_ids(cfg, used=()):
        """Platform IDs to suggest: the usual Privilege Cloud IDs plus every one already in use."""
        ids = {p: "standard Privilege Cloud platform" for p in DEFAULT_PLATFORM_CODES}
        for p in list(cfg.get("platform_map", {}).values()) + [r.get("platform", "") for r in cfg.get("platform_rules") or []] \
                + [cfg.get("default_platform") or ""]:
            if p and p not in ids:
                ids[p] = "used in your rules"
        for p in used:
            if p and p not in ids:
                ids[p] = "used by loaded accounts"
        return [{"id": k, "note": v} for k, v in sorted(ids.items(), key=lambda kv: kv[0].lower())]

    def _naming_samples(self, st, cfg, limit=400):
        """Generated convention names for the distinct folder/platform/username combinations."""
        namer = Namer(cfg)
        rows = st.db.execute(
            "SELECT r.folder_json, r.folder, r.type, r.username, p.platform_id, MIN(r.address) AS address, "
            "MIN(r.name) AS name, MIN(r.source) AS source, MIN(r.extra_json) AS extra_json, COUNT(*) AS n "
            "FROM records r JOIN plan_accounts p USING (record_id) "
            "GROUP BY r.folder_json, p.platform_id, r.username ORDER BY r.folder LIMIT ?", (limit,)).fetchall()
        out, seen = [], set()
        for r in rows:
            rec = SourceRecord(source=r["source"] or "", source_file="", source_id="", source_ref="",
                               folder=tuple(json.loads(r["folder_json"])), type=r["type"], username=r["username"],
                               address=r["address"] or "", name=r["name"] or "",
                               extra=json.loads(r["extra_json"] or "{}"))
            name, notes = namer.build(rec, r["platform_id"])
            key = (r["folder"], name)
            if key in seen:
                continue
            seen.add(key)
            out.append({"folder": r["folder"], "platform": r["platform_id"], "name": name,
                        "length": len(name), "notes": "; ".join(notes)})
        unknown = [{"word": w, "code": c} for w, c in sorted(namer.unknown.items(), key=lambda x: x[0].lower())]
        return out, unknown

    def _folder_codes(self, st, cfg):
        """Every distinct folder name in the loaded data with the code it gets."""
        counts = {}
        for folder_json, n in st.db.execute("SELECT folder_json, COUNT(*) FROM records GROUP BY folder_json"):
            for level in set(json.loads(folder_json)):
                counts[level] = counts.get(level, 0) + n
        return Namer(cfg).suggest(counts)

    def api_naming_preview(self, body):
        user = body.get("config")
        if not isinstance(user, dict):
            raise UiError("config must be a JSON object")
        try:
            cfg = config_from_dict(user)
        except Exception as exc:  # noqa: BLE001
            raise UiError(f"config is not valid: {exc}")
        if not self.db_path.exists():
            return {"samples": [], "unknown": [], "folder_codes": []}
        st = self.store()
        try:
            samples, unknown = self._naming_samples(st, cfg)
            folder_codes = self._folder_codes(st, cfg)
        finally:
            st.close()
        return {"samples": samples, "unknown": unknown, "folder_codes": folder_codes}

    VALUE_FIELDS = ("address_domain", "type", "platform")
    MAX_LAYER_VALUES = 300

    def api_rules_values(self, body):
        """The distinct values of one account detail in the loaded records, with how many
        accounts have each and a suggested 1-4 letter code, so a Safe name placeholder can be
        built from them (Mapping rules A: "Build Safe names from account details").
        field: column:<source column>, address_domain, type or platform."""
        field = str(body.get("field") or "").strip()
        if not (field.startswith("column:") and field[7:].strip()) and field not in self.VALUE_FIELDS:
            raise UiError("Pick a source column or account detail first.")
        user = body.get("config")
        cfg = config_from_dict(user) if isinstance(user, dict) else self.config()
        counts, empty = {}, 0
        if self.db_path.exists():
            st = self.store()
            try:
                rows = st.db.execute("SELECT r.address, r.type, r.username, r.extra_json, p.platform_id "
                                     "FROM records r LEFT JOIN plan_accounts p USING (record_id)").fetchall()
            finally:
                st.close()
            want = field[7:].strip().lower() if field.startswith("column:") else ""
            for r in rows:
                if want:
                    extra = json.loads(r["extra_json"] or "{}")
                    v = next((str(x) for k, x in extra.items() if k.lower() == want), "")
                elif field == "address_domain":
                    v = address_domain(r["address"])
                elif field == "platform":
                    v = r["platform_id"] or ""
                else:
                    v = r["type"] or ""
                v = clean_line(v)
                if not v:
                    empty += 1
                    continue
                key = v.lower()
                c = counts.setdefault(key, [v, 0])
                c[1] += 1
        namer = Namer(cfg)
        values, by_code = [], {}
        for v, n in sorted(counts.values(), key=lambda x: (-x[1], x[0].lower())):
            pairs = namer.level_codes(v.split(".")[0] if field == "address_domain" else v)
            codes = [c for _, c in pairs if c]
            code = codes[0] if len(codes) == 1 else "".join(c[0] for c in codes)[:4]
            row = {"value": v, "accounts": n, "code": code.upper(), "clash": ""}
            other = by_code.get(row["code"])
            if other:
                row["clash"] = other
            by_code.setdefault(row["code"], v)
            values.append(row)
        return {"field": field, "values": values[: self.MAX_LAYER_VALUES], "distinct": len(values),
                "empty": empty, "too_many": len(values) > self.MAX_LAYER_VALUES}

    PREVIEW_KINDS = ("safes", "members", "platforms", "accounts")

    def api_safes_preview(self, body):
        return self.api_rules_preview(dict(body, kind="safes"))

    def api_rules_preview(self, body):
        """What a mapping rules page's settings would give, before they are saved. Runs the
        full rules (exceptions, prefix, your own changes to Safes, members and accounts) on
        the loaded records, without secrets, and writes nothing. kind picks the view:
        safes (folder -> Safe and its CPM/settings), members (Safe members and roles),
        platforms (record type -> platform), accounts (account names and properties).
        Each row lists in "changed" the fields that differ from what is saved and applied now."""
        kind = body.get("kind") or "safes"
        if kind not in self.PREVIEW_KINDS:
            raise UiError(f"unknown preview {kind}")
        user = body.get("config")
        if isinstance(body.get("patch"), dict):
            user = self.config()
            user.update(body["patch"])
        if not isinstance(user, dict):
            raise UiError("config must be a JSON object")
        try:
            cfg = config_from_dict(user)
        except Exception as exc:  # noqa: BLE001
            raise UiError(f"config is not valid: {exc}")
        check_settings(cfg)
        check_roles(cfg)
        empty = {"kind": kind, "rows": [], "folder_codes": [], "safes": 0, "accounts": 0, "total_rows": 0}
        if not self.db_path.exists():
            return empty
        limit = max(1, min(int(body.get("limit") or 500), 2000))
        st = self.store()
        try:
            try:
                plan = st.plan(cfg)
            except re.error as exc:
                raise UiError(f"A pattern on this page is not valid: {exc}")
            saved = {"accounts": {r["record_id"]: dict(r) for r in st.db.execute("SELECT * FROM plan_accounts")},
                     "safes": {r["safe_name"]: dict(r) for r in st.db.execute("SELECT * FROM plan_safes")},
                     "members": {(r["safe_name"].lower(), (r["source_member"] or "").lower()): dict(r)
                                 for r in st.db.execute("SELECT * FROM plan_members")}}
            if kind == "accounts":
                saved["source_address"] = dict(st.db.execute("SELECT record_id, address FROM records"))
            folder_codes = self._folder_codes(st, cfg) if kind == "safes" else []
        finally:
            st.close()
        rows = getattr(self, f"_preview_{kind}")(plan, cfg, saved)
        return {"kind": kind, "rows": rows[:limit], "total_rows": len(rows), "safes": len(plan.safes),
                "accounts": len(plan.accounts), "folder_codes": folder_codes}

    @staticmethod
    def _preview_safes(plan, cfg, saved):
        settings = {}
        for name, info in plan.safes.items():
            b = safe_settings(name, info, cfg)
            if str(b.get("numberOfVersionsRetention", "")).strip():
                keeps = f"{b['numberOfVersionsRetention']} versions"
            elif str(b.get("numberOfDaysRetention", "")).strip():
                keeps = f"{b['numberOfDaysRetention']} days"
            else:
                keeps = ""
            settings[name] = {"cpm": b.get("managingCPM", "") or "", "keeps": keeps,
                              "description": b.get("description", "") or "",
                              "issues": "; ".join(sorted(info["issues"])), "valid": info["valid"],
                              "accounts": info["accounts"]}
        saved_safe = {}
        for a in saved["accounts"].values():
            saved_safe.setdefault(a["folder"], set()).add(a["target_safe"])
        groups = {}
        for p in plan.accounts:
            g = groups.setdefault((p.rec.folder_path, p.safe), {"accounts": 0, "how": set()})
            g["accounts"] += 1
            g["how"].add(p.safe_source)
        rows = []
        for (folder, safe), g in sorted(groups.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1].lower())):
            s = settings[safe]
            before, old = saved_safe.get(folder), saved["safes"].get(safe)
            changed = []
            if before is not None and safe not in before:
                changed.append("safe")
            if old:
                for key, col in (("cpm", "managing_cpm"), ("keeps", "retention"), ("description", "description")):
                    if (old.get(col) or "") != s[key]:
                        changed.append(key)
            rows.append({"folder": folder, "safe": safe, "length": len(safe), "accounts": g["accounts"],
                         "how": sorted(g["how"]), "cpm": s["cpm"], "keeps": s["keeps"],
                         "description": s["description"], "issues": s["issues"], "valid": s["valid"],
                         "changed": changed})
        return rows

    @staticmethod
    def _preview_members(plan, cfg, saved):
        rows = []
        for (safe, _), m in plan.members.items():
            sources = m.get("sources") or [m["source_name"]]
            old = None
            for src in sources:
                old = old or saved["members"].get((safe.lower(), (src or "").lower()))
            shown = " | ".join(sources)
            if m.get("standard"):
                shown = f"(standard member group {m.get('template', '')})"
            row = {"safe": safe, "source": shown, "standard": bool(m.get("standard")), "member_name": m["member_name"],
                   "member_type": m["member_type"], "search_in": m["search_in"],
                   "permission": m["permission"], "role": m["role"] or "UNMAPPED", "accounts": m["accounts"],
                   "directory_source": m.get("directory_source", ""), "notes": "; ".join(m["notes"])}
            row["changed"] = ["new"] if old is None and (saved["members"] or m.get("standard")) else [
                k for k, col in (("member_name", "member_name"), ("role", "role"), ("search_in", "search_in"),
                                 ("member_type", "member_type")) if old and (old.get(col) or "") != (row[k] or "")]
            rows.append(row)
        rows.sort(key=lambda r: (r["safe"].lower(), r["member_name"].lower()))
        return rows

    @staticmethod
    def _preview_platforms(plan, cfg, saved):
        groups = {}
        for p in plan.accounts:
            key = (p.rec.type, p.platform, p.platform_source)
            g = groups.setdefault(key, {"accounts": 0, "changed": 0, "folders": set(), "errors": 0})
            g["accounts"] += 1
            g["folders"].add(p.rec.folder_path)
            g["errors"] += 1 if p.errors else 0
            old = saved["accounts"].get(p.rec.record_id)
            if old and (old.get("platform_id") or "") != p.platform:
                g["changed"] += 1
        rows = []
        for (rtype, platform, how), g in sorted(groups.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1].lower())):
            folders = sorted(g["folders"])
            rows.append({"type": rtype, "platform": platform, "how": how, "accounts": g["accounts"],
                         "errors": g["errors"], "moved": g["changed"],
                         "folders": "; ".join(folders[:3]) + (f" and {len(folders) - 3} more" if len(folders) > 3 else ""),
                         "changed": ["platform"] if g["changed"] else []})
        return rows

    @staticmethod
    def _preview_accounts(plan, cfg, saved):
        props = cfg.get("account_property_map") or {}
        rows = []
        for p in plan.accounts:
            old = saved["accounts"].get(p.rec.record_id)
            extra = {k.lower(): v for k, v in (p.rec.extra or {}).items()}
            row = {"record_id": p.rec.record_id, "source_name": p.rec.name, "address": p.rec.address,
                   "source_address": saved.get("source_address", {}).get(p.rec.record_id, p.rec.address),
                   "username": p.rec.username, "safe": p.safe, "platform": p.platform,
                   "account_name": p.account_name,
                   "properties": "; ".join(f"{prop}={extra[col.lower()]}" for col, prop in props.items()
                                           if str(extra.get(col.lower(), "")).strip()),
                   "notes": "; ".join(p.errors + p.warnings)}
            row["changed"] = [k for k, col in (("account_name", "account_name"), ("address", "address"))
                              if old and (old.get(col) or "") != (row[k] or "")]
            rows.append(row)
        rows.sort(key=lambda r: (bool(not r["changed"]), r["safe"].lower(), (r["account_name"] or "").lower()))
        return rows


    def api_config_save(self, body):
        user = body.get("config")
        if isinstance(body.get("patch"), dict):
            # One settings page saves only its own keys on top of everything else.
            user = self.config()
            user.update(body["patch"])
        if not isinstance(user, dict):
            raise UiError("config must be a JSON object")
        tmp = self.config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(user, indent=2), encoding="utf-8")
        try:
            cfg = load_config(tmp)
            cleaned = clean_safe_settings(cfg)
            for rule in cfg["group_rules"]:
                if not rule.get("safe") or not (rule.get("group") or rule.get("group_pattern")):
                    raise UiError("Every group rule needs a group (or pattern) and a Safe.")
            for rule in cfg["folder_rules"]:
                if not rule.get("safe") or not rule.get("folder_prefix"):
                    raise UiError("Every folder rule needs a folder and a Safe.")
            check_roles(cfg)
            check_settings(cfg)
        except UiError:
            tmp.unlink()
            raise
        except Exception as exc:  # noqa: BLE001
            tmp.unlink()
            raise UiError(f"config is not valid: {exc}")
        # Keep only what differs from the built-in defaults, so later default updates apply.
        tmp.write_text(json.dumps(config_diff(cfg), indent=2), encoding="utf-8")
        tmp.replace(self.config_path)
        if not self.db_path.exists():
            return {"saved": True, "mapped": False, "cleaned": cleaned}
        st = self.store()
        try:
            st.map(cfg, str(self.config_path))
        finally:
            st.close()
        return {"saved": True, "mapped": True, "cleaned": cleaned}

    def api_accounts(self, body):
        where, params = build_where(body)
        sort = body.get("sort") if body.get("sort") in SORTABLE else "target_safe"
        order = "DESC" if body.get("desc") else "ASC"
        page = max(0, int(body.get("page") or 0))
        st = self.store()
        try:
            total = st.query(f"SELECT COUNT(*) FROM accounts WHERE {where}", params)[1][0][0]
            cols, rows = st.query(
                f"SELECT record_id, migrate, status, target_safe, platform_id, account_name, address, "
                f"username, secret_type, has_secret, source, folder, access_groups, notes, approved, source_type, "
                f"(SELECT r.name FROM records r WHERE r.record_id = accounts.record_id) AS source_name, "
                f"(SELECT r.address FROM records r WHERE r.record_id = accounts.record_id) AS source_address FROM accounts "
                f"WHERE {where} ORDER BY {sort} {order}, record_id LIMIT ? OFFSET ?",
                params + [PAGE_SIZE, page * PAGE_SIZE])
            facets = {}
            for key, col in FILTER_COLUMNS.items():
                facets[key] = [r[0] for r in st.query(f"SELECT DISTINCT {col} FROM accounts ORDER BY 1")[1]]
        finally:
            st.close()
        return {"total": total, "page": page, "page_size": PAGE_SIZE,
                "rows": [dict(zip(cols, r)) for r in rows], "facets": facets}

    def api_record(self, body):
        rid = body.get("id", "")
        st = self.store()
        try:
            rec = st.db.execute("SELECT * FROM records WHERE record_id = ?", (rid,)).fetchone()
            plan = st.db.execute("SELECT * FROM plan_accounts WHERE record_id = ?", (rid,)).fetchone()
            if not rec:
                raise UiError("record not found", 404)
            out = {k: rec[k] for k in rec.keys() if k != "secret_enc"}
            out["extra"] = json.loads(out.pop("extra_json"))
            out["notes_source"] = json.loads(out.pop("notes_json"))
            out.pop("folder_json")
            out["plan"] = dict(plan) if plan else {}
            out["grants"] = [dict(g) for g in st.db.execute(
                "SELECT member, permission, member_type FROM grants WHERE record_id = ?", (rid,))]
            out["edits"] = [dict(e) for e in st.db.execute(
                "SELECT field, value, changed_utc, changed_by, reason FROM edits WHERE record_id = ?", (rid,))]
            appr = st.db.execute("SELECT approved_utc, approved_by, reason FROM approvals WHERE record_id = ?",
                                 (rid,)).fetchone()
            out["approval"] = dict(appr) if appr and out["plan"].get("approved") == "Y" else None
        finally:
            st.close()
        return out

    def api_edit(self, body):
        values = body.get("values") or {}
        if any(k not in EDITABLE for k in values):
            raise UiError("only Migrate, Safe, platform and account name can be changed")
        if "migrate" in values and values["migrate"] not in ("Y", "N", ""):
            raise UiError("Migrate must be Y or N")
        cleaned = []
        for k in ("target_safe", "platform_id", "account_name"):
            if isinstance(values.get(k), str):
                values[k] = _line(values[k], cleaned)
        st = self.store()
        try:
            if body.get("ids"):
                ids = list(body["ids"])
            else:
                where, params = build_where(body)
                ids = st.select_ids(where, params)
            if not ids:
                raise UiError("No accounts selected.")
            if len(ids) > 1 and values.get("account_name") and values["account_name"].lower() != "(none)":
                raise UiError("Rename one account at a time.")
            st.set_edits(ids, values, body.get("reason") or "")
            st.map(st.stored_config(), st.meta("config_path"))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": len(ids), "cleaned": len(cleaned)}

    def api_approve(self, body):
        """Approve the ticked accounts that need a look, or take the approval back. The
        approval lasts until anything about the account changes."""
        approve = body.get("approve", True) is not False
        st = self.store()
        try:
            if body.get("ids"):
                ids = list(body["ids"])
            else:
                where, params = build_where(body)
                ids = st.select_ids(where, params)
            if not ids:
                raise UiError("No accounts selected.")
            n = st.approve(ids, approve, _line(str(body.get("reason") or ""), []))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": n, "selected": len(ids)}

    def api_safes(self, _body):
        st = self.store()
        try:
            cols, rows = st.query(
                "SELECT s.*, (SELECT group_concat(folder, ' | ') FROM (SELECT DISTINCT folder FROM plan_accounts a "
                "WHERE a.target_safe = s.safe_name ORDER BY folder)) AS source_folders FROM plan_safes s ORDER BY safe_name")
            mcols, mrows = st.query("SELECT * FROM plan_members ORDER BY safe_name, member_name")
            edits = st.member_edits()
            overrides = st.member_overrides()
            safe_ov = st.safe_overrides()
            # Users waiting for your decision are listed on their own page, not here.
            grants = st.db.execute("SELECT member, max(member_type) AS member_type, COUNT(DISTINCT record_id) AS n "
                                   "FROM grants WHERE coalesce(basis, '') <> 'undecided' "
                                   "GROUP BY lower(member)").fetchall()
            refs = st.references()
        finally:
            st.close()
        cfg = self.config()
        roles = list(all_roles(cfg))
        members = [dict(zip(mcols, r)) for r in mrows]
        return {"safes": [dict(zip(cols, r)) for r in rows], "members": members, "member_edits": edits,
                "safe_overrides": sorted(safe_ov.values(), key=lambda o: o.get("changed_utc") or ""),
                "people": self._people(members, grants, overrides, cfg, refs),
                "roles": roles, "directories": sorted({m["search_in"] for m in members if m["search_in"]} | {"Vault"}),
                "known_members": sorted({m["member_name"] for m in members}, key=str.lower)}

    @staticmethod
    def _people(members, grants, overrides, cfg, refs=None):
        """One row per member (user, group or role), with the Safes it is on. Members from the
        export whose accounts are not uploaded are listed too, with no Safes."""
        in_export = {r["member"].lower(): r["n"] for r in grants}
        people = {}
        for m in members:
            # A merged row lists several source members ("CORP\\X | LEGACY\\X"); each one is
            # its own person here, so a change (keyed by source member) reaches the right one.
            for source in (m["source_member"] or m["member_name"]).split(" | "):
                key = source.lower()
                p = people.setdefault(key, {
                    "key": key, "source_member": source, "member_name": m["member_name"],
                    "member_type": m["member_type"], "search_in": m["search_in"],
                    "directory_source": m["directory_source"], "export_accounts": in_export.get(key, 0),
                    "edited": key in overrides, "override": overrides.get(key), "safes": []})
                p["safes"].append({"safe_name": m["safe_name"], "role": m["role"], "accounts": m["accounts"],
                                   "source_permission": m["source_permission"], "notes": m["notes"]})
        default_type = normalize_member_type(cfg["default_member_type"])
        for r in grants:
            key = r["member"].lower()
            if key in people:
                continue
            mtype = normalize_member_type(r["member_type"], default_type)
            name, search_in, src = target_for(r["member"], cfg, mtype, refs)
            m = apply_member_override({"source_name": r["member"], "member_name": name, "member_type": mtype,
                                       "type": mtype, "search_in": search_in,
                                       "directory_source": src or "default"}, overrides.get(key))
            people[key] = {"key": key, "source_member": r["member"], "member_name": m["member_name"],
                           "member_type": m["member_type"], "search_in": m["search_in"],
                           "directory_source": m["directory_source"], "export_accounts": r["n"],
                           "edited": key in overrides, "override": overrides.get(key), "safes": []}
        return sorted(people.values(), key=lambda p: (p["member_name"] or "").lower())

    def api_members_change(self, body):
        """Change one member's memberName, memberType or searchIn everywhere (kept across re-mapping)."""
        key = (body.get("key") or "").strip()
        if not key:
            raise UiError("Pick a member first.")
        undo = bool(body.get("undo"))
        cleaned = []
        name = _line(body.get("member_name"), cleaned)
        mtype = (body.get("member_type") or "").strip()
        if mtype and mtype.lower() not in ("user", "group", "role"):
            raise UiError("Member type must be User, Group or Role.")
        search_in = body.get("search_in")
        search_in = None if search_in is None else _line(search_in, cleaned)
        if not undo and not name:
            raise UiError("The member name can't be empty.")
        st = self.store()
        try:
            st.set_member_override(key, name or None, normalize_member_type(mtype) if mtype else None,
                                   search_in, body.get("reason") or "", undo=undo)
            st.map(st.stored_config(), st.meta("config_path"))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": 1, "cleaned": len(cleaned)}

    def api_safes_change(self, body):
        """Rename one Safe, or change its description, location, CPM, retention, OLAC or auto purge.
        Kept across re-mapping and always wins over the rules. Empty fields keep the rules' value."""
        key = (body.get("key") or "").strip()
        current = (body.get("current") or "").strip()
        if not key:
            raise UiError("Pick a Safe first.")
        undo = bool(body.get("undo"))
        cfg = self.config()
        raw = body.get("settings") or {}
        settings, cleaned = {}, []
        new_name = str(raw.get("new_name") or "").strip()
        if new_name and new_name.lower() != key.lower():
            clean, valid, issues = sanitize_safe_name(new_name, cfg)
            if not valid:
                raise UiError(f"The Safe name '{new_name}' can't be used: {'; '.join(issues)}.")
            settings["new_name"] = clean
        for k in ("description", "location", "managingCPM"):
            v = _line(raw.get(k), cleaned)
            if v:
                settings[k] = v
        if len(settings.get("description", "")) > 100:
            raise UiError("The description can be at most 100 characters.")
        if len(settings.get("managingCPM", "")) > 20:
            raise UiError("The CPM name can be at most 20 characters.")
        kind, value = raw.get("retention_kind") or "", str(raw.get("retention_value") or "").strip()
        if kind and value:
            if not value.isdigit() or not (0 < int(value) <= (999 if kind == "versions" else 3650)):
                raise UiError("Keep: type a whole number (versions 1-999, days 1-3650).")
            settings["numberOfVersionsRetention" if kind == "versions" else "numberOfDaysRetention"] = int(value)
        for k in ("olacEnabled", "autoPurgeEnabled"):
            v = str(raw.get(k) or "").lower()
            if v in ("true", "false"):
                settings[k] = v == "true"
        if not undo and not settings:
            undo = True                         # nothing differs from the rules
        target = key if undo else settings.get("new_name", key)
        st = self.store()
        try:
            st.set_safe_override(key, settings, body.get("reason") or "", undo=undo,
                                 old_name=current or key, new_name=target)
            st.map(st.stored_config(), st.meta("config_path"))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": 1, "safe_name": target, "cleaned": len(cleaned)}

    def api_members_edit(self, body):
        """Add a member to, or remove one from, any number of Safes (kept across re-mapping)."""
        action = body.get("action")
        cleaned = []
        name = _line(body.get("member_name"), cleaned)
        pairs = body.get("pairs") or [[s, name] for s in body.get("safes") or []]
        if isinstance(pairs, list):
            pairs = [[p[0], _line(p[1], cleaned) if action == "add" else p[1]] if isinstance(p, list) and len(p) == 2 else p
                     for p in pairs]
        if not pairs or not all(isinstance(p, list) and len(p) == 2 and p[0] and p[1] for p in pairs):
            raise UiError("Tick at least one Safe and name the member.")
        role = (body.get("role") or "").strip()
        if action == "add":
            cfg = self.config()
            if not resolve_role(role, cfg):
                raise UiError("Pick the member's role.")
        st = self.store()
        try:
            n = 0
            by_member = {}
            for safe, member in pairs:
                by_member.setdefault(member, []).append(safe)
            for member, safes in by_member.items():
                n += st.set_member_edits(safes, member, action, _line(body.get("search_in"), cleaned),
                                         normalize_member_type(body.get("member_type")) if body.get("member_type") else "",
                                         role, body.get("reason") or "")
            st.map(st.stored_config(), st.meta("config_path"))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": n, "cleaned": len(cleaned)}

    def api_extract(self, body):
        name = "".join(c for c in (body.get("name") or "") if c.isalnum() or c in "-_ ").strip()
        if not name:
            name = time.strftime("%Y%m%d-%H%M%S")
        out = self.output / name
        if out.exists():
            if not body.get("replace"):
                raise UiError(f"An output called '{name}' already exists. Pick another name or tick Replace.")
            shutil.rmtree(out)
        include = bool(body.get("include_secrets"))
        if include and body.get("confirm") != "INCLUDE SECRETS":
            raise UiError("Type INCLUDE SECRETS to confirm.")
        where, params = (None, ())
        label = "everything"
        if body.get("scope") == "filter":
            where, params = build_where(body)
            label = json.dumps({"view": body.get("view"), "filters": body.get("filters")})
        st = self.store()
        try:
            plan, counts, files = run_extract(st, out, where, include, params, label)
        except (StoreError, ProtectError) as exc:
            shutil.rmtree(out, ignore_errors=True)
            raise UiError(str(exc))
        finally:
            st.close()
        return {"name": name, "path": str(out), "counts": counts,
                "files": [str(Path(f).relative_to(out)) for f in files] + ["manifest.json"]}

    def api_output_delete(self, body):
        name = body.get("name", "")
        path = (self.output / name).resolve()
        if path.parent != self.output or not path.is_dir():
            raise UiError("no such output")
        what = body.get("what", "upload")
        target = path / "upload" if what == "upload" else path
        if target.exists():
            for f in sorted(target.rglob("*"), reverse=True):
                if f.is_file():
                    secure_delete(f)
            shutil.rmtree(target, ignore_errors=True)
        return {"deleted": str(target)}

    def api_audit(self, _body):
        st = self.store()
        try:
            cols, rows = st.query("SELECT ts, user, action, detail FROM audit ORDER BY id DESC LIMIT 300")
            ecols, erows = st.query("SELECT * FROM edits ORDER BY changed_utc DESC LIMIT 500")
            summary = {
                "entries": st.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0],
                "first": st.db.execute("SELECT MIN(ts) FROM audit").fetchone()[0],
                "last": st.db.execute("SELECT MAX(ts) FROM audit").fetchone()[0],
                "by_action": [dict(r) for r in st.db.execute(
                    "SELECT action, COUNT(*) AS count, MAX(ts) AS last FROM audit GROUP BY action ORDER BY 2 DESC")],
                "by_user": [dict(r) for r in st.db.execute(
                    "SELECT user, COUNT(*) AS count, MIN(ts) AS first, MAX(ts) AS last FROM audit "
                    "GROUP BY user ORDER BY 2 DESC")],
                "edits": st.db.execute("SELECT COUNT(*) FROM edits").fetchone()[0],
                "edited_accounts": st.db.execute("SELECT COUNT(DISTINCT record_id) FROM edits").fetchone()[0],
                "edits_by_field": [dict(r) for r in st.db.execute(
                    "SELECT field, COUNT(*) AS count FROM edits GROUP BY field ORDER BY 2 DESC")],
            }
        finally:
            st.close()
        return {"audit": [dict(zip(cols, r)) for r in rows], "edits": [dict(zip(ecols, r)) for r in erows],
                "summary": summary}

    def export_csv(self, what):
        """Every row of the activity log or of the changes, or the Safe naming convention, as CSV text."""
        st = self.store()
        try:
            if what == "convention":
                cfg = self.config()
                cols, rows = convention_rows(st.plan(cfg), cfg)
            elif what == "audit":
                cols, rows = st.query("SELECT id, ts, user, host, action, detail FROM audit ORDER BY id")
            else:
                cols, rows = st.query("SELECT record_id, field, value, changed_utc, changed_by, reason "
                                      "FROM edits ORDER BY changed_utc, record_id")
            st.audit("export_log", what=what, rows=len(rows))
            st.db.commit()
        finally:
            st.close()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow(csvsafe.row(r))
        return "\ufeff" + buf.getvalue()

    def api_open_folder(self, body):
        which = body.get("which", "inbox")
        path = {"inbox": self.inbox, "output": self.output, "workspace": self.ws}.get(which)
        if not path:
            raise UiError("unknown folder")
        sub = body.get("name")
        if sub and which == "output":
            cand = (self.output / sub).resolve()
            if cand.parent == self.output and cand.is_dir():
                path = cand
        opened = False
        try:
            if sys.platform == "win32":
                os.startfile(str(path))   # noqa: S606 - opens Explorer on our own folder
                bring_to_front(path)      # otherwise it opens behind the browser
                opened = True
            elif os.environ.get("IMW_UI_NO_OPEN") != "1":
                tool = "open" if sys.platform == "darwin" else "xdg-open"
                if shutil.which(tool):
                    subprocess.Popen([tool, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    opened = True
        except OSError as exc:
            raise UiError(f"Could not open the folder: {exc}")
        return {"path": str(path), "opened": opened}

    def api_members_preview(self, body):
        """How each distinct member in the loaded data comes out with the given settings."""
        cfg = self.config()
        if isinstance(body.get("patch"), dict):
            cfg.update(body["patch"])
        try:
            cfg = config_from_dict(cfg)
            check_settings(cfg)
        except UiError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise UiError(f"settings are not valid: {exc}")
        if not self.db_path.exists():
            return {"members": []}
        st = self.store()
        try:
            rows = st.db.execute("SELECT member, member_type, COUNT(DISTINCT record_id) AS n FROM grants "
                                 "GROUP BY lower(member), member_type ORDER BY 3 DESC LIMIT 300").fetchall()
            refs = st.references()
        finally:
            st.close()
        try:
            before = config_from_dict(self.config())
        except Exception:  # noqa: BLE001
            before = None
        out = []
        for r in rows:
            mtype = normalize_member_type(r["member_type"], normalize_member_type(cfg["default_member_type"]))
            name, search_in, src = target_for(r["member"], cfg, mtype, refs)
            changed = []
            if before is not None:
                old_type = normalize_member_type(r["member_type"], normalize_member_type(before["default_member_type"]))
                old_name, old_in, _ = target_for(r["member"], before, old_type, refs)
                changed = [k for k, a, b in (("member_name", old_name, name), ("search_in", old_in, search_in),
                                             ("type", old_type, mtype)) if (a or "") != (b or "")]
            out.append({"source": r["member"], "type": mtype, "accounts": r["n"], "member_name": name,
                        "search_in": search_in, "directory_source": src or "(not matched; default)",
                        "changed": changed})
        return {"members": out}

    def api_ping(self, _body):
        return {"ok": True}

    # -- session ------------------------------------------------------------
    def api_session(self, _body):
        return {"locked": not self.unlocked, "user": self.auth.display, "kind": self.auth.kind,
                "idle_minutes": IDLE_SECONDS // 60,
                "wait": max(0, int(self.wait_until - time.time()))}

    def _audit_if_db(self, action, **detail):
        if self.db_path.exists():
            try:
                st = self.store()
                try:
                    st.audit(action, **detail)
                    st.db.commit()
                finally:
                    st.close()
            except Exception:  # noqa: BLE001 - never block sign-in on logging
                log.exception("audit failed")

    def api_unlock(self, body):
        now = time.time()
        if now < self.wait_until:
            raise UiError(f"Too many wrong passwords. Try again in {int(self.wait_until - now) + 1} seconds.", 429)
        password = body.get("password") or ""
        if password and self.auth.check(password):
            self.unlocked, self.failures, self.last_seen = True, 0, now
            self._audit_if_db("sign_in", user=self.auth.display)
            return {"ok": True}
        self.failures += 1
        if self.failures >= MAX_FAILURES:
            self.wait_until = now + min(300, 30 * 2 ** (self.failures - MAX_FAILURES))
        self._audit_if_db("sign_in_failed", user=self.auth.display, failures=self.failures)
        raise UiError("That password is not right for " + self.auth.display + ".")

    def api_lock(self, _body):
        self.unlocked = False
        self._audit_if_db("lock", reason="button")
        return {"locked": True}

    def api_end(self, body):
        # Ending is one click (the page sends END SESSION); deleting the database needs DELETE DB typed.
        if body.get("delete_db"):
            if body.get("confirm") != "DELETE DB":
                raise UiError("Type DELETE DB to confirm deleting the database.")
        elif body.get("confirm") != "END SESSION":
            raise UiError("Confirm with the End session button.")
        if not body.get("delete_db"):
            self._audit_if_db("end_session", database="kept")
        # End the session first: whatever happens to the files, nobody stays signed in and
        # the server stops.
        self.sid, self.unlocked = None, False
        if self.httpd:
            threading.Timer(0.5, self.httpd.shutdown).start()
        deleted, failed = False, []
        if body.get("delete_db"):
            for suffix in ("", "-wal", "-shm", "-journal"):
                f = Path(str(self.db_path) + suffix)
                try:
                    if f.exists():
                        secure_delete(f)
                        deleted = True
                except OSError as exc:      # e.g. Windows still holds a lock on the file
                    log.warning("could not delete %s: %s", f, exc)
                    failed.append(f.name)
        return {"ended": True, "database_deleted": deleted and not failed, "not_deleted": failed}

    ROUTES = {
        ("GET", "/api/state"): "api_state", ("POST", "/api/ingest"): "api_ingest",
        ("POST", "/api/inbox/delete"): "api_inbox_delete", ("GET", "/api/config"): "api_config_get",
        ("POST", "/api/config"): "api_config_save", ("POST", "/api/accounts"): "api_accounts",
        ("POST", "/api/record"): "api_record", ("POST", "/api/edit"): "api_edit",
        ("GET", "/api/safes"): "api_safes", ("POST", "/api/extract"): "api_extract",
        ("POST", "/api/output/delete"): "api_output_delete", ("GET", "/api/audit"): "api_audit",
        ("POST", "/api/naming/preview"): "api_naming_preview", ("POST", "/api/safes/preview"): "api_safes_preview", ("POST", "/api/rules/preview"): "api_rules_preview", ("POST", "/api/rules/values"): "api_rules_values",
        ("POST", "/api/approve"): "api_approve", ("GET", "/api/undecided"): "api_undecided",
        ("POST", "/api/decide"): "api_decide", ("POST", "/api/open"): "api_open_folder",
        ("POST", "/api/lock"): "api_lock", ("POST", "/api/end"): "api_end", ("POST", "/api/ping"): "api_ping",
        ("POST", "/api/members/preview"): "api_members_preview", ("POST", "/api/members/edit"): "api_members_edit",
        ("POST", "/api/members/change"): "api_members_change", ("POST", "/api/safes/change"): "api_safes_change",
    }
    # Allowed while locked.
    OPEN_ROUTES = {("GET", "/api/session"): "api_session", ("POST", "/api/unlock"): "api_unlock"}


def make_handler(app, port, scheme="https"):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    secure = "; Secure" if scheme == "https" else ""

    class Handler(BaseHTTPRequestHandler):
        server_version = "IMW"
        sys_version = ""
        timeout = 60      # a browser that opens a connection and stops talking does not hold a thread

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        def _send(self, status, body, ctype="application/json", headers=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _cookie(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "imw_sid":
                    return v
            return None

        def _guard(self, mutating):
            if self.headers.get("Host") not in allowed_hosts:
                return "bad host"
            origin = self.headers.get("Origin")
            if origin and origin not in {f"{scheme}://{h}" for h in allowed_hosts}:
                return "bad origin"
            if mutating and self.headers.get("X-IMW") != "1":
                return "missing header"
            return None

        def _session_ok(self):
            """The browser holds this run's session cookie (locked or not)."""
            with app.lock:
                sid = self._cookie()
                return bool(app.sid and sid and secrets.compare_digest(sid, app.sid))

        def _unlocked(self, touch=True):
            with app.lock:
                if app.unlocked and time.time() - app.last_seen > IDLE_SECONDS:
                    app.unlocked = False
                    app._audit_if_db("lock", reason="idle")
                if app.unlocked and touch:
                    app.last_seen = time.time()
                return app.unlocked

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def _peer_ok(self):
            """The browser connecting must run as the Workbench's Windows user (checked once per connection)."""
            if not hasattr(self, "_peer"):
                try:
                    self._peer = app.peer_check(self.client_address, port, app.owner["sid"])
                except Exception as exc:  # noqa: BLE001 - can't confirm: refuse
                    log.warning("could not check who is connecting: %s", exc)
                    self._peer = False
            return self._peer

        def _handle(self, method):
            url = urlparse(self.path)
            if not self._peer_ok():
                with app.lock:
                    app._audit_if_db("refused_connection", reason="another Windows user")
                return self._send(HTTPStatus.FORBIDDEN, f"<p>This Workbench belongs to {html_escape(app.owner['display'])}. "
                                  "Connections from other Windows users are refused.</p>".encode(),
                                  "text/html; charset=utf-8")
            problem = self._guard(method == "POST")
            if problem:
                return self._send(HTTPStatus.FORBIDDEN, {"error": problem})
            if method == "GET" and url.path == "/":
                token = parse_qs(url.query).get("t", [""])[0]
                with app.lock:
                    if token and app.launch_token and secrets.compare_digest(token, app.launch_token):
                        app.launch_token = None
                        app.sid = secrets.token_urlsafe(32)
                        app.unlocked = False
                        cookie = f"imw_sid={app.sid}; HttpOnly; SameSite=Strict; Path=/{secure}"
                        return self._send(HTTPStatus.SEE_OTHER, b"", "text/plain",
                                          {"Location": "/", "Set-Cookie": cookie})
                if not self._session_ok():
                    return self._send(HTTPStatus.UNAUTHORIZED,
                                      b"<p>Session ended or not started. Close this tab and run "
                                      b"<code>python -m imw ui</code> again to get a new link.</p>",
                                      "text/html; charset=utf-8")
                return self._send(HTTPStatus.OK, (STATIC / "index.html").read_bytes(),
                                  "text/html; charset=utf-8")
            if method == "GET" and url.path in STATIC_SCRIPTS:
                if not self._session_ok():
                    return self._send(HTTPStatus.UNAUTHORIZED, b"", "text/plain")
                return self._send(HTTPStatus.OK, (STATIC / STATIC_SCRIPTS[url.path]).read_bytes(),
                                  "text/javascript; charset=utf-8")
            if not url.path.startswith("/api/"):
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if not self._session_ok():
                return self._send(HTTPStatus.UNAUTHORIZED, {"error": "Session ended. Restart the UI."})
            if url.path.startswith("/api/export/") and method == "GET":
                if not self._unlocked():
                    return self._send(HTTPStatus.LOCKED, {"error": "locked"})
                what = url.path.rsplit("/", 1)[-1].replace(".csv", "")
                if what not in ("audit", "edits", "convention"):
                    return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                try:
                    with app.lock:
                        text = app.export_csv(what)
                except UiError as exc:
                    return self._send(exc.status, {"error": str(exc)})
                stamp = time.strftime("%Y%m%d-%H%M%S")
                return self._send(HTTPStatus.OK, text.encode("utf-8"), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="imw_{"safe_naming_convention" if what == "convention" else what}_{stamp}.csv"'})
            name = App.OPEN_ROUTES.get((method, url.path))
            if name:
                self._unlocked(touch=False)          # applies the idle lock before answering
            else:
                name = App.ROUTES.get((method, url.path))
                if not name:
                    return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                if not self._unlocked():
                    return self._send(HTTPStatus.LOCKED, {"error": "locked"})
            body = {}
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                if length > 10_000_000:
                    return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "too large"})
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    return self._send(HTTPStatus.BAD_REQUEST, {"error": "bad JSON"})
            try:
                with app.lock:
                    result = getattr(app, name)(body)
                self._send(HTTPStatus.OK, result)
            except UiError as exc:
                self._send(exc.status, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                log.exception("request failed")
                self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Unexpected error: {exc}"})

    return Handler


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Browsers drop connections while they show the certificate warning; that is not an error.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            log.debug("connection from %s closed: %s", client_address, exc)
            return
        super().handle_error(request, client_address)


def serve(workspace, port=0, open_browser=True, protector_flag=None, ready=None, authenticator=None,
          use_tls=True, new_cert=False, trust_cert=False):
    app = App(workspace, protector_flag, authenticator)
    httpd = WorkbenchServer(("127.0.0.1", port), None)
    port = httpd.server_address[1]
    scheme = "https" if use_tls else "http"
    cert_note = None
    if use_tls:
        ctx, cert_path, created = server_context(app.ws, renew=new_cert)
        # Handshake in the request thread, so one slow client cannot stall the listener.
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        if trust_cert:
            trust_certificate(cert_path)
            print("Certificate added to your Windows user's Trusted Root store.")
        cert_note = (f"HTTPS certificate: {cert_path} ({'new' if created else 'existing'}), "
                     f"SHA-256 {fingerprint(cert_path)}")
    httpd.RequestHandlerClass = make_handler(app, port, scheme)
    app.httpd = httpd
    httpd.app = app
    url = f"{scheme}://127.0.0.1:{port}/?t={app.launch_token}"
    print(f"{PRODUCT} running. Workspace: {app.ws}")
    print(f"Put export files in: {app.inbox}")
    if cert_note:
        print(cert_note)
        if not trust_cert:
            print("The browser warns once about this self-signed certificate: choose Advanced, then "
                  "Continue. To stop the warning, start once with --trust-cert.")
    else:
        print("WARNING: plain HTTP (--no-tls). Use only for troubleshooting.")
    print(f"Open this link (works once): {url}")
    print(f"Sign in as {app.auth.display}. Press Ctrl+C to stop.")
    if ready:
        ready(url, httpd)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
