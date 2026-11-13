"""Local web UI for the staging database: python -m pam2pc ui

Security model
  * Listens on 127.0.0.1 only; the Host and Origin headers must match.
  * The start-up link carries a one-time token that is exchanged for an HttpOnly,
    SameSite=Strict session cookie. Changes also need a custom request header.
  * The session ends after 30 minutes without activity.
  * No API returns a secret value. Secrets are only decrypted by the Output step
    when "include secrets" is chosen, straight into upload/Accounts.csv.
  * Runs in-process as the signed-in user, so DPAPI works as for the CLI.
"""

import json
import logging
import os
import secrets
import shutil
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..adapters import ADAPTERS, AdapterError, detect_adapter, get_adapter
from ..config import (ALL_PERMISSIONS, DEFAULT_CONFIG, PERMISSION_PRESETS, config_diff,
                      config_from_dict, load_config, resolve_role)
from ..model import SourceRecord
from ..naming import Namer
from ..protect import ProtectError
from ..store import Store, StoreError, run_extract
from ..transform import Permissions

log = logging.getLogger("pam2pc.ui")
STATIC = Path(__file__).parent / "static"
IDLE_SECONDS = 30 * 60
PAGE_SIZE = 200
EDITABLE = ("migrate", "target_safe", "platform_id", "account_name")

# The review menu: label -> SQL condition on the accounts view.
VIEWS = {
    "all": ("All accounts", "1=1"),
    "upload": ("Will be uploaded", "migrate = 'Y' AND status <> 'ERROR'"),
    "review": ("Needs a look (REVIEW)", "status = 'REVIEW'"),
    "errors": ("Errors - will NOT be uploaded", "status = 'ERROR'"),
    "excluded": ("Excluded by you (Migrate = N)", "migrate = 'N'"),
    "renamed_safes": ("Safe name was changed", "valid_safe_name = 'FALSE'"),
    "no_access": ("No access groups", "access_groups = ''"),
    "no_secret": ("Empty secret", "has_secret = 'N'"),
    "fallback": ("Safe from folder fallback (no rule matched)", "safe_mapping_source LIKE 'fallback:%'"),
    "duplicates": ("Possible duplicates", "notes LIKE '%possible duplicate%'"),
    "edited": ("Changed by you", "record_id IN (SELECT record_id FROM edits)"),
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
        like = f"%{search}%"
        parts.append("(account_name LIKE ? OR username LIKE ? OR address LIKE ? OR folder LIKE ? "
                     "OR record_id LIKE ? OR target_safe LIKE ?)")
        params += [like] * 6
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


def looks_like_permissions(path):
    """A CSV whose header has a group/principal column and a permission column, and no password column."""
    if path.suffix.lower() != ".csv":
        return False
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            header = [h.strip().lower() for h in fh.readline().split(",")]
    except OSError:
        return False
    return (any(h in ("group", "principal", "member", "group name") for h in header)
            and any(h in ("permission", "role", "access") for h in header)
            and not any("password" in h for h in header))


def secure_delete(path):
    """Overwrite then delete. Best effort: SSDs and some file systems keep old copies."""
    size = path.stat().st_size
    with open(path, "r+b") as fh:
        fh.write(b"\0" * size)
        fh.flush()
        os.fsync(fh.fileno())
    path.unlink()


class App:
    def __init__(self, workspace, protector_flag=None):
        self.ws = Path(workspace).resolve()
        self.inbox = self.ws / "inbox"
        self.output = self.ws / "output"
        for d in (self.ws, self.inbox, self.output):
            d.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ws / "migration.db"
        self.config_path = self.ws / "config.json"
        self.protector_flag = protector_flag
        self.lock = threading.RLock()
        self.launch_token = secrets.token_urlsafe(32)
        self.sid = None
        self.last_seen = 0.0

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
                 "inbox_files": [], "outputs": [], "views": {k: v[0] for k, v in VIEWS.items()}}
        for f in sorted(self.inbox.iterdir()):
            if f.is_file():
                try:
                    guess = detect_adapter(f).name
                except AdapterError:
                    guess = ""
                state["inbox_files"].append({"name": f.name, "size": f.stat().st_size, "guess": guess,
                                             "permissions": looks_like_permissions(f)})
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
                state["inputs"] = [dict(r) for r in st.db.execute(
                    "SELECT id, source, path, records, loaded_utc, loaded_by FROM inputs ORDER BY id")]
                counts = {r[0]: r[1] for r in st.db.execute(
                    "SELECT status, COUNT(*) FROM plan_accounts GROUP BY status")}
                state["status_counts"] = counts
                state["excluded"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'N'").fetchone()[0]
                state["to_upload"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'Y' AND status <> 'ERROR'").fetchone()[0]
                state["safes"] = st.db.execute("SELECT COUNT(*) FROM plan_safes").fetchone()[0]
                state["invalid_safes"] = st.db.execute(
                    "SELECT COUNT(*) FROM plan_safes WHERE valid_safe_name = 'FALSE'").fetchone()[0]
                state["edits"] = st.db.execute("SELECT COUNT(DISTINCT record_id) FROM edits").fetchone()[0]
                state["stale"] = bool(st.db.execute(
                    "SELECT COUNT(*) FROM records WHERE record_id NOT IN (SELECT record_id FROM plan_accounts)"
                ).fetchone()[0])
            finally:
                st.close()
        return state

    def api_ingest(self, body):
        files = body.get("files") or []
        if not files:
            raise UiError("Pick at least one export file.")
        cfg = self.config()
        perms = None
        if body.get("permissions"):
            perms = Permissions(self._inbox_file(body["permissions"]))
        results = []
        st = self.store(create=True)
        try:
            for f in files:
                path = self._inbox_file(f["name"])
                adapter = get_adapter(f["source"]) if f.get("source") else detect_adapter(path)
                records = list(adapter.read(path, cfg))
                n, replaced = st.ingest(adapter.name, path, records, perms,
                                        str(self._inbox_file(body["permissions"])) if perms else None)
                results.append({"name": f["name"], "source": adapter.name, "records": n, "replaced": replaced})
            st.map(cfg, str(self.config_path) if self.config_path.exists() else None)
        except (AdapterError, ValueError, OSError, ProtectError, StoreError) as exc:
            raise UiError(f"{exc}")
        finally:
            st.close()
        return {"results": results, "protector": self.protector_flag or "dpapi"}

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
        hints = {"types_without_platform": [], "groups": [], "folders": []}
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
            finally:
                st.close()
        return {"config": cfg, "defaults": DEFAULT_CONFIG, "hints": hints, "saved": self.config_path.exists(),
                "presets": PERMISSION_PRESETS, "permissions": ALL_PERMISSIONS}

    def _naming_samples(self, st, cfg, limit=400):
        """Generated convention names for the distinct folder/platform/username combinations."""
        namer = Namer(cfg)
        rows = st.db.execute(
            "SELECT r.folder_json, r.folder, r.type, r.username, p.platform_id, COUNT(*) AS n "
            "FROM records r JOIN plan_accounts p USING (record_id) "
            "GROUP BY r.folder_json, p.platform_id, r.username ORDER BY r.folder LIMIT ?", (limit,)).fetchall()
        out, seen = [], set()
        for r in rows:
            rec = SourceRecord(source="", source_file="", source_id="", source_ref="",
                               folder=tuple(json.loads(r["folder_json"])), type=r["type"], username=r["username"])
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

    def api_config_save(self, body):
        user = body.get("config")
        if not isinstance(user, dict):
            raise UiError("config must be a JSON object")
        tmp = self.config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(user, indent=2), encoding="utf-8")
        try:
            cfg = load_config(tmp)
            for rule in cfg["group_rules"]:
                if not rule.get("safe") or not (rule.get("group") or rule.get("group_pattern")):
                    raise UiError("Every group rule needs a group (or pattern) and a Safe.")
            for rule in cfg["folder_rules"]:
                if not rule.get("safe") or not rule.get("folder_prefix"):
                    raise UiError("Every folder rule needs a folder and a Safe.")
            check_roles(cfg)
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
            return {"saved": True, "mapped": False}
        st = self.store()
        try:
            st.map(cfg, str(self.config_path))
        finally:
            st.close()
        return {"saved": True, "mapped": True}

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
                f"username, secret_type, has_secret, source, folder, access_groups, notes FROM accounts "
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
        finally:
            st.close()
        return out

    def api_edit(self, body):
        values = body.get("values") or {}
        if any(k not in EDITABLE for k in values):
            raise UiError("only Migrate, Safe, platform and account name can be changed")
        if "migrate" in values and values["migrate"] not in ("Y", "N", ""):
            raise UiError("Migrate must be Y or N")
        st = self.store()
        try:
            if body.get("ids"):
                ids = list(body["ids"])
            else:
                where, params = build_where(body)
                ids = st.select_ids(where, params)
            if not ids:
                raise UiError("No accounts selected.")
            if len(ids) > 1 and values.get("account_name"):
                raise UiError("Rename one account at a time.")
            st.set_edits(ids, values, body.get("reason") or "")
            st.map(st.stored_config(), st.meta("config_path"))
        except StoreError as exc:
            raise UiError(str(exc))
        finally:
            st.close()
        return {"changed": len(ids)}

    def api_safes(self, _body):
        st = self.store()
        try:
            cols, rows = st.query("SELECT * FROM plan_safes ORDER BY safe_name")
            mcols, mrows = st.query("SELECT * FROM plan_members ORDER BY safe_name, member_name")
        finally:
            st.close()
        return {"safes": [dict(zip(cols, r)) for r in rows], "members": [dict(zip(mcols, r)) for r in mrows]}

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
        finally:
            st.close()
        return {"audit": [dict(zip(cols, r)) for r in rows], "edits": [dict(zip(ecols, r)) for r in erows]}

    ROUTES = {
        ("GET", "/api/state"): "api_state", ("POST", "/api/ingest"): "api_ingest",
        ("POST", "/api/inbox/delete"): "api_inbox_delete", ("GET", "/api/config"): "api_config_get",
        ("POST", "/api/config"): "api_config_save", ("POST", "/api/accounts"): "api_accounts",
        ("POST", "/api/record"): "api_record", ("POST", "/api/edit"): "api_edit",
        ("GET", "/api/safes"): "api_safes", ("POST", "/api/extract"): "api_extract",
        ("POST", "/api/output/delete"): "api_output_delete", ("GET", "/api/audit"): "api_audit",
        ("POST", "/api/naming/preview"): "api_naming_preview",
    }


def make_handler(app, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "pam2pc-ui"
        sys_version = ""

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
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _cookie(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "pam2pc_sid":
                    return v
            return None

        def _guard(self, mutating):
            if self.headers.get("Host") not in allowed_hosts:
                return "bad host"
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in allowed_hosts}:
                return "bad origin"
            if mutating and self.headers.get("X-Pam2pc") != "1":
                return "missing header"
            return None

        def _session_ok(self):
            with app.lock:
                sid = self._cookie()
                if not app.sid or not sid or not secrets.compare_digest(sid, app.sid):
                    return False
                if time.time() - app.last_seen > IDLE_SECONDS:
                    app.sid = None
                    return False
                app.last_seen = time.time()
                return True

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def _handle(self, method):
            url = urlparse(self.path)
            problem = self._guard(method == "POST")
            if problem:
                return self._send(HTTPStatus.FORBIDDEN, {"error": problem})
            if method == "GET" and url.path == "/":
                token = parse_qs(url.query).get("t", [""])[0]
                with app.lock:
                    if token and app.launch_token and secrets.compare_digest(token, app.launch_token):
                        app.launch_token = None
                        app.sid = secrets.token_urlsafe(32)
                        app.last_seen = time.time()
                        cookie = f"pam2pc_sid={app.sid}; HttpOnly; SameSite=Strict; Path=/"
                        return self._send(HTTPStatus.SEE_OTHER, b"", "text/plain",
                                          {"Location": "/", "Set-Cookie": cookie})
                if not self._session_ok():
                    return self._send(HTTPStatus.UNAUTHORIZED,
                                      b"<p>Session ended or not started. Close this tab and run "
                                      b"<code>python -m pam2pc ui</code> again to get a new link.</p>",
                                      "text/html; charset=utf-8")
                return self._send(HTTPStatus.OK, (STATIC / "index.html").read_bytes(),
                                  "text/html; charset=utf-8")
            if not url.path.startswith("/api/"):
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if not self._session_ok():
                return self._send(HTTPStatus.UNAUTHORIZED, {"error": "Session ended. Restart the UI."})
            if url.path == "/api/logout" and method == "POST":
                with app.lock:
                    app.sid = None
                return self._send(HTTPStatus.OK, {"ok": True})
            name = App.ROUTES.get((method, url.path))
            if not name:
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
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


def serve(workspace, port=0, open_browser=True, protector_flag=None, ready=None):
    app = App(workspace, protector_flag)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(app, port)
    url = f"http://127.0.0.1:{port}/?t={app.launch_token}"
    print(f"pam2pc UI running. Workspace: {app.ws}")
    print(f"Put export files in: {app.inbox}")
    print(f"Open this link (works once): {url}")
    print("Press Ctrl+C to stop.")
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
