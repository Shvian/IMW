#!/usr/bin/env python3
"""
Delinea -> CyberArk Privilege Cloud migration: local web UI.

A guided front end for the existing tools (readiness checks, Phase 1 mapping,
Phase 2 execution). It drives the same scripts, ledger and audit logs as the
command line, so resume and no-duplicate guarantees are unchanged.

Security model (see ui/README.md):
  * Listens on 127.0.0.1 only. Host and Origin headers are checked (blocks DNS
    rebinding and cross-site requests). State-changing calls need a custom
    header, so a web page elsewhere cannot forge them.
  * Opening the UI needs the one-time link printed in this console. The link is
    exchanged for an HttpOnly, SameSite=Strict session cookie. One session at a
    time; it ends after --idle-minutes without user activity.
  * API credentials are typed into the UI and held only in this process's
    memory. They are never written to disk, logs or the browser, and are
    passed only to the child process that needs them, in its environment.
    They are dropped when the session ends, idles out or the UI stops.
  * Uploaded CSVs are scrubbed in memory: secret-value and attachment columns
    are removed before anything is written to disk.
  * Every UI action is written to a hash-chained audit log
    (workspace/ui_audit.jsonl), alongside the Phase 2 audit logs.

Standard library only (Python 3.8+).

  python ui/server/migration_ui.py [--workspace PATH] [--port N] [--no-browser]
"""

import argparse
import contextlib
import csv
import getpass
import hashlib
import importlib.util
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from collections import OrderedDict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent                      # delinea-migration/
P1_SCRIPT = ROOT / "phase1" / "delinea_phase1_mapping.py"
P2_SCRIPT = ROOT / "phase2" / "cyberark_phase2_execute.py"
READINESS_SCRIPT = ROOT / "setup" / "Test-MigrationReadiness.ps1"
STATIC = HERE / "static"

VERSION = "1.0.0"
MAX_UPLOAD = 200 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
IS_WINDOWS = os.name == "nt"
# The Windows registry can map .js to text/plain, which browsers refuse to run with nosniff.
for _ext, _type in ((".js", "application/javascript"), (".mjs", "application/javascript"), (".css", "text/css"),
                    (".svg", "image/svg+xml"), (".json", "application/json"), (".html", "text/html"),
                    (".csv", "text/csv"), (".jsonl", "application/x-ndjson"), (".log", "text/plain")):
    mimetypes.add_type(_type, _ext)
CALL_POLICY = {"calls": 5000, "seconds": 300}   # Ian's starting limit, per system


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


phase1 = _load("delinea_phase1_mapping", P1_SCRIPT)
phase2 = _load("cyberark_phase2_execute", P2_SCRIPT)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    return phase2.sha256_file(path) if Path(path).exists() else ""


def atomic_write(path, data, encoding="utf-8"):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(data, str):
        data = data.encode(encoding)
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class UserError(Exception):
    """A problem the operator can fix; shown in the UI as-is."""

    def __init__(self, message, status=400, hint=""):
        super().__init__(message)
        self.status, self.hint = status, hint


# --------------------------------------------------------------------------- #
# Workspace: every file the UI reads or writes lives here (no secrets, ever)
# --------------------------------------------------------------------------- #
class Workspace:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.inputs = self.root / "inputs"
        self.config_dir = self.root / "config"
        self.p1_out = self.root / "phase1_output"
        self.history = self.root / "history"
        self.state = {"production": self.root / "state" / "production",
                      "rehearsal": self.root / "state" / "rehearsal",
                      "preflight": self.root / "state" / "preflight"}
        self.readiness = self.root / "readiness"
        for d in [self.inputs, self.config_dir, self.p1_out, self.history, self.readiness, *self.state.values()]:
            d.mkdir(parents=True, exist_ok=True)
        self.export = self.inputs / "delinea_export.csv"
        self.permissions = self.inputs / "delinea_permissions.csv"
        self.mapping_cfg = self.config_dir / "mapping_config.json"
        self.p2_cfg = self.config_dir / "phase2_config.json"
        self.review = self.p1_out / "Migration_Review.csv"
        self.safes = self.p1_out / "Safes_Review.csv"
        self.members = self.p1_out / "Safe_Members_Review.csv"
        self.ui_audit = self.root / "ui_audit.jsonl"
        self.ui_state = self.root / "ui_state.json"
        with contextlib.redirect_stdout(io.StringIO()):
            if not self.mapping_cfg.exists():
                phase1.write_default_config(str(self.mapping_cfg))
            if not self.p2_cfg.exists():
                phase2.write_default_config(str(self.p2_cfg))

    def rel(self, p):
        return Path(p).resolve().relative_to(self.root).as_posix()

    def resolve(self, rel):
        """Map a workspace-relative path to a file, refusing anything outside the workspace."""
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise UserError("Path is outside the workspace", 403)
        return p

    def load_state(self):
        try:
            return json.loads(self.ui_state.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def save_state(self, **updates):
        st = self.load_state()
        st.update(updates)
        atomic_write(self.ui_state, json.dumps(st, indent=2))
        return st

    def snapshot_phase1_output(self, reason):
        files = [p for p in (self.review, self.safes, self.members) if p.exists()]
        if not files:
            return None
        dest = self.history / f"{stamp()}_{reason}"
        dest.mkdir(parents=True, exist_ok=True)
        for p in files:
            shutil.copy2(p, dest / p.name)
        return self.rel(dest)


# --------------------------------------------------------------------------- #
# Session, credentials and audit
# --------------------------------------------------------------------------- #
class Session:
    """One browser session at a time. Credentials live only in this object."""

    def __init__(self, idle_seconds, audit):
        self.idle_seconds = idle_seconds
        self.audit = audit
        self.lock = threading.RLock()
        self.launch_token = None
        self.sid = None
        self.last_activity = 0.0
        self.started = None
        self.operator = ""
        self._creds = {}

    def new_launch_token(self):
        with self.lock:
            self.launch_token = secrets.token_urlsafe(32)
            return self.launch_token

    def exchange(self, token):
        with self.lock:
            if not token or not self.launch_token or not secrets.compare_digest(token, self.launch_token):
                return None
            self.launch_token = None                        # one-time
            if self.sid:
                self._end("replaced by a new session")
            self.sid = secrets.token_urlsafe(32)
            self.last_activity = time.monotonic()
            self.started = utcnow()
            self.audit("session_start")
            return self.sid

    def check(self, sid, user_activity):
        with self.lock:
            self.expire_if_idle()
            if not self.sid or not sid or not secrets.compare_digest(sid, self.sid):
                return False
            if user_activity:
                self.last_activity = time.monotonic()
            return True

    def expire_if_idle(self):
        with self.lock:
            if self.sid and time.monotonic() - self.last_activity > self.idle_seconds:
                self._end(f"idle for {self.idle_seconds // 60} minutes")

    def _end(self, reason):
        had = sorted(self._creds)
        self._creds.clear()
        self.sid = None
        self.audit("session_end", reason=reason, credentials_dropped=had)

    def end(self, reason):
        with self.lock:
            if self.sid:
                self._end(reason)

    def idle_left(self):
        with self.lock:
            if not self.sid:
                return 0
            return max(0, int(self.idle_seconds - (time.monotonic() - self.last_activity)))

    # credentials -----------------------------------------------------------
    def set_cred(self, system, value):
        with self.lock:
            self._creds[system] = value

    def clear_cred(self, system=None):
        with self.lock:
            if system:
                self._creds.pop(system, None)
            else:
                self._creds.clear()

    def has(self, system):
        return bool(self._creds.get(system))

    def get(self, system):
        return self._creds.get(system, "")

    @staticmethod
    def _forms(v):
        """The secret as it may appear in output: raw, repr()/JSON-escaped, URL-encoded, and
        those escapes applied twice (an exception message inside a repr or JSON string)."""
        forms = {v}
        for _ in range(2):
            for f in list(forms):
                forms.add(repr(f)[1:-1])
                forms.add(json.dumps(f)[1:-1])
                forms.add(json.dumps(f, ensure_ascii=False)[1:-1])
                forms.add(f.replace("\\", "\\\\").replace("'", "\\'"))
                forms.add(f.replace("\\", "\\\\").replace('"', '\\"'))
        for f in list(forms):
            forms.add(urllib.parse.quote(f, safe=""))
            forms.add(urllib.parse.quote(f))
            forms.add(urllib.parse.quote_plus(f))
        return sorted(forms, key=len, reverse=True)

    def redact(self, text):
        for v in list(self._creds.values()):
            if v and len(v) >= 4:
                for form in self._forms(v):
                    text = text.replace(form, "********")
                    if "%" in form:   # the same with lower-case %xx escapes
                        text = text.replace(re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), form),
                                            "********")
        return text


class UiAudit:
    """Hash-chained audit of UI actions, same format and verifier as Phase 2."""

    def __init__(self, path):
        self.lock = threading.Lock()
        self.log = phase2.AuditLog(path, f"ui-{uuid.uuid4()}", getpass.getuser(), socket.gethostname())
        self.operator_label = ""

    def __call__(self, event, **fields):
        with self.lock:
            if self.operator_label:
                fields.setdefault("operator_name", self.operator_label)
            self.log.write("ui_" + event, **fields)

    def close(self):
        with self.lock:
            self.log.close()


# --------------------------------------------------------------------------- #
# Upload scrubbing: secret-value and attachment columns never reach the disk
# --------------------------------------------------------------------------- #
def decode_upload(data):
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise UserError("The file is not UTF-8 or Windows-1252 text. Save it as CSV (UTF-8) and try again.")


def _matches(name, patterns):
    return any(re.search(p, name.strip(), re.IGNORECASE) for p in patterns)


def scrub_export(text, mcfg):
    """Remove secret and attachment columns from a multi-header Delinea export."""
    markers = {m.lower() for m in mcfg["header_markers"]}
    secret_pats, excl_pats = mcfg["secret_column_patterns"], mcfg["exclude_field_patterns"]
    rows = list(csv.reader(io.StringIO(text)))

    def is_header(r):
        return bool(markers.intersection(c.strip().lower() for c in r))

    non_blank = [i for i, r in enumerate(rows) if any(c.strip() for c in r)]
    next_nb = {a: b for a, b in zip(non_blank, non_blank[1:])}
    out, drop, kinds = [], set(), {}
    sections = data_rows = values = 0
    dropped = OrderedDict()
    id_seen = False
    for i, r in enumerate(rows):
        if not any(c.strip() for c in r):
            out.append([])
            continue
        if is_header(r):
            sections += 1
            drop, kinds = set(), {}
            for j, c in enumerate(r):
                if _matches(c, secret_pats):
                    drop.add(j)
                    kinds[j] = "secret"
                elif _matches(c, excl_pats):
                    drop.add(j)
                    kinds[j] = "attachment"
            for j in sorted(drop):
                dropped.setdefault(r[j].strip(), kinds[j])
            if any(c.strip().lower() in {a.lower() for a in mcfg["field_aliases"]["secret_id"]} for c in r):
                id_seen = True
            out.append([c for j, c in enumerate(r) if j not in drop])
            continue
        nb = [c for c in r if c.strip()]
        if len(nb) == 1 and r[0].strip() and i in next_nb and is_header(rows[next_nb[i]]):
            out.append([r[0]])                            # template title row
            continue
        if sections:
            data_rows += 1
        values += sum(1 for j in drop if kinds[j] == "secret" and j < len(r) and r[j].strip())
        out.append([c for j, c in enumerate(r) if j not in drop])
    if not sections:
        raise UserError("No header row found. The export needs a 'Secret Name' column "
                        "(or change header_markers in the mapping rules).")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    for r in out:
        w.writerow(r)
    warnings = []
    if values:
        warnings.append(f"The original file held {values} plaintext secret values. They were removed and "
                        "not saved, but the original file still has them: delete it securely, and use a "
                        "metadata-only Secret Server report next time.")
    if not id_seen:
        warnings.append("No 'Secret ID' column found. Phase 2 needs it to fetch each secret from Delinea.")
    return buf.getvalue(), {"sections": sections, "rows": data_rows, "secret_values_removed": values,
                            "dropped_columns": [{"name": k, "kind": v} for k, v in dropped.items()],
                            "warnings": warnings}


def scrub_table(text, secret_pats, required, label):
    """Single-header CSV (permissions, review files): drop secret columns, check required ones."""
    rdr = csv.reader(io.StringIO(text))
    try:
        header = next(rdr)
    except StopIteration:
        raise UserError(f"The {label} file is empty.")
    lower = [h.strip().lower() for h in header]
    for options in required:
        if not any(o.lower() in lower for o in options):
            raise UserError(f"The {label} file has no '{options[0]}' column. Columns found: {', '.join(header)}")
    drop = {j for j, h in enumerate(header) if _matches(h, secret_pats) and not h.startswith("Delinea Secret")}
    values = 0
    rows = []
    for r in rdr:
        values += sum(1 for j in drop if j < len(r) and r[j].strip())
        rows.append([c for j, c in enumerate(r) if j not in drop])
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow([h for j, h in enumerate(header) if j not in drop])
    w.writerows(rows)
    warnings = []
    if values:
        warnings.append(f"Removed {values} secret values from the {label} file. Delete the original securely.")
    return buf.getvalue(), {"rows": len(rows), "secret_values_removed": values,
                            "dropped_columns": [{"name": header[j], "kind": "secret"} for j in sorted(drop)],
                            "warnings": warnings}


# --------------------------------------------------------------------------- #
# Config validation: no credentials, TLS on, HTTPS endpoints, call budget
# --------------------------------------------------------------------------- #
CRED_KEY = re.compile(r"(secret|password|passwd|passphrase|api_?key|token)$", re.IGNORECASE)
URL_KEYS = ("token_url", "api_base_url", "base_url")


def _walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


# Sections whose keys are data (template names, permissions, field names), not setting names.
DATA_MAPS = ("platform_map", "secret_field_slugs", "field_aliases", "permission_map", "account_property_map",
             "role_permissions", "directory_map", "field_query", "safe_defaults")


def _check_no_credentials(cfg):
    for path, v in _walk(cfg):
        if path.split(".")[0].split("[")[0] in DATA_MAPS and "." in path:
            continue
        key = re.split(r"[.\[]", path)[-1]
        if isinstance(v, str) and v and CRED_KEY.search(key) and not key.endswith("_env"):
            raise UserError(f"'{path}' looks like a credential. Credentials are never stored in the config: "
                            "enter them under Connections, where they are held in memory only.")


def validate_phase2_config(cfg):
    if not isinstance(cfg, dict):
        raise UserError("Config must be a JSON object")
    _check_no_credentials(cfg)
    if cfg.get("verify_tls", True) is not True:
        raise UserError("verify_tls must stay true. Fix the certificate trust instead "
                        "(see readiness check NET-nE for TLS inspection proxies).")
    warnings = []
    for system in ("cyberark", "delinea"):
        sec = cfg.get(system) or {}
        for k in URL_KEYS:
            url = sec.get(k)
            if not url:
                continue
            u = urllib.parse.urlparse(url)
            if u.scheme == "http" and u.hostname in LOOPBACK_HOSTS:
                warnings.append(f"{system}.{k} uses http on this machine; only valid for the test mock.")
            elif u.scheme != "https" or not u.hostname:
                raise UserError(f"{system}.{k} must be an https:// URL (got '{url}')")
            if "EXAMPLE" in url:
                warnings.append(f"{system}.{k} still has the EXAMPLE placeholder.")
        rpm = float(sec.get("requests_per_minute") or 0)
        cap = float(sec.get("max_calls_per_window") or 0)
        win = float(sec.get("window_seconds") or 300)
        per_policy = min(rpm * CALL_POLICY["seconds"] / 60 if rpm else 1e12,
                         cap * CALL_POLICY["seconds"] / win if cap else 1e12)
        if per_policy >= CALL_POLICY["calls"]:
            warnings.append(f"{system}: these limits allow about {int(per_policy)} calls per 5 minutes, at or "
                            f"above the {CALL_POLICY['calls']} starting policy.")
    return warnings


def validate_mapping_config(cfg):
    if not isinstance(cfg, dict):
        raise UserError("Mapping rules must be a JSON object")
    _check_no_credentials(cfg)
    for i, rule in enumerate(cfg.get("group_rules", [])):
        if not isinstance(rule, dict) or not rule.get("safe") or not (rule.get("group") or rule.get("group_pattern")):
            raise UserError(f"Group rule {i + 1} needs a group (or pattern) and a Safe")
        if rule.get("group_pattern"):
            try:
                re.compile(rule["group_pattern"])
            except re.error as e:
                raise UserError(f"Group rule {i + 1}: pattern is not a valid regex ({e})")
        mp = rule.get("min_permission")
        if mp and mp.lower() not in phase1.PERMISSION_RANK:
            raise UserError(f"Group rule {i + 1}: min_permission must be List, View, Edit or Owner")
    for i, rule in enumerate(cfg.get("folder_rules", [])):
        if not isinstance(rule, dict) or not rule.get("folder_prefix") or not rule.get("safe"):
            raise UserError(f"Folder rule {i + 1} needs a folder prefix and a Safe")
    for key in ("exclude_field_patterns", "secret_column_patterns"):
        for p in cfg.get(key, []):
            try:
                re.compile(p)
            except re.error as e:
                raise UserError(f"{key}: '{p}' is not a valid regex ({e})")
    if cfg.get("fallback_strategy", "folder_leaf") not in ("folder_leaf", "folder_path", "unmapped"):
        raise UserError("fallback_strategy must be folder_leaf, folder_path or unmapped")
    return []


def config_changes(old, new):
    o, n = dict(_walk(old)), dict(_walk(new))
    out = []
    for k in sorted(set(o) | set(n)):
        if o.get(k) != n.get(k):
            out.append({"key": k, "old": o.get(k), "new": n.get(k)})
    return out


# --------------------------------------------------------------------------- #
# Review files (Phase 1 output) read and edit
# --------------------------------------------------------------------------- #
ACCOUNT_EDITABLE = ["Migrate", "Target CyberArk Safe", "Target Platform ID", "Account Name", "Address",
                    "Username", "Secret Type", "Delinea Secret Field"]
MEMBER_EDITABLE = ["Member_Name", "CyberArk_Role"]
FIELD_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def read_table(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rdr = csv.reader(fh)
        header = next(rdr, [])
        return header, [r + [""] * (len(header) - len(r)) for r in rdr]


def write_table(path, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(header)
    w.writerows(rows)
    atomic_write(path, buf.getvalue(), encoding="utf-8-sig")


def validate_cell(column, value, p2cfg):
    value = str(value)
    if "\n" in value or "\r" in value or len(value) > 256:
        raise UserError(f"{column}: one line, up to 256 characters")
    if column == "Migrate":
        if value.upper() not in ("Y", "N"):
            raise UserError("Migrate must be Y or N")
        return value.upper()
    if column == "Target CyberArk Safe":
        problems = phase2.safe_name_problems(value, p2cfg)
        if problems:
            raise UserError(f"Safe '{value}': " + "; ".join(problems))
        return value
    if column == "Secret Type":
        if value.lower() not in phase2.SECRET_TYPES:
            raise UserError("Secret Type must be password or key")
        return value.lower()
    if column == "Delinea Secret Field":
        if not FIELD_SLUG.match(value):
            raise UserError("Delinea Secret Field must be a field slug, e.g. password or private-key")
        return value
    if column == "Account Name":
        if not value.strip() or phase1.ACCOUNT_NAME_INVALID.search(value):
            raise UserError('Account Name cannot be empty or contain \\ / : * ? " < > |')
        return value
    if column == "Target Platform ID":
        if not value.strip():
            raise UserError("Target Platform ID cannot be empty")
        return value.strip()
    if column == "CyberArk_Role":
        roles = list(p2cfg.get("role_permissions", {}))
        if value not in roles:
            raise UserError(f"CyberArk_Role must be one of {', '.join(roles)}")
        return value
    if column == "Member_Name" and not value.strip():
        raise UserError("Member_Name cannot be empty")
    return value


def row_matches(header, row, q, flt):
    d = dict(zip(header, row))
    if flt == "review" and d.get("Review_Status") != "REVIEW":
        return False
    if flt == "invalid" and d.get("Valid_Safe_Name") != "FALSE":
        return False
    if flt == "excluded" and phase2.is_yes(d.get("Migrate")):
        return False
    if flt == "included" and not phase2.is_yes(d.get("Migrate")):
        return False
    if flt and flt.startswith("safe:") and d.get("Target CyberArk Safe") != flt[5:]:
        return False
    if q:
        ql = q.lower()
        return any(ql in str(v).lower() for v in row)
    return True


# --------------------------------------------------------------------------- #
# Jobs: one child process at a time, output streamed to the browser
# --------------------------------------------------------------------------- #
class Job:
    def __init__(self, action, label, argv, mode, meta):
        self.id = uuid.uuid4().hex[:12]
        self.action, self.label, self.argv, self.mode, self.meta = action, label, argv, mode, meta
        self.started, self.finished = utcnow(), None
        self.started_mono = time.monotonic()
        self.exit_code = None
        self.state = "running"
        self.lines = []
        self.first_line = 0
        self.proc = None
        self.stop_requested = False

    def brief(self):
        return {"id": self.id, "action": self.action, "label": self.label, "mode": self.mode,
                "state": self.state, "started": self.started, "finished": self.finished,
                "exit_code": self.exit_code, "lines": self.first_line + len(self.lines),
                "outcome": self.outcome()}

    def outcome(self):
        if self.state == "running":
            return "running"
        if self.stop_requested:
            return "stopped"
        return {0: "ok", 1: "error", 2: "invalid", 3: "failures"}.get(self.exit_code, "error")


class JobRunner:
    MAX_LINES = 20000

    def __init__(self, session, audit, on_done):
        self.session, self.audit, self.on_done = session, audit, on_done
        self.lock = threading.Lock()
        self.current = None
        self.history = []

    def busy(self):
        return bool(self.current and self.current.state == "running")

    def start(self, action, label, argv, env, mode="", meta=None):
        with self.lock:
            if self.busy():
                raise UserError(f"'{self.current.label}' is still running. Wait for it or stop it first.", 409)
            job = Job(action, label, argv, mode, meta or {})
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
            try:
                job.proc = subprocess.Popen(argv, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            creationflags=flags, start_new_session=not IS_WINDOWS)
            except OSError as e:
                raise UserError(f"Could not start {label}: {e}", 500)
            self.current = job
            self.history.insert(0, job)
            del self.history[20:]
        self.audit("job_start", job_id=job.id, action=action, label=label, mode=mode,
                   argv=[self._display(a) for a in argv], **{k: v for k, v in job.meta.items() if k != "secret"})
        threading.Thread(target=self._pump, args=(job,), daemon=True).start()
        return job

    @staticmethod
    def _display(a):
        a = str(a)
        try:
            return Path(a).relative_to(ROOT).as_posix() if os.path.isabs(a) else a
        except ValueError:
            return a

    def _pump(self, job):
        for raw in iter(job.proc.stdout.readline, b""):
            line = self.session.redact(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
            job.lines.append(line)
            if len(job.lines) > self.MAX_LINES:
                drop = len(job.lines) - self.MAX_LINES
                del job.lines[:drop]
                job.first_line += drop
        job.exit_code = job.proc.wait()
        job.finished = utcnow()
        job.state = "done"
        self.audit("job_end", job_id=job.id, action=job.action, exit_code=job.exit_code, outcome=job.outcome(),
                   seconds=round(time.monotonic() - job.started_mono, 1))
        try:
            self.on_done(job)
        except Exception as e:                                   # never lose the job record
            job.lines.append(f"[ui] post-processing failed: {e}")

    def stop(self):
        job = self.current
        if not job or job.state != "running":
            raise UserError("Nothing is running", 409)
        job.stop_requested = True
        self.audit("job_stop_requested", job_id=job.id, action=job.action)
        try:
            job.proc.send_signal(signal.CTRL_BREAK_EVENT if IS_WINDOWS else signal.SIGINT)
        except OSError:
            pass

        def hard_stop():
            time.sleep(20)
            if job.state == "running":
                job.lines.append("[ui] did not stop within 20 s; terminating. The ledger re-checks "
                                 "in-progress objects on the next run.")
                job.proc.kill()
        threading.Thread(target=hard_stop, daemon=True).start()

    def output(self, job_id, since):
        job = next((j for j in self.history if j.id == job_id), None)
        if not job:
            raise UserError("Unknown job", 404)
        start = max(0, since - job.first_line)
        return {"job": job.brief(), "from": job.first_line + start, "lines": job.lines[start:start + 2000]}


# --------------------------------------------------------------------------- #
# The application
# --------------------------------------------------------------------------- #
class App:
    def __init__(self, workspace, idle_minutes):
        self.ws = Workspace(workspace)
        self.audit = UiAudit(self.ws.ui_audit)
        self.session = Session(idle_minutes * 60, self.audit)
        self.jobs = JobRunner(self.session, self.audit, self._job_done)
        self.port = None
        self.server = None
        self.audit("start", version=VERSION, workspace=str(self.ws.root), pid=os.getpid())

    # helpers ----------------------------------------------------------------
    def p2cfg(self):
        return phase2.load_config(str(self.ws.p2_cfg))

    def mcfg(self):
        return phase1.load_config(str(self.ws.mapping_cfg))

    def py(self, script, *args):
        return [sys.executable, "-u", str(script), *[str(a) for a in args]]

    def delinea_env_name(self, cfg):
        d = cfg["delinea"]
        return d["client_secret_env"] if d.get("grant_type") == "client_credentials" else d["password_env"]

    def child_env(self, needs):
        cfg = self.p2cfg()
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        names = {"cyberark": cfg["cyberark"]["client_secret_env"], "delinea": self.delinea_env_name(cfg)}
        for n in (cfg["cyberark"]["client_secret_env"], cfg["delinea"]["password_env"],
                  cfg["delinea"]["client_secret_env"]):
            env.pop(n, None)                       # only what this session entered is passed on
        missing = [s for s in needs if not self.session.has(s)]
        if missing:
            label = {"cyberark": "CyberArk", "delinea": "Delinea"}
            raise UserError("Enter the " + " and ".join(label[m] for m in missing) +
                            " credential under Connections first.", 409)
        for s in needs:
            env[names[s]] = self.session.get(s)
        return env

    def operator(self):
        name = self.session.operator.strip()
        os_user = getpass.getuser()
        return f"{name} ({os_user}, via UI)" if name else f"{os_user} (via UI)"

    def review_args(self):
        if not self.ws.review.exists():
            raise UserError("No Migration_Review.csv yet. Generate the mapping first.", 409)
        a = ["--review", self.ws.review]
        if self.ws.members.exists():
            a += ["--members", self.ws.members]
        return a

    def review_shas(self):
        return {"review": sha256_file(self.ws.review), "members": sha256_file(self.ws.members)}

    def lock_path(self, mode):
        return self.ws.state[mode] / "run.lock"

    # job completion: remember what matters for the guided flow ---------------
    def _job_done(self, job):
        st = self.ws.load_state()
        rec = {"ts": job.finished, "exit_code": job.exit_code, "outcome": job.outcome(), "job_id": job.id}
        if job.action == "phase1":
            self.ws.save_state(phase1=rec)
        elif job.action == "plan":
            rec.update(job.meta.get("shas", {}))
            self.ws.save_state(plan=rec)
        elif job.action in ("preflight", "probe-delinea", "cleanup-rehearsal", "readiness", "readiness-fix"):
            self.ws.save_state(**{job.action.replace("-", "_"): rec})
        elif job.action in ("rehearsal", "migrate"):
            runs = st.get(job.action + "_runs", [])
            runs.insert(0, dict(rec, only_failed=job.meta.get("only_failed", False),
                                safes=job.meta.get("safes", []), stages=job.meta.get("stages")))
            self.ws.save_state(**{job.action + "_runs": runs[:50]})

    # actions -----------------------------------------------------------------
    def start_job(self, body):
        action = body.get("action", "")
        o = body.get("options") or {}
        cfgp = ["--config", self.ws.p2_cfg]
        safes = [s for s in (o.get("safes") or []) if isinstance(s, str) and s.strip()]
        safe_args = [x for s in safes for x in ("--safe", s)]
        meta = {}
        needs = []
        if self.jobs.busy():
            raise UserError(f"'{self.jobs.current.label}' is still running.", 409)

        if action == "phase1":
            if not self.ws.export.exists():
                raise UserError("Upload the Delinea export first (Data files).", 409)
            snap = self.ws.snapshot_phase1_output("before_phase1")
            meta["previous_output_saved_to"] = snap
            argv = self.py(P1_SCRIPT, "--input", self.ws.export, "--config", self.ws.mapping_cfg,
                           "--output-dir", self.ws.p1_out)
            if self.ws.permissions.exists():
                argv += ["--permissions", str(self.ws.permissions)]
            return self.jobs.start(action, "Generate mapping (Phase 1)", argv, self.child_env([]), meta=meta)

        if action == "plan":
            meta["shas"] = self.review_shas()
            argv = self.py(P2_SCRIPT, "plan", *cfgp, "--state-dir", self.ws.state["production"],
                           *self.review_args(), *safe_args)
            return self.jobs.start(action, "Plan (no changes)", argv, self.child_env([]), "production", meta)

        if action == "preflight":
            argv = self.py(P2_SCRIPT, "preflight", *cfgp, "--state-dir", self.ws.state["preflight"],
                           "--mapping-config", self.ws.mapping_cfg)
            if self.ws.review.exists():
                argv += [str(a) for a in self.review_args()]
            return self.jobs.start(action, "Tenant preflight (read-only)", argv,
                                   self.child_env(["cyberark"]), "preflight")

        if action in ("rehearsal", "migrate"):
            only_failed = bool(o.get("only_failed"))
            stages = [s for s in (o.get("stages") or ["safes", "members", "accounts"])
                      if s in ("safes", "members", "accounts")]
            if not stages:
                raise UserError("Choose at least one stage")
            mode = "rehearsal" if action == "rehearsal" else "production"
            word = "REHEARSE" if action == "rehearsal" else "MIGRATE"
            if (body.get("confirm") or "").strip() != word:
                raise UserError(f"Type {word} to confirm.")
            argv = self.py(P2_SCRIPT, "run", *cfgp, "--state-dir", self.ws.state[mode], *self.review_args(),
                           *safe_args, "--stages", ",".join(stages), "--yes", "--operator", self.operator())
            if only_failed:
                argv.append("--only-failed")
            if o.get("force_unlock"):
                argv.append("--force-unlock")
            if action == "rehearsal":
                prefix = (o.get("prefix") or "ZZTEST-").strip()
                if not re.match(r"^ZZ[A-Za-z0-9-]{0,10}$", prefix, re.IGNORECASE):
                    raise UserError("Rehearsal prefix must start with ZZ and use letters, digits or '-', "
                                    "e.g. ZZTEST-")
                argv += ["--rehearsal-prefix", prefix]
                needs = ["cyberark"]
                meta["prefix"] = prefix
            else:
                plan = self.ws.load_state().get("plan") or {}
                shas = self.review_shas()
                if not (plan.get("exit_code") == 0 and plan.get("review") == shas["review"]
                        and plan.get("members") == shas["members"]):
                    raise UserError("Run Plan on the current review files first, and fix any blockers. "
                                    "The review files changed since the last clean plan.", 409)
                needs = ["cyberark"] + (["delinea"] if "accounts" in stages else [])
            meta.update(only_failed=only_failed, stages=stages, safes=safes, shas=self.review_shas())
            label = ("Rehearsal" if action == "rehearsal" else "Migration") + (" (retry failed)" if only_failed else "")
            return self.jobs.start(action, label, argv, self.child_env(needs), mode, meta)

        if action == "cleanup-rehearsal":
            if (body.get("confirm") or "").strip() != "DELETE":
                raise UserError("Type DELETE to confirm.")
            argv = self.py(P2_SCRIPT, "cleanup-rehearsal", *cfgp, "--state-dir", self.ws.state["rehearsal"],
                           "--yes", "--operator", self.operator())
            if o.get("force_unlock"):
                argv.append("--force-unlock")
            return self.jobs.start(action, "Clean up rehearsal", argv, self.child_env(["cyberark"]), "rehearsal")

        if action == "probe-delinea":
            n = int(o.get("per_template") or 1)
            argv = self.py(P2_SCRIPT, "probe-delinea", *cfgp, "--state-dir", self.ws.state["production"],
                           *self.review_args(), "--per-template", max(1, min(n, 5)), "--operator", self.operator())
            return self.jobs.start(action, "Delinea access probe", argv, self.child_env(["delinea"]), "production")

        if action in ("report", "verify-audit", "status"):
            mode = o.get("mode") if o.get("mode") in ("production", "rehearsal") else "production"
            argv = self.py(P2_SCRIPT, action, *cfgp, "--state-dir", self.ws.state[mode])
            if action == "report":
                argv += ["--out", str(self.ws.state[mode] / f"migration_report_{stamp()}.csv")]
            labels = {"report": "Export ledger report", "verify-audit": "Verify audit log", "status": "Ledger status"}
            return self.jobs.start(action, f"{labels[action]} ({mode})", argv, self.child_env([]), mode)

        if action in ("readiness", "readiness-fix"):
            ps = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
            if not ps:
                raise UserError("PowerShell is not available here. The readiness checks run on the Windows "
                                "migration server.", 409)
            base = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(READINESS_SCRIPT), "-Mode", "Check",
                    "-NonInteractive", "-MigrationRoot", str(ROOT), "-ConfigPath", str(self.ws.p2_cfg),
                    "-StateDir", str(self.ws.state["production"]), "-ReportDir", str(self.ws.readiness)]
            if action == "readiness":
                return self.jobs.start(action, "Readiness checks", [ps, *base], self.child_env([]))
            ids = [i.strip().upper() for i in (o.get("ids") or []) if re.match(r"^[A-Za-z]+-[0-9A-Za-z]+$", i.strip())]
            if not ids:
                raise UserError("Choose at least one check to fix")
            args = base + ["-FixIds", ",".join(ids), "-Force"]
            meta["ids"] = ids
            if o.get("elevated") and IS_WINDOWS:
                def q(a):
                    a = f'"{a}"' if " " in a else a
                    return "'" + a.replace("'", "''") + "'"
                cmd = (f"$p = Start-Process -FilePath '{ps.replace(chr(39), chr(39) * 2)}' -Verb RunAs -Wait -PassThru -ArgumentList @("
                       + ",".join(q(a) for a in args) + "); exit $p.ExitCode")
                argv = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
                meta["elevated"] = True
                return self.jobs.start(action, "Readiness fixes (elevated window)", argv, self.child_env([]),
                                       meta=meta)
            return self.jobs.start(action, "Readiness fixes", [ps, *args], self.child_env([]), meta=meta)

        raise UserError(f"Unknown action '{action}'")

    # connections -------------------------------------------------------------
    def test_connection(self, system):
        cfg = self.p2cfg()
        if not self.session.has(system):
            raise UserError("Enter the credential first", 409)
        t0 = time.monotonic()
        try:
            if system == "cyberark":
                client = phase2.CyberArkClient(cfg, self.session.get("cyberark"))
            elif system == "delinea":
                client = phase2.DelineaClient(cfg, self.session.get("delinea"))
            else:
                raise UserError("Unknown system")
            client.renew()
            client = None                                    # token discarded
            result = {"ok": True, "message": "Signed in. The token was discarded."}
        except phase2.ApiError as e:
            result = {"ok": False, "message": self.session.redact(str(e)),
                      "hint": phase2.hint_for(e, "AUTH")}
        except UserError:
            raise
        except Exception as e:
            result = {"ok": False, "message": self.session.redact(f"{type(e).__name__}: {e}"),
                      "hint": "Check the URL, DNS, proxy and certificate trust (see the readiness checks)."}
        result["seconds"] = round(time.monotonic() - t0, 1)
        self.audit("connection_test", system=system, ok=result["ok"],
                   message=result["message"][:300])
        tests = self.ws.load_state().get("connection_tests", {})
        tests[system] = {"ok": result["ok"], "ts": utcnow()}
        self.ws.save_state(connection_tests=tests)
        return result

    # overview ----------------------------------------------------------------
    def ledger_summary(self, mode):
        db = self.ws.state[mode] / "migration_state.db"
        if not db.exists():
            return None
        with ro_db(db) as con:
            rows = con.execute("SELECT stage, status, COUNT(*) FROM objects GROUP BY stage, status").fetchall()
            runs = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        out = {"runs": runs, "stages": {}}
        for stage, status, n in rows:
            out["stages"].setdefault(stage, {})[status] = n
        return out

    def readiness_latest(self):
        reports = sorted(self.ws.readiness.glob("readiness_*.json"))
        if not reports:
            return None
        data = json.loads(reports[-1].read_text(encoding="utf-8-sig"))
        data["file"] = self.ws.rel(reports[-1])
        return data

    def overview(self):
        st = self.ws.load_state()
        cfg_raw = json.loads(self.ws.p2_cfg.read_text(encoding="utf-8"))
        steps = []

        def step(sid, title, status, detail):
            steps.append({"id": sid, "title": title, "status": status, "detail": detail})

        rd = None
        try:
            rd = self.readiness_latest()
        except (ValueError, OSError):
            pass
        if rd:
            checks = rd.get("checks") or []
            fails = sum(1 for c in checks if c.get("Status") == "Fail")
            warns = sum(1 for c in checks if c.get("Status") == "Warn")
            step("readiness", "Server readiness", "warn" if fails or warns else "done",
                 f"{fails} failed, {warns} warnings ({rd.get('generated', '')[:16]})")
        else:
            step("readiness", "Server readiness", "todo", "Not run yet")

        placeholders = [k for k, v in _walk(cfg_raw) if isinstance(v, str) and "EXAMPLE" in v]
        missing_ids = not cfg_raw.get("cyberark", {}).get("client_id")
        tests = st.get("connection_tests", {})
        if placeholders or missing_ids:
            step("connections", "Connections", "todo", "Fill in the tenant URLs and client ID")
        elif tests.get("cyberark", {}).get("ok"):
            step("connections", "Connections", "done", "CyberArk sign-in tested" +
                 ("; Delinea tested" if tests.get("delinea", {}).get("ok") else ""))
        else:
            step("connections", "Connections", "warn", "Configured; sign-in not tested yet")

        if self.ws.export.exists():
            step("files", "Data files", "done", "Export uploaded" +
                 ("; permissions uploaded" if self.ws.permissions.exists() else "; no permissions file (optional)"))
        else:
            step("files", "Data files", "todo", "Upload the Delinea export")

        p1 = st.get("phase1")
        if self.ws.review.exists():
            stale = p1 and self.ws.export.exists() and self.ws.export.stat().st_mtime > self.ws.review.stat().st_mtime
            step("mapping", "Mapping rules", "warn" if stale else "done",
                 "Export is newer than the mapping; regenerate" if stale else "Mapping generated")
        else:
            step("mapping", "Mapping rules", "todo", "Generate the mapping")

        plan = st.get("plan") or {}
        shas = self.review_shas() if self.ws.review.exists() else {}
        if not self.ws.review.exists():
            step("review", "Review", "todo", "Waiting for the mapping")
        elif plan.get("review") == shas.get("review") and plan.get("members") == shas.get("members"):
            step("review", "Review", "done" if plan.get("exit_code") == 0 else "warn",
                 "Plan is clean" if plan.get("exit_code") == 0 else "Plan has blockers")
        else:
            step("review", "Review", "todo", "Review the mapping, then run Plan")

        reh = self.ledger_summary("rehearsal")
        if reh:
            failed = sum(s.get("FAILED", 0) for s in reh["stages"].values())
            done = sum(s.get("DONE", 0) for s in reh["stages"].values())
            step("rehearsal", "Rehearsal", "warn" if failed else "done", f"{done} done, {failed} failed")
        else:
            step("rehearsal", "Rehearsal", "todo", "Optional but recommended")

        prod = self.ledger_summary("production")
        if prod and prod["runs"]:
            failed = sum(s.get("FAILED", 0) + s.get("IN_PROGRESS", 0) for s in prod["stages"].values())
            done = sum(s.get("DONE", 0) for s in prod["stages"].values())
            step("migrate", "Migration", "warn" if failed else "done", f"{done} done, {failed} outstanding")
            step("results", "Results", "done" if not failed else "warn", "Review the ledger and audit log")
        else:
            step("migrate", "Migration", "todo", "Not started")
            step("results", "Results", "todo", "Available after the first run")

        cfg = self.p2cfg()
        return {
            "version": VERSION, "workspace": str(self.ws.root), "host": socket.gethostname(),
            "os_user": getpass.getuser(), "is_windows": IS_WINDOWS,
            "session": {"operator": self.session.operator, "idle_left": self.session.idle_left(),
                        "credentials": {"cyberark": self.session.has("cyberark"),
                                        "delinea": self.session.has("delinea")},
                        "delinea_grant": cfg["delinea"].get("grant_type", "password")},
            "steps": steps,
            "job": self.jobs.current.brief() if self.jobs.current else None,
            "locks": {m: self.lock_path(m).exists() for m in ("production", "rehearsal")},
            "plan": plan, "review_shas": shas,
        }

    # files -------------------------------------------------------------------
    def list_files(self):
        out = []
        for p in sorted(self.ws.root.rglob("*")):
            if not p.is_file() or p.name.endswith((".tmp", ".lock")) or p.name in ("ui_state.json",):
                continue
            rel = self.ws.rel(p)
            area = rel.split("/")[0]
            if area == "state":
                area = "state/" + rel.split("/")[1]
            stt = p.stat()
            out.append({"path": rel, "area": area, "size": stt.st_size,
                        "modified": datetime.fromtimestamp(stt.st_mtime, timezone.utc).isoformat(timespec="seconds")})
        return out

    def upload(self, kind, filename, data):
        if self.jobs.busy():
            raise UserError("Wait for the running job to finish before replacing files.", 409)
        text, enc = decode_upload(data)
        mcfg = self.mcfg()
        if kind == "export":
            clean, info = scrub_export(text, mcfg)
            dest = self.ws.export
        elif kind == "permissions":
            clean, info = scrub_table(text, mcfg["secret_column_patterns"],
                                      [["Group", "Principal", "Group Name", "User/Group"],
                                       ["Permission", "Role", "Access"]], "permissions")
            dest = self.ws.permissions
        elif kind in ("review", "members"):
            req = ([["Migrate"], ["Target CyberArk Safe"], ["Delinea Secret ID"], ["Delinea Secret Field"]]
                   if kind == "review" else [["Target CyberArk Safe"], ["Member_Name"], ["CyberArk_Role"]])
            pats = [p for p in mcfg["secret_column_patterns"]]
            clean, info = scrub_table(text, pats, req, "review" if kind == "review" else "members")
            info["previous_saved_to"] = self.ws.snapshot_phase1_output(f"before_upload_{kind}")
            dest = self.ws.review if kind == "review" else self.ws.members
        else:
            raise UserError("Unknown file kind")
        atomic_write(dest, clean, encoding="utf-8-sig")
        info.update(kind=kind, saved_as=self.ws.rel(dest), original_name=Path(filename).name[:200],
                    original_sha256=sha256_bytes(data), saved_sha256=sha256_file(dest), encoding=enc)
        self.audit("file_uploaded", **{k: v for k, v in info.items() if k != "warnings"},
                   warnings=info["warnings"])
        return info

    def delete_input(self, kind):
        p = {"export": self.ws.export, "permissions": self.ws.permissions}.get(kind)
        if not p:
            raise UserError("Only uploaded inputs can be removed here")
        if p.exists():
            p.unlink()
            self.audit("file_removed", path=self.ws.rel(p))
        return {"ok": True}

    # review ------------------------------------------------------------------
    def review_page(self, which, q, flt, offset, limit):
        path = self.ws.review if which == "accounts" else self.ws.members
        if not path.exists():
            raise UserError("Not generated yet", 404)
        header, rows = read_table(path)
        idx = [i for i, r in enumerate(rows) if row_matches(header, r, q, flt)]
        page = [{"row": i, "values": rows[i]} for i in idx[offset:offset + limit]]
        return {"columns": header, "editable": ACCOUNT_EDITABLE if which == "accounts" else MEMBER_EDITABLE,
                "total": len(rows), "matched": len(idx), "offset": offset, "rows": page,
                "roles": list(self.p2cfg().get("role_permissions", {}))}

    def safes_summary(self):
        if not self.ws.review.exists():
            raise UserError("Not generated yet", 404)
        cfg = self.p2cfg()
        header, rows = read_table(self.ws.review)
        h = {c: i for i, c in enumerate(header)}
        safes = OrderedDict()
        for r in rows:
            name = r[h["Target CyberArk Safe"]]
            s = safes.setdefault(name, {"safe": name, "accounts": 0, "included": 0, "members": 0,
                                        "problems": phase2.safe_name_problems(name, cfg)})
            s["accounts"] += 1
            s["included"] += 1 if phase2.is_yes(r[h["Migrate"]]) else 0
        if self.ws.members.exists():
            mh, mrows = read_table(self.ws.members)
            mi = mh.index("Target CyberArk Safe")
            for r in mrows:
                if r[mi] in safes:
                    safes[r[mi]]["members"] += 1
        return {"safes": list(safes.values()), "max_length": cfg["safe_name_max_length"]}

    def _require_idle_for_edit(self):
        if self.jobs.busy() and self.jobs.current.action in ("rehearsal", "migrate", "phase1"):
            raise UserError("A run is in progress. Edit the review files after it finishes.", 409)

    def edit_review(self, which, body):
        self._require_idle_for_edit()
        cfg = self.p2cfg()
        path = self.ws.review if which == "accounts" else self.ws.members
        if not path.exists():
            raise UserError("Not generated yet", 404)
        header, rows = read_table(path)
        h = {c: i for i, c in enumerate(header)}
        editable = ACCOUNT_EDITABLE if which == "accounts" else MEMBER_EDITABLE
        changes = list(body.get("changes") or [])
        bulk = body.get("bulk")
        if bulk:
            if bulk.get("column") not in ("Migrate", "Target Platform ID", "Target CyberArk Safe", "CyberArk_Role"):
                raise UserError("Bulk edit supports Migrate, Target Platform ID, Target CyberArk Safe and CyberArk_Role")
            for i, r in enumerate(rows):
                if row_matches(header, r, bulk.get("q", ""), bulk.get("filter", "")):
                    changes.append({"row": i, "column": bulk["column"], "value": bulk.get("value", "")})
        log = []
        for c in changes:
            col, i = c.get("column"), c.get("row")
            if col not in editable or col not in h:
                raise UserError(f"'{col}' cannot be edited")
            if not isinstance(i, int) or not 0 <= i < len(rows):
                raise UserError("Row out of range (the file may have been regenerated; reload)", 409)
            value = validate_cell(col, c.get("value", ""), cfg)
            old = rows[i][h[col]]
            if old == value:
                continue
            rows[i][h[col]] = value
            ident = rows[i][h["Delinea Secret ID"]] if "Delinea Secret ID" in h else \
                f"{rows[i][h['Target CyberArk Safe']]}/{rows[i][h.get('Member_Name', 0)]}"
            log.append({"row": i, "id": ident, "column": col, "old": old, "new": value})
            if which == "accounts" and col == "Target CyberArk Safe":
                rows[i][h["Valid_Safe_Name"]] = "TRUE"
                rows[i][h["Safe_Name_Issues"]] = ""
                rows[i][h["Safe_Mapping_Source"]] = "manual (UI)"
        deletes = sorted({int(i) for i in (body.get("delete_rows") or [])}, reverse=True) if which == "members" else []
        for i in deletes:
            if 0 <= i < len(rows):
                log.append({"row": i, "deleted": dict(zip(header, rows[i]))})
                del rows[i]
        for add in (body.get("add_rows") or []) if which == "members" else []:
            safe = validate_cell("Target CyberArk Safe", add.get("safe", ""), cfg)
            member = validate_cell("Member_Name", add.get("member", ""), cfg)
            role = validate_cell("CyberArk_Role", add.get("role", ""), cfg)
            new = [""] * len(header)
            for col, v in (("Target CyberArk Safe", safe), ("Member_Name", member), ("Member_Type", "Group"),
                           ("CyberArk_Role", role), ("Review_Notes", "added in UI")):
                if col in h:
                    new[h[col]] = v
            rows.append(new)
            log.append({"added": dict(zip(header, new))})
        if not log:
            return {"changed": 0}
        backup = self.ws.snapshot_phase1_output(f"before_edit_{which}")
        write_table(path, header, rows)
        for n in range(0, len(log), 2000):
            self.audit("review_edited", file=self.ws.rel(path), changes=log[n:n + 2000],
                       total_changes=len(log), backup=backup, sha256=sha256_file(path))
        return {"changed": len(log), "backup": backup}

    def rename_safe(self, body):
        self._require_idle_for_edit()
        cfg = self.p2cfg()
        old, new = body.get("old", ""), validate_cell("Target CyberArk Safe", body.get("new", ""), cfg)
        if not self.ws.review.exists():
            raise UserError("Not generated yet", 404)
        backup = self.ws.snapshot_phase1_output("before_rename_safe")
        counts = {}
        for path in (self.ws.review, self.ws.members):
            if not path.exists():
                continue
            header, rows = read_table(path)
            h = {c: i for i, c in enumerate(header)}
            n = 0
            for r in rows:
                if r[h["Target CyberArk Safe"]] == old:
                    r[h["Target CyberArk Safe"]] = new
                    if "Valid_Safe_Name" in h:
                        r[h["Valid_Safe_Name"]], r[h["Safe_Name_Issues"]] = "TRUE", ""
                        r[h["Safe_Mapping_Source"]] = "manual (UI)"
                    n += 1
            write_table(path, header, rows)
            counts[path.name] = n
        self.audit("safe_renamed", old=old, new=new, rows=counts, backup=backup)
        return {"renamed": counts, "backup": backup}

    # results -----------------------------------------------------------------
    def ledger(self, mode, stage, status, q, offset, limit):
        db = self.ws.state[mode] / "migration_state.db"
        if not db.exists():
            return {"total": 0, "rows": [], "summary": None}
        where, args = [], []
        if stage:
            where.append("stage=?")
            args.append(stage)
        if status:
            where.append("status=?")
            args.append(status)
        if q:
            where.append("(safe LIKE ? OR object LIKE ? OR delinea_secret_id LIKE ? OR last_error LIKE ?)")
            args += [f"%{q}%"] * 4
        w = (" WHERE " + " AND ".join(where)) if where else ""
        with ro_db(db) as con:
            total = con.execute(f"SELECT COUNT(*) FROM objects{w}", args).fetchone()[0]
            rows = con.execute(f"SELECT * FROM objects{w} ORDER BY CASE stage WHEN 'SAFE' THEN 1 WHEN 'MEMBER' "
                               f"THEN 2 ELSE 3 END, safe, object LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
            runs = con.execute("SELECT * FROM runs ORDER BY started DESC LIMIT 100").fetchall()
        return {"total": total, "rows": [dict(r) for r in rows], "runs": [dict(r) for r in runs],
                "summary": self.ledger_summary(mode)}

    def progress(self, mode):
        """Expected totals from the review files, and where the ledger stands now."""
        totals = {}
        job = self.jobs.current
        if self.ws.review.exists():
            safes_filter = set(s.lower() for s in (job.meta.get("safes") or [])) if job and job.mode == mode else set()
            header, rows = read_table(self.ws.review)
            h = {c: i for i, c in enumerate(header)}
            inc = [r for r in rows if phase2.is_yes(r[h["Migrate"]])
                   and (not safes_filter or r[h["Target CyberArk Safe"]].lower() in safes_filter)]
            safe_names = {r[h["Target CyberArk Safe"]] for r in inc}
            members = 0
            if self.ws.members.exists():
                mh, mrows = read_table(self.ws.members)
                mi = mh.index("Target CyberArk Safe")
                members = sum(1 for r in mrows if r[mi] in safe_names)
            totals = {"SAFE": len(safe_names), "MEMBER": members, "ACCOUNT": len(inc)}
        current = None
        db = self.ws.state[mode] / "migration_state.db"
        if db.exists() and job and job.mode == mode and job.action in ("rehearsal", "migrate"):
            with ro_db(db) as con:
                run = con.execute("SELECT run_id, started, outcome FROM runs ORDER BY started DESC LIMIT 1").fetchone()
                if run and run["started"] >= job.started[:19]:
                    counts = con.execute("SELECT stage, status, COUNT(*) FROM objects WHERE last_run_id=? "
                                         "GROUP BY stage, status", (run["run_id"],)).fetchall()
                    current = {"run_id": run["run_id"], "outcome": run["outcome"], "stages": {}}
                    for stage, status, n in counts:
                        current["stages"].setdefault(stage, {})[status] = n
        return {"totals": totals, "ledger": self.ledger_summary(mode), "current_run": current,
                "lock": self.lock_path(mode).exists()}

    def audit_entries(self, which, offset, limit):
        path = self.ws.ui_audit if which == "ui" else self.ws.state.get(which, Path("-")) / "audit_log.jsonl"
        if not path.exists():
            return {"total": 0, "entries": [], "file": None}
        with open(path, encoding="utf-8") as fh:
            lines = [l for l in fh if l.strip()]
        lines.reverse()
        entries = []
        for l in lines[offset:offset + limit]:
            try:
                entries.append(json.loads(l))
            except ValueError:
                entries.append({"event": "UNREADABLE LINE", "raw": l[:200]})
        return {"total": len(lines), "entries": entries, "file": self.ws.rel(path)}

    def verify(self, which):
        path = self.ws.ui_audit if which == "ui" else self.ws.state.get(which, Path("-")) / "audit_log.jsonl"
        if not path.exists():
            return {"ok": False, "message": "No audit log yet"}
        ok, msg = phase2.verify_audit(path)
        self.audit("audit_verified", log=self.ws.rel(path), ok=ok, message=msg)
        return {"ok": ok, "message": msg}

    def shutdown(self, reason):
        self.session.end(reason)
        self.audit("stop", reason=reason)
        self.audit.close()


@contextlib.contextmanager
def ro_db(path):
    con = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.close()


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
NO_SESSION_PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><title>Migration UI</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:80px auto;padding:0 16px;color:#1f2328}
code{background:#f0efec;padding:2px 6px;border-radius:4px}</style></head><body>
<h1>Session needed</h1><p>For security, the migration UI opens only from the one-time link shown in the
console window where it was started. The session may also have ended after inactivity.</p>
<p>Go to that window and press <code>Enter</code> to print a fresh link.</p></body></html>"""

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Handler(BaseHTTPRequestHandler):
    app = None                       # set by serve()
    server_version = "MigrationUI"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):   # no request logging: URLs can hold the launch token
        pass

    # plumbing ----------------------------------------------------------------
    def _send(self, status, body=b"", ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, status, message, hint=""):
        if self.command != "GET":
            self.close_connection = True          # an unread request body must not leak into the next request
        self._send(status, {"error": message, "hint": hint})

    def _host_ok(self):
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{self.app.port}", f"localhost:{self.app.port}"}

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin.lower() in {f"http://127.0.0.1:{self.app.port}", f"http://localhost:{self.app.port}"}

    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "mui_sid":
                return v
        return ""

    def _body(self, limit=1024 * 1024):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise UserError(f"Request too large (limit {limit // (1024 * 1024)} MB)", 413)
        return self.rfile.read(n) if n else b""

    def _json(self):
        try:
            return json.loads(self._body() or b"{}")
        except ValueError:
            raise UserError("Body is not valid JSON")

    def _dispatch(self):
        if not self._host_ok():
            return self._err(421, "Wrong host. Use the link printed in the console.")
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        path = u.path
        if path == "/launch" and self.command == "GET":
            sid = self.app.session.exchange(q.get("token", ""))
            if not sid:
                return self._send(403, NO_SESSION_PAGE, "text/html; charset=utf-8")
            return self._send(303, b"", "text/plain", {
                "Location": "/", "Set-Cookie": f"mui_sid={sid}; HttpOnly; SameSite=Strict; Path=/"})
        poll = self.headers.get("X-Poll") == "1"
        if not self.app.session.check(self._cookie(), user_activity=not poll):
            if path.startswith("/api/"):
                return self._err(401, "Session ended. Get a new link from the console window (press Enter there).")
            return self._send(401, NO_SESSION_PAGE, "text/html; charset=utf-8")
        if self.command != "GET":
            if not self._origin_ok() or self.headers.get("X-Migration-UI") != "1":
                return self._err(403, "Cross-site request refused")
        if path.startswith("/api/"):
            return self._api(path[5:], q)
        return self._static(path)

    def _static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        p = (STATIC / rel).resolve()
        if STATIC.resolve() not in p.parents or not p.is_file():
            p = STATIC / "index.html"                      # client-side routes
        if not p.exists():
            return self._send(500, b"UI not built: run npm run build in ui/web", "text/plain")
        ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(200, p.read_bytes(), ctype)

    def _api(self, route, q):
        a = self.app
        m = self.command
        try:
            if route == "overview" and m == "GET":
                return self._send(200, a.overview())
            if route == "session" and m == "PUT":
                body = self._json()
                name = str(body.get("operator", ""))[:80].strip()
                if a.session.operator != name:
                    a.session.operator = name
                    a.audit.operator_label = name
                    a.audit("operator_set", operator_name=name)
                return self._send(200, {"ok": True})
            if route == "session" and m == "DELETE":
                a.session.end("ended by user")
                return self._send(200, {"ok": True}, headers={"Set-Cookie": "mui_sid=; Max-Age=0; Path=/"})
            if route == "shutdown" and m == "POST":
                if a.jobs.busy():
                    raise UserError("A job is running. Stop it or wait before shutting down.", 409)
                self._send(200, {"ok": True})
                threading.Thread(target=lambda: (a.shutdown("shut down from the UI"), a.server.shutdown()),
                                 daemon=True).start()
                return
            if route == "config" and m == "GET":
                return self._send(200, {
                    "phase2": json.loads(a.ws.p2_cfg.read_text(encoding="utf-8")),
                    "mapping": json.loads(a.ws.mapping_cfg.read_text(encoding="utf-8")),
                    "policy": CALL_POLICY, "warnings": validate_phase2_config(
                        json.loads(a.ws.p2_cfg.read_text(encoding="utf-8")))})
            if route in ("config/phase2", "config/mapping") and m == "PUT":
                new = self._json().get("config")
                which = route.split("/")[1]
                path = a.ws.p2_cfg if which == "phase2" else a.ws.mapping_cfg
                warnings = validate_phase2_config(new) if which == "phase2" else validate_mapping_config(new)
                old = json.loads(path.read_text(encoding="utf-8"))
                changes = config_changes(old, new)
                atomic_write(path, json.dumps(new, indent=2))
                a.audit("config_saved", file=a.ws.rel(path), changes=changes, sha256=sha256_file(path))
                return self._send(200, {"ok": True, "warnings": warnings, "changes": len(changes)})
            if route == "credentials" and m == "POST":
                body = self._json()
                system, value = body.get("system"), body.get("value", "")
                if system not in ("cyberark", "delinea"):
                    raise UserError("Unknown system")
                if not isinstance(value, str) or not value or len(value) > 4096:
                    raise UserError("Enter the credential")
                a.session.set_cred(system, value)
                value = body = None
                a.audit("credential_set", system=system, stored="memory only")
                return self._send(200, {"ok": True})
            if route.startswith("credentials/") and m == "DELETE":
                system = route.split("/", 1)[1]
                a.session.clear_cred(system)
                a.audit("credential_cleared", system=system)
                return self._send(200, {"ok": True})
            if route == "connections/test" and m == "POST":
                return self._send(200, a.test_connection(self._json().get("system")))
            if route == "readiness" and m == "GET":
                return self._send(200, {"latest": a.readiness_latest(), "is_windows": IS_WINDOWS,
                                        "powershell": bool(shutil.which("powershell.exe") or shutil.which("powershell")
                                                           or shutil.which("pwsh"))})
            if route == "files" and m == "GET":
                return self._send(200, {"files": a.list_files(),
                                        "inputs": {"export": a.ws.export.exists(),
                                                   "permissions": a.ws.permissions.exists()}})
            if route.startswith("files/") and m == "POST":
                kind = route.split("/", 1)[1]
                name = urllib.parse.unquote(self.headers.get("X-Filename") or "upload.csv")
                data = self._body(MAX_UPLOAD)
                return self._send(200, a.upload(kind, name, data))
            if route.startswith("files/") and m == "DELETE":
                return self._send(200, a.delete_input(route.split("/", 1)[1]))
            if route == "download" and m == "GET":
                p = a.ws.resolve(q.get("path", ""))
                if not p.is_file():
                    raise UserError("File not found", 404)
                a.audit("download", path=a.ws.rel(p), sha256=sha256_file(p))
                ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
                return self._send(200, p.read_bytes(), ctype, {
                    "Content-Disposition": f'attachment; filename="{p.name}"'})
            if route.startswith("review/") and m == "GET":
                which = route.split("/", 1)[1]
                if which == "safes":
                    return self._send(200, a.safes_summary())
                if which not in ("accounts", "members"):
                    raise UserError("Unknown review file", 404)
                return self._send(200, a.review_page(which, q.get("q", ""), q.get("filter", ""),
                                                     int(q.get("offset", 0)), min(int(q.get("limit", 100)), 500)))
            if route in ("review/accounts", "review/members") and m == "PUT":
                return self._send(200, a.edit_review(route.split("/")[1], self._json()))
            if route == "review/rename-safe" and m == "POST":
                return self._send(200, a.rename_safe(self._json()))
            if route == "jobs" and m == "POST":
                return self._send(200, a.start_job(self._json()).brief())
            if route == "jobs" and m == "GET":
                return self._send(200, {"current": a.jobs.current.brief() if a.jobs.current else None,
                                        "history": [j.brief() for j in a.jobs.history]})
            if route.startswith("jobs/") and route.endswith("/output") and m == "GET":
                return self._send(200, a.jobs.output(route.split("/")[1], int(q.get("since", 0))))
            if route == "jobs/current/stop" and m == "POST":
                a.jobs.stop()
                return self._send(200, {"ok": True})
            if route == "progress" and m == "GET":
                return self._send(200, a.progress(q.get("mode") if q.get("mode") in ("production", "rehearsal")
                                                  else "production"))
            if route == "ledger" and m == "GET":
                mode = q.get("mode") if q.get("mode") in ("production", "rehearsal") else "production"
                return self._send(200, a.ledger(mode, q.get("stage", ""), q.get("status", ""), q.get("q", ""),
                                                int(q.get("offset", 0)), min(int(q.get("limit", 100)), 500)))
            if route == "audit" and m == "GET":
                which = q.get("log") if q.get("log") in ("production", "rehearsal", "ui") else "production"
                return self._send(200, a.audit_entries(which, int(q.get("offset", 0)),
                                                       min(int(q.get("limit", 100)), 500)))
            if route == "audit/verify" and m == "POST":
                which = self._json().get("log")
                if which not in ("production", "rehearsal", "ui"):
                    raise UserError("Unknown log")
                return self._send(200, a.verify(which))
            if route == "preflight" and m == "GET":
                reports = sorted(a.ws.state["preflight"].glob("preflight_*.json"))
                return self._send(200, json.loads(reports[-1].read_text(encoding="utf-8")) if reports else {})
            return self._err(404, "Not found")
        except UserError as e:
            return self._err(e.status, str(e), e.hint)
        except (ValueError, KeyError) as e:
            return self._err(400, f"Bad request: {e}")
        except Exception as e:
            a.audit("error", route=route, error=a.session.redact(f"{type(e).__name__}: {e}")[:500])
            return self._err(500, a.session.redact(f"Unexpected error: {type(e).__name__}: {e}"))

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def do_DELETE(self):
        self._dispatch()


def serve(workspace, port=0, open_browser=True, idle_minutes=15, print_fn=print):
    app = App(workspace, idle_minutes)
    Handler.app = app
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    app.server = server
    app.port = server.server_address[1]

    def link():
        return f"http://127.0.0.1:{app.port}/launch?token={app.session.new_launch_token()}"

    def expiry_loop():
        while True:
            time.sleep(30)
            app.session.expire_if_idle()

    threading.Thread(target=expiry_loop, daemon=True).start()
    first = link()
    print_fn(f"Migration UI {VERSION}  (workspace: {app.ws.root})")
    print_fn("Listening on 127.0.0.1 only. Open this one-time link in the browser on THIS server:")
    print_fn(f"  {first}")
    print_fn("Press Enter here for a fresh link (e.g. after the session idles out). Ctrl+C stops the UI.")
    if open_browser:
        webbrowser.open(first)

    def console():
        for _ in sys.stdin:
            print_fn(f"  {link()}")
    if sys.stdin and sys.stdin.isatty():
        threading.Thread(target=console, daemon=True).start()
    return app, server


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local web UI for the Delinea -> CyberArk migration")
    ap.add_argument("--workspace", default=str(ROOT / "workspace"),
                    help="Folder for inputs, configs, review files, ledgers and logs (default: ./workspace)")
    ap.add_argument("--port", type=int, default=0, help="Port on 127.0.0.1 (default: a free one)")
    ap.add_argument("--no-browser", action="store_true", help="Do not open the browser")
    ap.add_argument("--idle-minutes", type=int, default=15, help="End the session after this much inactivity")
    args = ap.parse_args(argv)
    app, server = serve(args.workspace, args.port, not args.no_browser, args.idle_minutes)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if app.jobs.busy():
            print("Stopping the running job...")
            try:
                app.jobs.stop()
                app.jobs.current.proc.wait(timeout=25)
            except Exception:
                pass
        if not app.audit.log.fh.closed:
            app.shutdown("stopped from the console")
        print("Migration UI stopped. Credentials held in memory are gone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
