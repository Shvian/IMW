"""Local staging database (SQLite, standard library).

Workflow:
  ingest   load exports into the database once (secrets encrypted with DPAPI)
  map      apply the config rules; results go into plan_* tables you can query
  set      record deliberate changes (Migrate, Safe, platform, account name)
  query    read-only SQL or built-in reports
  extract  write review and upload CSVs, optionally for a subset (a wave)

Secrets live only in records.secret_enc, encrypted. Everything else is plain so
it can be queried. Queries can never read secret_enc: the read-only connection
returns NULL for it.
"""

import base64
import csv
import getpass
import hashlib
import json
import logging
import platform as _platform
import sqlite3
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from . import csvsafe
from .model import Grant, SourceRecord
from .owner import OwnerError, current_identity, restrict
from .protect import ProtectError, get_protector, new_salt
from .transform import SAFE_OVERRIDE_KEYS, _changed, build_plan, rebuild_totals, safe_settings, sanitize_record
from .writers import write_manifest, write_review, write_upload

log = logging.getLogger("imw.store")
SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS inputs (
  id INTEGER PRIMARY KEY, source TEXT, path TEXT, sha256 TEXT, records INTEGER,
  permissions_path TEXT, permissions_sha256 TEXT, loaded_utc TEXT, loaded_by TEXT);
CREATE TABLE IF NOT EXISTS records (
  record_id TEXT PRIMARY KEY, input_id INTEGER, source TEXT, source_file TEXT, source_id TEXT,
  source_ref TEXT, name TEXT, folder TEXT, folder_json TEXT, type TEXT, address TEXT,
  username TEXT, secret_type TEXT, has_secret INTEGER, secret_enc TEXT, has_grants INTEGER,
  access_source TEXT, target_safe TEXT, target_platform TEXT, extra_json TEXT, notes_json TEXT);
CREATE TABLE IF NOT EXISTS grants (record_id TEXT, member TEXT, permission TEXT, member_type TEXT);
CREATE INDEX IF NOT EXISTS grants_record ON grants(record_id);
CREATE TABLE IF NOT EXISTS edits (
  record_id TEXT, field TEXT, value TEXT, changed_utc TEXT, changed_by TEXT, reason TEXT,
  PRIMARY KEY (record_id, field));
CREATE TABLE IF NOT EXISTS plan_accounts (
  record_id TEXT PRIMARY KEY, migrate TEXT, status TEXT, notes TEXT, target_safe TEXT,
  proposed_safe TEXT, valid_safe_name TEXT, safe_name_issues TEXT, safe_mapping_source TEXT,
  platform_id TEXT, platform_source TEXT, account_name TEXT, address TEXT, username TEXT,
  secret_type TEXT, has_secret TEXT, source TEXT, source_ref TEXT, source_type TEXT, folder TEXT,
  access_groups TEXT, access_source TEXT);
CREATE TABLE IF NOT EXISTS plan_safes (
  safe_name TEXT PRIMARY KEY, length INTEGER, valid_safe_name TEXT, proposed_names TEXT,
  issues TEXT, mapping_sources TEXT, accounts INTEGER, accounts_to_upload INTEGER,
  managing_cpm TEXT, description TEXT, retention TEXT, location TEXT, olac_enabled TEXT,
  auto_purge TEXT, rule_names TEXT, override_json TEXT, rules_json TEXT);
CREATE TABLE IF NOT EXISTS plan_members (
  safe_name TEXT, source_member TEXT, member_name TEXT, search_in TEXT, member_type TEXT,
  source_permission TEXT, role TEXT, accounts INTEGER, notes TEXT, directory_source TEXT);
CREATE TABLE IF NOT EXISTS member_edits (
  safe_name TEXT, member_name TEXT, action TEXT, search_in TEXT, member_type TEXT, role TEXT,
  changed_utc TEXT, changed_by TEXT, reason TEXT, PRIMARY KEY (safe_name, member_name));
CREATE TABLE IF NOT EXISTS member_overrides (
  member_key TEXT PRIMARY KEY, member_name TEXT, member_type TEXT, search_in TEXT,
  changed_utc TEXT, changed_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS safe_overrides (
  safe_key TEXT PRIMARY KEY, settings_json TEXT, changed_utc TEXT, changed_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts TEXT, user TEXT, host TEXT, action TEXT, detail TEXT);
CREATE VIEW IF NOT EXISTS accounts AS SELECT * FROM plan_accounts;
"""

EDIT_FIELDS = OrderedDict([("migrate", "Migrate"), ("target_safe", "Target_Safe"),
                           ("platform_id", "Platform_ID"), ("account_name", "Account_Name")])

REPORTS = OrderedDict([
    ("summary", "SELECT status, migrate, COUNT(*) AS accounts FROM accounts GROUP BY status, migrate "
                "ORDER BY status, migrate"),
    ("inputs", "SELECT id, source, path, records, loaded_utc, loaded_by, sha256 FROM inputs ORDER BY id"),
    ("safes", "SELECT * FROM plan_safes ORDER BY safe_name"),
    ("invalid-safes", "SELECT * FROM plan_safes WHERE valid_safe_name = 'FALSE' ORDER BY safe_name"),
    ("errors", "SELECT record_id, notes, target_safe, platform_id, account_name, source_ref "
               "FROM accounts WHERE status = 'ERROR' ORDER BY record_id"),
    ("review", "SELECT record_id, notes, target_safe, platform_id, account_name, source_ref "
               "FROM accounts WHERE status = 'REVIEW' ORDER BY record_id"),
    ("no-access", "SELECT record_id, folder, target_safe, account_name FROM accounts "
                  "WHERE access_groups = '' ORDER BY folder"),
    ("members", "SELECT * FROM plan_members ORDER BY safe_name, member_name"),
    ("platforms", "SELECT platform_id, source_type, COUNT(*) AS accounts FROM accounts "
                  "GROUP BY platform_id, source_type ORDER BY platform_id"),
    ("edits", "SELECT * FROM edits ORDER BY changed_utc"),
    ("audit", "SELECT * FROM audit ORDER BY id"),
])


class StoreError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _user():
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Store:
    def __init__(self, path, create=False, protector=None):
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise StoreError(f"database {self.path} does not exist; run 'ingest' first")
        new = not self.path.exists()
        try:
            me = current_identity()
        except OwnerError as exc:
            raise StoreError(str(exc))
        try:
            self.db = sqlite3.connect(str(self.path))
            self.db.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        except sqlite3.OperationalError as exc:
            if not new:
                raise StoreError(f"Can't open {self.path} ({exc}). It probably belongs to another Windows user: "
                                 "only the user who created a database can open it.")
            raise
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        # Plan tables are rebuilt by every map, so an older layout is simply recreated.
        for table, column in (("plan_safes", "managing_cpm"), ("plan_safes", "rules_json"),
                              ("plan_members", "directory_source")):
            cols = [r[1] for r in self.db.execute(f"PRAGMA table_info({table})")]
            if cols and column not in cols:
                self.db.execute(f"DROP TABLE {table}")
        self.db.executescript(SCHEMA)
        if new:
            self._set_meta("schema_version", SCHEMA_VERSION)
            self._set_meta("created_utc", _now())
            self._set_meta("created_by", f"{_user()}@{_platform.node()}")
            self._set_meta("salt", base64.b64encode(new_salt()).decode())
            self._set_meta("protector", protector or "dpapi")
            self._set_meta("owner_sid", me["sid"])
            self._set_meta("owner_name", me["display"])
            self.db.commit()
            try:
                restrict(self.path, me["sid"])
            except OwnerError as exc:
                self.db.close()
                self.path.unlink()
                raise StoreError(str(exc))
        else:
            self._check_owner(me)
        self._protector = None

    def _check_owner(self, me):
        """Only the Windows user who created the database may open it (see owner.py)."""
        owner = self.meta("owner_sid")
        if owner is None:      # made before owners were recorded: the creator's name decides
            creator = (self.meta("created_by") or "").rsplit("@", 1)[0]
            if creator.lower() != (me["user"] or "").lower():
                self.db.close()
                raise StoreError(f"This database was created by {creator}. You are signed in to Windows as "
                                 f"{me['display']}, so it stays closed.")
            self._set_meta("owner_sid", me["sid"])
            self._set_meta("owner_name", me["display"])
            self.db.commit()
            restrict(self.path, me["sid"])
        elif owner != me["sid"]:
            name = self.meta("owner_name") or owner
            self.db.close()
            raise StoreError(f"This database belongs to {name}. You are signed in to Windows as "
                             f"{me['display']}, so it stays closed. Only the user who created a database can open it.")

    # -- meta / audit -----------------------------------------------------
    def _set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))

    def meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def audit(self, action, **detail):
        self.db.execute("INSERT INTO audit(ts, user, host, action, detail) VALUES (?,?,?,?,?)",
                        (_now(), _user(), _platform.node(), action, json.dumps(detail, default=str)))

    @property
    def protector(self):
        if self._protector is None:
            name = self.meta("protector")
            if name == "none":
                raise StoreError("this database was created with --no-secrets and holds no secrets")
            self._protector = get_protector(name, base64.b64decode(self.meta("salt")))
        return self._protector

    # -- ingest -----------------------------------------------------------
    def ingest(self, source, path, records, perms=None, perms_path=None):
        perms_paths = [p for p in (perms_path if isinstance(perms_path, (list, tuple)) else [perms_path]) if p]
        store_secrets = self.meta("protector") != "none"
        cur = self.db.execute(
            "INSERT INTO inputs(source, path, sha256, records, permissions_path, permissions_sha256, "
            "loaded_utc, loaded_by) VALUES (?,?,?,?,?,?,?,?)",
            (source, str(Path(path).resolve()), sha256_file(path), len(records),
             " | ".join(str(Path(p).resolve()) for p in perms_paths) or None,
             " | ".join(sha256_file(p) for p in perms_paths) or None, _now(), _user()))
        input_id = cur.lastrowid
        seen = {}
        replaced = 0
        self.last_sanitized = 0
        for rec in records:
            if sanitize_record(rec):
                self.last_sanitized += 1
            # Permissions are looked up by the id as written in the source, so resolve them
            # before a duplicate id gets its #N suffix.
            if rec.grants is None and perms is not None:
                grants, rec.access_source = perms.resolve(rec)
                rec.grants = list(grants)
            elif rec.grants is not None:
                rec.access_source = rec.access_source or "source"
            base = rec.record_id
            seen[base] = seen.get(base, 0) + 1
            if seen[base] > 1:
                rec.source_id = f"{rec.source_id}#{seen[base]}"
                rec.notes.append("duplicate id in the source; suffixed in Record_ID")
            secret_enc = None
            if rec.secret and store_secrets:
                secret_enc = self.protector.protect(rec.secret, rec.record_id)
            rid = rec.record_id
            if self.db.execute("SELECT 1 FROM records WHERE record_id = ?", (rid,)).fetchone():
                replaced += 1
            self.db.execute("DELETE FROM grants WHERE record_id = ?", (rid,))
            self.db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, input_id, rec.source, rec.source_file, rec.source_id, rec.source_ref, rec.name,
                 rec.folder_path, json.dumps(list(rec.folder)), rec.type, rec.address, rec.username,
                 rec.secret_type, 1 if rec.secret.strip() else 0, secret_enc,
                 0 if rec.grants is None else 1, rec.access_source or "none", rec.target_safe,
                 rec.target_platform, json.dumps(rec.extra), json.dumps(rec.notes)))
            for g in rec.grants or []:
                self.db.execute("INSERT INTO grants VALUES (?,?,?,?)",
                                (rid, g.member, g.permission, g.member_type))
            rec.secret = ""  # drop the plaintext as soon as it is stored
        self.audit("ingest", source=source, path=str(path), records=len(records), replaced=replaced,
                   sanitized=self.last_sanitized,
                   permissions=" | ".join(map(str, perms_paths)), secrets_stored=store_secrets)
        self.db.commit()
        return len(records), replaced

    # -- load -------------------------------------------------------------
    def load_records(self, with_secrets=False):
        grants = {}
        for g in self.db.execute("SELECT * FROM grants"):
            grants.setdefault(g["record_id"], []).append(Grant(g["member"], g["permission"], g["member_type"]))
        out = []
        for r in self.db.execute("SELECT * FROM records ORDER BY input_id, rowid"):
            rec = SourceRecord(source=r["source"], source_file=r["source_file"], source_id=r["source_id"],
                               source_ref=r["source_ref"], name=r["name"],
                               folder=tuple(json.loads(r["folder_json"])), type=r["type"],
                               address=r["address"], username=r["username"],
                               secret_type=r["secret_type"], has_secret=bool(r["has_secret"]),
                               grants=grants.get(r["record_id"], []) if r["has_grants"] else None,
                               access_source=r["access_source"] if r["has_grants"] else "",
                               target_safe=r["target_safe"], target_platform=r["target_platform"],
                               extra=OrderedDict(json.loads(r["extra_json"])),
                               notes=json.loads(r["notes_json"]))
            if with_secrets and r["secret_enc"]:
                rec.secret = self.protector.unprotect(r["secret_enc"], r["record_id"])
            out.append(rec)
        return out

    def overrides(self):
        ov = {}
        for e in self.db.execute("SELECT record_id, field, value FROM edits"):
            ov.setdefault(e["record_id"], {})[EDIT_FIELDS[e["field"]]] = e["value"]
        return ov

    # -- map --------------------------------------------------------------
    def stored_config(self):
        text = self.meta("config")
        if text is None:
            raise StoreError("no config stored yet; run 'map' first")
        return json.loads(text)

    def member_edits(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM member_edits ORDER BY changed_utc")]

    def set_member_edits(self, safes, member_name, action, search_in="", member_type="", role="", reason=""):
        """action: add | remove | undo, for each Safe in safes."""
        if action not in ("add", "remove", "undo"):
            raise StoreError("action must be add, remove or undo")
        for safe in safes:
            if action == "undo":
                self.db.execute("DELETE FROM member_edits WHERE lower(safe_name) = lower(?) AND "
                                "lower(member_name) = lower(?)", (safe, member_name))
            else:
                self.db.execute("DELETE FROM member_edits WHERE lower(safe_name) = lower(?) AND "
                                "lower(member_name) = lower(?)", (safe, member_name))
                self.db.execute("INSERT INTO member_edits VALUES (?,?,?,?,?,?,?,?,?)",
                                (safe, member_name, action, search_in, member_type, role, _now(), _user(), reason))
        self.audit("member_" + action, safes=list(safes), member=member_name, role=role, search_in=search_in,
                   reason=reason)
        self.db.commit()
        return len(safes)

    def member_overrides(self):
        """{lower source member name: {member_name, member_type, search_in, ...}}; None = not changed."""
        return {r["member_key"]: dict(r) for r in self.db.execute("SELECT * FROM member_overrides")}

    def set_member_override(self, member_key, member_name=None, member_type=None, search_in=None,
                            reason="", undo=False):
        """Change one member everywhere it appears. undo=True puts the rules' values back."""
        key = (member_key or "").strip().lower()
        if not key:
            raise StoreError("name the member to change")
        self.db.execute("DELETE FROM member_overrides WHERE member_key = ?", (key,))
        if not undo and any(v is not None for v in (member_name, member_type, search_in)):
            self.db.execute("INSERT INTO member_overrides VALUES (?,?,?,?,?,?,?)",
                            (key, member_name or None, member_type or None, search_in, _now(), _user(), reason))
        self.audit("member_undo" if undo else "member_change", member=member_key, member_name=member_name,
                   member_type=member_type, search_in=search_in, reason=reason)
        self.db.commit()

    def safe_overrides(self):
        """{lower Safe name as the rules give it: {"new_name": ..., "description": ..., ...,
        "changed_utc", "changed_by", "reason"}}: your direct changes to whole Safes."""
        out = {}
        for r in self.db.execute("SELECT * FROM safe_overrides"):
            d = json.loads(r["settings_json"] or "{}")
            d.update(key=r["safe_key"], changed_utc=r["changed_utc"], changed_by=r["changed_by"], reason=r["reason"])
            out[r["safe_key"]] = d
        return out

    def set_safe_override(self, safe_key, settings, reason="", undo=False, old_name=None, new_name=None):
        """Rename one Safe or change its settings, kept across re-mapping. safe_key is the Safe's
        name as the rules give it. Per-Safe member changes follow a rename (old_name -> new_name);
        the ones moved are kept with the change (moved_edits) so Undo moves back only those."""
        key = (safe_key or "").strip().lower()
        if not key:
            raise StoreError("name the Safe to change")
        row = self.db.execute("SELECT settings_json FROM safe_overrides WHERE safe_key = ?", (key,)).fetchone()
        moved = list(json.loads(row["settings_json"] or "{}").get("moved_edits") or []) if row else []
        self.db.execute("DELETE FROM safe_overrides WHERE safe_key = ?", (key,))
        settings = {k: v for k, v in (settings or {}).items() if v not in (None, "") and k != "moved_edits"}
        if old_name and new_name and old_name.lower() != new_name.lower():
            moved = self._move_member_edits(key, old_name, new_name, moved)
        if not undo and settings:
            if moved:
                settings["moved_edits"] = moved
            self.db.execute("INSERT INTO safe_overrides VALUES (?,?,?,?,?)",
                            (key, json.dumps(settings), _now(), _user(), reason))
        self.audit("safe_undo" if undo else "safe_change", safe=safe_key, settings=settings, reason=reason)
        self.db.commit()

    def _move_member_edits(self, key, old_name, new_name, moved):
        """Move the per-Safe member changes that belong to the rules' Safe `key` from Safe old_name
        to Safe new_name. When old_name holds only that Safe, all its changes belong to it. When
        other Safes were put into it too, only the changes moved earlier (moved) and, if it is the
        Safe's own name, the ones no other rename brought in. Names match ignoring case; if new_name
        already has a change for the same member, the newer change wins. Returns the moved names."""
        held = self.db.execute("SELECT rule_names FROM plan_safes WHERE lower(safe_name) = lower(?)",
                               (old_name,)).fetchone()
        holders = {n.strip().lower() for n in (held["rule_names"] or "").split(" | ") if n.strip()} if held else set()
        rows = self.db.execute("SELECT * FROM member_edits WHERE lower(safe_name) = lower(?)", (old_name,)).fetchall()
        if holders - {key}:
            mine = {m.lower() for m in moved}
            if old_name.lower() == key:
                claimed = set()
                for other_key, ov in self.safe_overrides().items():
                    if other_key != key and other_key in holders:
                        claimed.update(m.lower() for m in ov.get("moved_edits") or [])
                rows = [r for r in rows if r["member_name"].lower() in mine or r["member_name"].lower() not in claimed]
            else:
                rows = [r for r in rows if r["member_name"].lower() in mine]
        out = []
        for r in rows:
            there = self.db.execute("SELECT changed_utc FROM member_edits WHERE lower(safe_name) = lower(?) AND "
                                    "lower(member_name) = lower(?)", (new_name, r["member_name"])).fetchall()
            self.db.execute("DELETE FROM member_edits WHERE safe_name = ? AND member_name = ?",
                            (r["safe_name"], r["member_name"]))
            if any((t["changed_utc"] or "") > (r["changed_utc"] or "") for t in there):
                continue                    # the target Safe's own change is newer: it stays
            self.db.execute("DELETE FROM member_edits WHERE lower(safe_name) = lower(?) AND lower(member_name) = lower(?)",
                            (new_name, r["member_name"]))
            vals = dict(r)
            vals["safe_name"] = new_name
            self.db.execute("INSERT INTO member_edits VALUES (?,?,?,?,?,?,?,?,?)",
                            tuple(vals[c] for c in ("safe_name", "member_name", "action", "search_in", "member_type",
                                                   "role", "changed_utc", "changed_by", "reason")))
            out.append(r["member_name"])
        return out

    def plan(self, cfg, with_secrets=False):
        return build_plan(self.load_records(with_secrets), cfg, None, self.overrides(), explicit=True,
                          member_edits=self.member_edits(), member_overrides=self.member_overrides(),
                          safe_overrides=self.safe_overrides())

    def map(self, cfg, cfg_path=None):
        plan = self.plan(cfg)
        self.db.execute("DELETE FROM plan_accounts")
        self.db.execute("DELETE FROM plan_safes")
        self.db.execute("DELETE FROM plan_members")
        for p in plan.accounts:
            r = p.rec
            self.db.execute(
                "INSERT INTO plan_accounts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r.record_id, p.migrate, p.status, "; ".join(p.errors + p.warnings), p.safe,
                 p.proposed_safe, "TRUE" if p.valid_safe else "FALSE", "; ".join(p.safe_issues),
                 p.safe_source, p.platform, p.platform_source, p.account_name, r.address, r.username,
                 r.secret_type, "Y" if r.has_secret else "N", r.source, r.source_ref, r.type,
                 r.folder_path, "; ".join(f"{g.member}={g.permission}" for g in p.grants),
                 p.access_source))
        for name, s in plan.safes.items():
            body = safe_settings(name, s, cfg)
            if str(body.get("numberOfVersionsRetention", "")).strip():
                retention = f"{body['numberOfVersionsRetention']} versions"
            elif str(body.get("numberOfDaysRetention", "")).strip():
                retention = f"{body['numberOfDaysRetention']} days"
            else:
                retention = ""
            rules = safe_settings(name, s, cfg, with_override=False)
            yes_no = lambda v: "" if v in ("", None) else ("Yes" if str(v).lower() in ("true", "1", "yes") else "No")
            self.db.execute("INSERT INTO plan_safes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (name, len(name), "TRUE" if s["valid"] else "FALSE",
                             " | ".join(sorted(s["proposed"])), " | ".join(sorted(s["issues"])),
                             " | ".join(sorted(s["sources"])), s["accounts"], s["migrating"],
                             body.get("managingCPM", ""), body.get("description", ""), retention,
                             body.get("location", ""), yes_no(body.get("olacEnabled")),
                             yes_no(body.get("autoPurgeEnabled")), " | ".join(sorted(s["rule_names"])),
                             json.dumps(s["override"]) if s["override"] else "",
                             json.dumps({k: rules.get(k, "") for k in SAFE_OVERRIDE_KEYS})))
        for (safe, _), m in plan.members.items():
            self.db.execute("INSERT INTO plan_members VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (safe, m["source_name"], m["member_name"], m["search_in"], m["member_type"],
                             m["permission"], m["role"] or "UNMAPPED", m["accounts"], "; ".join(m["notes"]),
                             m.get("directory_source", "")))
        self._set_meta("config", json.dumps(cfg))
        self._set_meta("config_path", str(cfg_path or "(defaults)"))
        self._set_meta("mapped_utc", _now())
        self.audit("map", config=str(cfg_path or "(defaults)"), accounts=len(plan.accounts))
        self.db.commit()
        return plan

    # -- edits ------------------------------------------------------------
    def select_ids(self, where, params=()):
        """Record ids from the accounts view matching a WHERE clause, read-only."""
        ro = self.readonly()
        try:
            return [r[0] for r in ro.execute(f"SELECT record_id FROM accounts WHERE {where}", params)]
        except sqlite3.Error as exc:
            raise StoreError(f"bad --where clause: {exc}")
        finally:
            ro.close()

    def set_edits(self, ids, values, reason=""):
        known = {r[0] for r in self.db.execute("SELECT record_id FROM records")}
        missing = [i for i in ids if i not in known]
        if missing:
            raise StoreError(f"unknown record id(s): {', '.join(missing[:5])}")
        n = 0
        for rid in ids:
            for fld, val in values.items():
                if val is None:
                    continue
                if val == "":
                    self.db.execute("DELETE FROM edits WHERE record_id = ? AND field = ?", (rid, fld))
                else:
                    self.db.execute("INSERT OR REPLACE INTO edits VALUES (?,?,?,?,?,?)",
                                    (rid, fld, val, _now(), _user(), reason))
                n += 1
        self.audit("set", records=len(ids), values=values, reason=reason)
        self.db.commit()
        return n

    def import_review(self, path, encoding="utf-8-sig"):
        """Take changed values from an edited Accounts_Review.csv as edits."""
        current = {r["record_id"]: r for r in self.db.execute("SELECT * FROM plan_accounts")}
        cols = {"Migrate": "migrate", "Target_Safe": "target_safe", "Platform_ID": "platform_id",
                "Account_Name": "account_name"}
        count = 0
        with open(path, newline="", encoding=encoding) as fh, csvsafe.reading(path):
            for row in csv.DictReader(fh):
                rid = csvsafe.unescape((row.get("Record_ID") or "").strip()).strip()
                if rid not in current:
                    continue
                vals = {}
                for col, fld in cols.items():
                    new = csvsafe.unescape((row.get(col) or "").strip()).strip()
                    if fld == "migrate":
                        if new and new.upper() != current[rid][fld].upper():
                            vals[fld] = new.upper()
                    elif _changed(new, current[rid][fld]):
                        vals[fld] = new
                if vals:
                    self.set_edits([rid], vals, reason=f"imported from {Path(path).name}")
                    count += 1
        return count

    # -- query ------------------------------------------------------------
    def readonly(self):
        uri = self.path.resolve().as_uri() + "?mode=ro"
        con = sqlite3.connect(uri, uri=True)

        def deny_secret(action, arg1, arg2, dbname, source):
            if action == sqlite3.SQLITE_ATTACH:
                return sqlite3.SQLITE_DENY  # no writing into other database files
            if action == sqlite3.SQLITE_READ and arg1 == "records" and arg2 == "secret_enc":
                return sqlite3.SQLITE_IGNORE  # reads as NULL
            return sqlite3.SQLITE_OK

        con.set_authorizer(deny_secret)
        return con

    def query(self, sql, params=()):
        con = self.readonly()
        try:
            cur = con.execute(sql, params)
            cols = [d[0] for d in cur.description or []]
            return cols, cur.fetchall()
        except sqlite3.Error as exc:
            raise StoreError(str(exc))
        finally:
            con.close()

    def inputs_for_manifest(self):
        return [{"source": r["source"], "path": r["path"], "sha256": r["sha256"],
                 "loaded_utc": r["loaded_utc"]} for r in self.db.execute("SELECT * FROM inputs")]

    def close(self):
        self.db.close()


def extract_plan(store, where=None, include_secrets=False, params=()):
    cfg = store.stored_config()
    if include_secrets and store.meta("protector") == "none":
        raise StoreError("this database was created with --no-secrets, so it has no secrets to "
                         "extract; ingest into a new database without --no-secrets")
    if include_secrets:
        try:
            plan = store.plan(cfg, with_secrets=True)
        except ProtectError as exc:
            raise StoreError(str(exc))
    else:
        plan = store.plan(cfg)
    if where:
        keep = set(store.select_ids(where, params))
        for p in plan.accounts:
            p.in_scope = p.rec.record_id in keep
        rebuild_totals(plan, cfg)
    return plan, cfg


def run_extract(store, out_dir, where=None, include_secrets=False, params=(), label=""):
    """Write review + upload files and the manifest. Returns (plan, counts, files)."""
    plan, cfg = extract_plan(store, where, include_secrets, params)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = write_review(plan, out_dir)
    upload_files, counts = write_upload(plan, cfg, out_dir, include_secrets)
    files += upload_files
    counts.update(records=len(plan.accounts), filter=label or where or "",
                  database=str(store.path.resolve()))
    write_manifest(out_dir, store.inputs_for_manifest(), files, counts, include_secrets,
                   store.meta("config_path"))
    store.audit("extract", output=str(out_dir.resolve()), where=label or where or "",
                include_secrets=include_secrets, accounts=counts["accounts"])
    store.db.commit()
    return plan, counts, files


def print_table(cols, rows, out=sys.stdout, max_width=60):
    if not cols:
        print("(no columns)", file=out)
        return
    text = [[("" if v is None else str(v)).replace("\n", " ")[:max_width] for v in row] for row in rows]
    widths = [max([len(c)] + [len(r[i]) for r in text]) for i, c in enumerate(cols)]
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)), file=out)
    print("  ".join("-" * w for w in widths), file=out)
    for r in text:
        print("  ".join(v.ljust(w) for v, w in zip(r, widths)), file=out)
    print(f"({len(rows)} rows)", file=out)
