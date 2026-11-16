"""Command line: python -m imw <command> ..."""

import argparse
import logging
import shutil
import sys
from pathlib import Path

from . import __version__
from .adapters import ADAPTERS, AdapterError, detect_adapter, get_adapter
from .config import load_config, write_default_config
from .protect import ProtectError
from .reference import KINDS, USED_KINDS, References, read_templates, read_users, reference_kind
from .store import REPORTS, Store, StoreError, print_table, run_extract
from .transform import sanitize_record, Permissions, build_plan, load_overrides
from .writers import write_convention, write_manifest, write_review, write_upload

log = logging.getLogger("imw")

SECRETS_WARNING = """\
WARNING: upload/Accounts.csv now holds PLAINTEXT secrets, as do your source exports.
  - Keep them on an encrypted volume on the migration host, nowhere else.
  - Do not open Accounts.csv in Excel (it can alter values), email it or sync it.
  - Upload, check the result, then securely delete the exports and the upload folder.
  - The review/ folder holds no secret values and can be shared with reviewers."""


def parse_input(spec):
    """'keepass=C:\\x.xml' -> ('keepass', path); plain path -> (None, path)."""
    name, sep, rest = spec.partition("=")
    if sep and name.lower() in ADAPTERS:
        return name.lower(), rest
    return None, spec


def read_references(args):
    """[(kind, path, rows)] from --reference and from any --input that is a reference file
    (a template list or users list, see reference.py); None after logging an error."""
    out = []
    specs = list(getattr(args, "reference", None) or [])
    specs += [s for s in args.input if parse_input(s)[0] is None and not args.source
              and Path(s).is_file() and reference_kind(s, args.encoding)]
    for path in specs:
        if not Path(path).is_file():
            log.error("reference file not found: %s", path)
            return None
        kind = reference_kind(path, args.encoding)
        if kind not in USED_KINDS:
            log.warning("%s: %s; skipped", path, KINDS.get(kind, "not a template list or users list"))
            continue
        try:
            rows = (read_templates if kind == "templates" else read_users)(path, args.encoding)
        except (ValueError, OSError) as exc:
            log.error("%s", exc)
            return None
        log.info("%s: %d rows read as %s", path, len(rows), KINDS[kind].lower())
        out.append((kind, path, rows))
    return out


def references_from(loaded):
    return References([r for k, _, rows in loaded if k == "templates" for r in rows],
                      [r for k, _, rows in loaded if k == "users" for r in rows])


def read_inputs(args, cfg):
    """[(adapter_name, path, records)] or None after logging an error. Reference files given
    with --input are left to read_references."""
    out = []
    for spec in args.input:
        name, path = parse_input(spec)
        if not Path(path).is_file():
            log.error("input not found: %s", path)
            return None
        if name is None and not args.source and reference_kind(path, args.encoding):
            continue
        try:
            adapter = get_adapter(name or args.source) if (name or args.source) else detect_adapter(path)
            got = list(adapter.read(path, cfg, args.encoding))
        except (AdapterError, ValueError, OSError) as exc:
            log.error("%s", exc if str(exc).startswith(str(path)) else f"{path}: {exc}")
            return None
        log.info("%s: %d records read with the '%s' adapter", path, len(got), adapter.name)
        out.append((adapter.name, path, got))
    return out


def print_summary(plan, counts=None):
    status = {"OK": 0, "REVIEW": 0, "ERROR": 0}
    for p in plan.accounts:
        status[p.status] += 1
    invalid = sum(1 for s in plan.safes.values() if not s["valid"])
    print()
    print(f"Records:                 {len(plan.accounts)}")
    print(f"  OK / REVIEW / ERROR:   {status['OK']} / {status['REVIEW']} / {status['ERROR']}")
    print(f"  Migrate=N:             {sum(1 for p in plan.accounts if p.migrate == 'N')}")
    print(f"Target Safes:            {len(plan.safes)} ({invalid} with Valid_Safe_Name=FALSE)")
    if counts:
        print(f"Upload files:            {counts['safes']} Safes, {counts['members']} members, "
              f"{counts['accounts']} accounts")
        if counts["members_skipped"]:
            print(f"  {counts['members_skipped']} member rows left out (no role); see SafeMembers_Review.csv")
    if status["ERROR"]:
        print(f"  {status['ERROR']} ERROR rows are never in the upload files")
    return status


def prepare_output(out_dir, force):
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        if not force:
            log.error("%s is not empty. Use another --output-dir or pass --force to replace it.", out_dir)
            return None
        for sub in ("review", "upload"):
            shutil.rmtree(out_dir / sub, ignore_errors=True)
        (out_dir / "manifest.json").unlink(missing_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def open_store(args, create=False):
    protector = None
    if create:
        if getattr(args, "no_secrets", False):
            protector = "none"
        elif getattr(args, "insecure_plaintext_secrets", False):
            protector = "plain"
        elif sys.platform != "win32":
            raise StoreError("secrets are protected with Windows DPAPI, which needs Windows. On this "
                             "machine use --no-secrets (metadata only), or --insecure-plaintext-secrets "
                             "for test data only.")
    return Store(args.db, create=create, protector=protector)


def cmd_ingest(args):
    cfg = load_config(args.config)
    try:
        store = open_store(args, create=True)
    except StoreError as exc:
        log.error("%s", exc)
        return 2
    loaded = read_inputs(args, cfg)
    refs = read_references(args)
    if loaded is None or refs is None:
        return 2
    try:
        perms = Permissions(args.permissions, args.encoding) if args.permissions else None
    except (ValueError, OSError) as exc:
        log.error("permissions: %s", exc)
        return 2
    try:
        for kind, path, rows in refs:
            store.ingest_reference(kind, path, rows)
            print(f"{path}: {len(rows)} rows stored as {KINDS[kind].lower()}")
        for name, path, records in loaded:
            n, replaced = store.ingest(name, path, records, perms, args.permissions)
            print(f"{path}: {n} records stored ({replaced} replaced earlier copies)")
    except (StoreError, ProtectError) as exc:
        log.error("%s", exc)
        return 2
    mode = store.meta("protector")
    print(f"Database: {Path(args.db).resolve()}  (secrets: "
          + {"dpapi": "encrypted with Windows DPAPI", "none": "not stored",
             "plain": "PLAINTEXT - test data only"}[mode] + ")")
    if mode == "dpapi":
        print("The export files are no longer needed: securely delete them now.")
    print("Next: python -m imw map --db " + str(args.db) + " -c <config.json>")
    store.close()
    return 0


def cmd_map(args):
    try:
        store = open_store(args)
        cfg = load_config(args.config) if args.config else (
            store.stored_config() if store.meta("config") else load_config(None))
        plan = store.map(cfg, args.config or store.meta("config_path"))
    except StoreError as exc:
        log.error("%s", exc)
        return 2
    print_summary(plan)
    print("Results are in the database. Try: python -m imw query --db " + str(args.db) +
          " --report summary")
    store.close()
    return 0


def cmd_set(args):
    values = {"migrate": args.migrate.upper() if args.migrate else None, "target_safe": args.safe,
              "platform_id": args.platform, "account_name": args.name}
    if args.clear:
        values = {k: "" for k in values}
    try:
        store = open_store(args)
        if args.from_review:
            n = store.import_review(args.from_review, args.encoding)
            print(f"Imported changes for {n} records from {args.from_review}")
        else:
            if all(v is None for v in values.values()):
                log.error("nothing to set: give --migrate, --safe, --platform, --name or --clear")
                return 2
            if values["migrate"] not in (None, "", "Y", "N"):
                log.error("--migrate must be Y or N")
                return 2
            ids = list(args.record or []) + (store.select_ids(args.where) if args.where else [])
            if not ids:
                log.error("no records selected: give --record or a --where that matches something")
                return 2
            store.set_edits(ids, values, args.reason or "")
            print(f"Updated {len(ids)} records")
        plan = store.map(store.stored_config(), store.meta("config_path"))
    except (StoreError, ValueError, OSError) as exc:
        log.error("%s", exc)
        return 2
    print_summary(plan)
    store.close()
    return 0


def cmd_query(args):
    if args.report == "list" or (not args.sql and not args.report):
        for name, sql in REPORTS.items():
            print(f"{name:14} {sql}")
        print("\nTables: inputs, records, grants, edits, plan_accounts (view: accounts), plan_safes, "
              "plan_members, audit. records.secret_enc always reads as NULL.")
        return 0
    sql = REPORTS.get(args.report) if args.report else args.sql
    if sql is None:
        log.error("unknown report '%s'; use --report list", args.report)
        return 2
    try:
        store = open_store(args)
        cols, rows = store.query(sql)
    except StoreError as exc:
        log.error("%s", exc)
        return 2
    if args.csv:
        import csv
        from . import csvsafe
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as fh:
            w = csvsafe.SafeWriter(csv.writer(fh))
            w.writerow(cols)
            w.writerows(rows)
        print(f"Wrote {len(rows)} rows to {args.csv}")
    else:
        print_table(cols, rows)
    return 0


def cmd_extract(args):
    out_dir = prepare_output(args.output_dir, args.force)
    if out_dir is None:
        return 2
    try:
        store = open_store(args)
        plan, counts, _ = run_extract(store, out_dir, args.where, args.include_secrets)
    except StoreError as exc:
        log.error("%s", exc)
        return 2
    store.close()
    print_summary(plan, counts)
    print(f"Output: {out_dir.resolve()}")
    print()
    print(SECRETS_WARNING if args.include_secrets else
          "Accounts.csv has an empty 'Secret' column. Add --include-secrets for the upload-ready version.")
    return 0


def cmd_ui(args):
    from .ui.auth import AuthError, get_authenticator
    from .ui.server import serve
    flag = "none" if args.no_secrets else ("plain" if args.insecure_plaintext_secrets else None)
    try:
        auth = get_authenticator()
    except AuthError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    from .owner import OwnerError
    from .ui.tls import TlsError
    # Workspaces made before the rename are called pam2pc_workspace: keep using one if it is there.
    if args.workspace == "imw_workspace" and not Path("imw_workspace").exists() and Path("pam2pc_workspace").is_dir():
        print("Using the existing workspace pam2pc_workspace (from before the rename). "
              "Rename the folder to imw_workspace, or pass -w, to change this.")
        args.workspace = "pam2pc_workspace"
    try:
        return serve(args.workspace, args.port, not args.no_browser, flag, authenticator=auth,
                     use_tls=not args.no_tls, new_cert=args.new_cert, trust_cert=args.trust_cert)
    except (TlsError, OwnerError, StoreError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_sources(_args):
    for name, cls in ADAPTERS.items():
        print(f"{name:10} {cls.description}")
    return 0


def cmd_init_config(args):
    write_default_config(args.path)
    print(f"Wrote starter config to {args.path}")
    return 0


def cmd_convert(args):
    cfg = load_config(args.config)
    out_dir = prepare_output(args.output_dir, args.force)
    if out_dir is None:
        return 2
    loaded = read_inputs(args, cfg)
    refs = read_references(args)
    if loaded is None or refs is None:
        return 2
    records = [r for _, _, got in loaded for r in got]
    inputs = [(name, path) for name, path, _ in loaded]
    cleaned = sum(1 for r in records if sanitize_record(r))
    if cleaned:
        log.warning("%d records had control or invisible characters removed (see their Notes)", cleaned)
    if not records:
        log.error("No records found. Check --source and the column names (field_aliases).")
        return 1

    try:
        perms = Permissions(args.permissions, args.encoding) if args.permissions else None
        overrides = load_overrides(args.overrides, args.encoding) if args.overrides else None
    except (ValueError, OSError) as exc:
        log.error("%s", exc)
        return 2
    plan = build_plan(records, cfg, perms, overrides, refs=references_from(refs))

    files = write_review(plan, out_dir) + [write_convention(plan, cfg, out_dir)]
    upload_files, counts = write_upload(plan, cfg, out_dir, args.include_secrets)
    files += upload_files
    counts.update(records=len(plan.accounts))
    manifest = write_manifest(out_dir, inputs, files, counts, args.include_secrets, args.config)
    print_summary(plan, counts)
    print(f"Output: {out_dir.resolve()}  (manifest: {manifest.name})")
    print()
    if args.include_secrets:
        print(SECRETS_WARNING)
    else:
        print("Accounts.csv has an empty 'Secret' column (dry run). Review the files, then run "
              "again with --include-secrets to produce the upload-ready version.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="imw", description="Convert PAM exports into Privilege Cloud API-ready CSV files. "
                                   "Offline: makes no network connections.")
    ap.add_argument("--version", action="version", version=f"Idira Migration Workbench (imw) {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("sources", help="List the supported source formats").set_defaults(func=cmd_sources)

    p = sub.add_parser("init-config", help="Write a starter config file")
    p.add_argument("path")
    p.set_defaults(func=cmd_init_config)

    p = sub.add_parser("convert", help="Convert one or more exports")
    p.add_argument("--input", "-i", action="append", required=True,
                   help="Export file. Repeat for several files. Prefix with the source to skip "
                        "auto-detection, e.g. keepass=vault.xml or table=accounts.xlsx")
    p.add_argument("--source", choices=sorted(ADAPTERS), help="Source for every --input without a prefix")
    p.add_argument("--config", "-c", help="Config JSON (see init-config)")
    p.add_argument("--permissions", "-p", action="append",
                       help="Permissions CSV: groups per folder or record. Repeat to merge several files")
    p.add_argument("--reference", action="append",
                   help="Template list (secret name -> template, e.g. Delinea's allsecrets.csv) or users "
                        "list (full name -> UPN, e.g. lauserslist.csv). Repeat for several. Found "
                        "automatically when passed with --input too")
    p.add_argument("--overrides", help="An edited review/Accounts_Review.csv; changed Migrate, "
                                       "Target_Safe, Platform_ID and Account_Name values win")
    p.add_argument("--output-dir", "-o", default="imw_output")
    p.add_argument("--include-secrets", action="store_true",
                   help="Write secret values into upload/Accounts.csv (default: left empty)")
    p.add_argument("--force", action="store_true", help="Replace an existing output folder")
    p.add_argument("--encoding", default="utf-8-sig", help="Text encoding of CSV inputs (try cp1252)")
    p.set_defaults(func=cmd_convert)

    def add_inputs(p):
        p.add_argument("--input", "-i", action="append", required=True,
                       help="Export file. Repeat for several files. Prefix with the source to skip "
                            "auto-detection, e.g. keepass=vault.xml or table=accounts.xlsx")
        p.add_argument("--source", choices=sorted(ADAPTERS), help="Source for every --input without a prefix")
        p.add_argument("--permissions", "-p", action="append",
                       help="Permissions CSV: groups per folder or record. Repeat to merge several files")
        p.add_argument("--reference", action="append",
                       help="Template list (secret name -> template, e.g. Delinea's allsecrets.csv) or users "
                            "list (full name -> UPN, e.g. lauserslist.csv). Repeat for several. Found "
                            "automatically when passed with --input too")
        p.add_argument("--encoding", default="utf-8-sig", help="Text encoding of CSV inputs (try cp1252)")

    def add_db(p):
        p.add_argument("--db", "-d", required=True, help="Local staging database file, e.g. migration.db")

    p = sub.add_parser("ingest", help="Load exports into the local database (secrets encrypted)")
    add_db(p)
    add_inputs(p)
    p.add_argument("--config", "-c", help="Config JSON (only source-reading options are used here)")
    p.add_argument("--no-secrets", action="store_true", help="New database only: store metadata, no secrets")
    p.add_argument("--insecure-plaintext-secrets", action="store_true",
                   help="New database only: store secrets UNENCRYPTED (test data on non-Windows only)")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("map", help="Apply the config rules to everything in the database")
    add_db(p)
    p.add_argument("--config", "-c", help="Config JSON (default: the one used by the last map)")
    p.set_defaults(func=cmd_map)

    p = sub.add_parser("set", help="Record changes: Migrate, Safe, platform or account name")
    add_db(p)
    p.add_argument("--record", "-r", action="append", help="Record_ID to change (repeatable)")
    p.add_argument("--where", "-w", help="SQL condition on the accounts view, e.g. \"target_safe = 'X'\"")
    p.add_argument("--migrate", choices=["Y", "N", "y", "n"])
    p.add_argument("--safe", help="Target Safe (cleaned to the Safe name rules)")
    p.add_argument("--platform", help="Platform ID")
    p.add_argument("--name", help="Account name")
    p.add_argument("--clear", action="store_true", help="Remove earlier changes for these records")
    p.add_argument("--reason", help="Why; kept in the edits table and audit log")
    p.add_argument("--from-review", help="Import changed values from an edited Accounts_Review.csv")
    p.add_argument("--encoding", default="utf-8-sig")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("query", help="Read-only SQL or a built-in report")
    add_db(p)
    p.add_argument("sql", nargs="?", help="SELECT statement")
    p.add_argument("--report", help="Built-in report name; 'list' shows them")
    p.add_argument("--csv", help="Write the result to this CSV file instead of the screen")
    p.set_defaults(func=cmd_query)

    p = sub.add_parser("extract", help="Write review and upload CSVs from the database")
    add_db(p)
    p.add_argument("--output-dir", "-o", required=True)
    p.add_argument("--where", "-w", help="Only upload accounts matching this SQL condition (a wave)")
    p.add_argument("--include-secrets", action="store_true",
                   help="Decrypt secrets into upload/Accounts.csv (default: left empty)")
    p.add_argument("--force", action="store_true", help="Replace an existing output folder")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("ui", help="Start the Idira Migration Workbench (local web UI over HTTPS)")
    p.add_argument("--workspace", "-w", default="imw_workspace",
                   help="Folder for the database, config, inbox and outputs (default: imw_workspace)")
    p.add_argument("--port", type=int, default=0, help="Port on 127.0.0.1 (default: any free port)")
    p.add_argument("--no-browser", action="store_true", help="Print the link instead of opening a browser")
    p.add_argument("--no-secrets", action="store_true", help="New database only: metadata, no secrets")
    p.add_argument("--insecure-plaintext-secrets", action="store_true",
                   help="New database only: secrets UNENCRYPTED (test data on non-Windows only)")
    p.add_argument("--trust-cert", action="store_true",
                   help="Windows: trust the Workbench's self-signed HTTPS certificate for your user "
                        "(Windows asks you to confirm), so the browser stops warning")
    p.add_argument("--new-cert", action="store_true", help="Make a new HTTPS certificate and key")
    p.add_argument("--no-tls", action="store_true", help="Plain HTTP instead of HTTPS (troubleshooting only)")
    p.set_defaults(func=cmd_ui)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
