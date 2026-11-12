"""Command line: python -m pam2pc <command> ..."""

import argparse
import logging
import shutil
import sys
from pathlib import Path

from . import __version__
from .adapters import ADAPTERS, AdapterError, detect_adapter, get_adapter
from .config import load_config, write_default_config
from .transform import Permissions, build_plan, load_overrides
from .writers import write_manifest, write_review, write_upload

log = logging.getLogger("pam2pc")

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
    out_dir = Path(args.output_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        if not args.force:
            log.error("%s is not empty. Use another --output-dir or pass --force to replace it.", out_dir)
            return 2
        for sub in ("review", "upload"):
            shutil.rmtree(out_dir / sub, ignore_errors=True)
        (out_dir / "manifest.json").unlink(missing_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    records, inputs = [], []
    for spec in args.input:
        name, path = parse_input(spec)
        if not Path(path).is_file():
            log.error("input not found: %s", path)
            return 2
        try:
            adapter = get_adapter(name or args.source) if (name or args.source) else detect_adapter(path)
            got = list(adapter.read(path, cfg, args.encoding))
        except (AdapterError, ValueError, OSError) as exc:
            log.error("%s: %s", path, exc)
            return 2
        log.info("%s: %d records read with the '%s' adapter", path, len(got), adapter.name)
        records.extend(got)
        inputs.append((adapter.name, path))
    if not records:
        log.error("No records found. Check --source and the column names (field_aliases).")
        return 1

    perms = Permissions(args.permissions, args.encoding) if args.permissions else None
    overrides = load_overrides(args.overrides, args.encoding) if args.overrides else None
    plan = build_plan(records, cfg, perms, overrides)

    files = write_review(plan, out_dir)
    upload_files, counts = write_upload(plan, cfg, out_dir, args.include_secrets)
    files += upload_files
    status = {"OK": 0, "REVIEW": 0, "ERROR": 0}
    for p in plan.accounts:
        status[p.status] += 1
    counts.update(records=len(plan.accounts), excluded=sum(1 for p in plan.accounts if p.migrate == "N"),
                  **{f"status_{k.lower()}": v for k, v in status.items()})
    manifest = write_manifest(out_dir, inputs, files, counts, args.include_secrets, args.config)

    invalid = sum(1 for s in plan.safes.values() if not s["valid"])
    print()
    print(f"Records read:            {len(plan.accounts)}")
    print(f"  OK / REVIEW / ERROR:   {status['OK']} / {status['REVIEW']} / {status['ERROR']}")
    print(f"  Migrate=N:             {counts['excluded']}")
    print(f"Target Safes:            {len(plan.safes)} ({invalid} with Valid_Safe_Name=FALSE)")
    print(f"Upload files:            {counts['safes']} Safes, {counts['members']} members, "
          f"{counts['accounts']} accounts")
    if counts["members_skipped"]:
        print(f"  {counts['members_skipped']} member rows left out (no role); see SafeMembers_Review.csv")
    if status["ERROR"]:
        print(f"  {status['ERROR']} ERROR rows are not in the upload files; see Accounts_Review.csv")
    print(f"Output:                  {out_dir.resolve()}  (manifest: {manifest.name})")
    print()
    if args.include_secrets:
        print(SECRETS_WARNING)
    else:
        print("Accounts.csv has an empty 'secret' column (dry run). Review the files, then run "
              "again with --include-secrets to produce the upload-ready version.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pam2pc", description="Convert PAM exports into Privilege Cloud API-ready CSV files. "
                                   "Offline: makes no network connections.")
    ap.add_argument("--version", action="version", version=f"pam2pc {__version__}")
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
    p.add_argument("--permissions", "-p", help="Permissions CSV: groups per folder or record")
    p.add_argument("--overrides", help="An edited review/Accounts_Review.csv; changed Migrate, "
                                       "Target_Safe, Platform_ID and Account_Name values win")
    p.add_argument("--output-dir", "-o", default="pam2pc_output")
    p.add_argument("--include-secrets", action="store_true",
                   help="Write secret values into upload/Accounts.csv (default: left empty)")
    p.add_argument("--force", action="store_true", help="Replace an existing output folder")
    p.add_argument("--encoding", default="utf-8-sig", help="Text encoding of CSV inputs (try cp1252)")
    p.set_defaults(func=cmd_convert)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
