"""Output parity between the Python Workbench (python -m imw) and the .NET port (IMW).

Runs the same commands with both and compares every output file byte for byte, plus what
each prints. Only values that differ on every run are ignored: the manifest's created_utc,
host and absolute paths, and the database's own timestamps and salt.

    python dotnet/tests/parity/run_parity.py [--imw path/to/IMW(.dll|.exe)] [--keep DIR]

Needs Python 3.8+ with the repository's imw package (run from the repository root).
Exit code 0 when every scenario matches.
"""

import argparse
import difflib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples"


def dotnet_cmd(imw):
    imw = Path(imw)
    return ["dotnet", str(imw)] if imw.suffix == ".dll" else [str(imw)]


def run(cmd, cwd):
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8", PYTHONHASHSEED="0")
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, env=env)
    return done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")


def normalize_text(text, work):
    text = text.replace("\r\n", "\n")
    text = text.replace(str(work), "<WORK>")
    text = text.replace("python -m imw", "IMW")
    return text


def normalize_manifest(data, work):
    m = json.loads(data.decode("utf-8"))
    m.pop("created_utc", None)
    m.pop("host", None)
    for i in m.get("inputs", []):
        i.pop("loaded_utc", None)
    if "counts" in m and "database" in m["counts"]:
        m["counts"]["database"] = "<db>"
    return normalize_text(json.dumps(m, indent=2, sort_keys=True), work).encode()


def compare_dirs(a, b, work):
    problems = []
    files_a = sorted(p.relative_to(a).as_posix() for p in a.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(b).as_posix() for p in b.rglob("*") if p.is_file())
    if files_a != files_b:
        problems.append(f"file lists differ:\n  python: {files_a}\n  dotnet: {files_b}")
    for rel in sorted(set(files_a) & set(files_b)):
        da, db = (a / rel).read_bytes(), (b / rel).read_bytes()
        if rel.endswith("manifest.json"):
            da, db = normalize_manifest(da, work), normalize_manifest(db, work)
        if da != db:
            diff = "\n".join(list(difflib.unified_diff(
                da.decode("utf-8", "replace").splitlines(), db.decode("utf-8", "replace").splitlines(),
                f"python/{rel}", f"dotnet/{rel}", lineterm="", n=1))[:40])
            problems.append(f"{rel} differs:\n{diff}")
    return problems


def compare_output(label, py, net, work):
    problems = []
    if py[0] != net[0]:
        problems.append(f"{label}: exit code python {py[0]} dotnet {net[0]}")
    for name, x, y in (("stdout", py[1], net[1]), ("stderr", py[2], net[2])):
        x, y = normalize_text(x, work), normalize_text(y, work)
        if x != y:
            diff = "\n".join(list(difflib.unified_diff(x.splitlines(), y.splitlines(), f"python {name}",
                                                       f"dotnet {name}", lineterm="", n=1))[:30])
            problems.append(f"{label}: {name} differs:\n{diff}")
    return problems


def scenarios(pack):
    s = [
        ("delinea csv + permissions", ["-i", f"delinea={SAMPLES/'delinea_export.csv'}", "-c", str(SAMPLES/"config_delinea.json"),
                                       "-p", str(SAMPLES/"delinea_permissions.csv")]),
        ("delinea csv + two permission files", ["-i", str(SAMPLES/"delinea_export.csv"), "-c", str(SAMPLES/"config_delinea.json"),
                                                "-p", str(SAMPLES/"delinea_permissions.csv"), "-p", str(SAMPLES/"delinea_permissions_extra.csv")]),
        ("delinea xml", ["-i", str(SAMPLES/"delinea_export.xml"), "-c", str(SAMPLES/"config_delinea.json")]),
        ("keepass xml", ["-i", str(SAMPLES/"keepass_export.xml"), "-c", str(SAMPLES/"config_generic.json")]),
        ("keepass converted from delinea", ["-i", str(SAMPLES/"delinea_keepass_converted.xml"), "-c", str(SAMPLES/"config_generic.json")]),
        ("keepassxc csv", ["-i", str(SAMPLES/"keepassxc_export.csv"), "-c", str(SAMPLES/"config_generic.json")]),
        ("excel by group", ["-i", str(SAMPLES/"accounts_by_group.xlsx"), "-c", str(SAMPLES/"config_excel.json")]),
        ("inventory csv", ["-i", f"table={SAMPLES/'accounts_inventory.csv'}", "-c", str(SAMPLES/"config_generic.json")]),
        ("list only csv, defaults", ["-i", str(SAMPLES/"accounts_list_only.csv")]),
        ("everything at once", ["-i", str(SAMPLES/"delinea_export.csv"), "-i", str(SAMPLES/"keepass_export.xml"),
                                "-i", str(SAMPLES/"accounts_inventory.csv"), "-c", str(SAMPLES/"config_generic.json"),
                                "--include-secrets"]),
    ]
    if pack:
        inbox = pack / "inbox"
        s += [
            ("sample pack: delinea csv", ["-i", str(inbox/"delinea_export.csv"), "-p", str(inbox/"delinea_permissions.csv"),
                                          "-c", str(pack/"config.json"), "--include-secrets"]),
            ("sample pack: delinea xml", ["-i", str(inbox/"delinea_export.xml"), "-c", str(pack/"config.json")]),
            ("sample pack: keepass", ["-i", str(inbox/"keepass_export.xml"), "-c", str(pack/"config.json")]),
            ("sample pack: excel", ["-i", str(inbox/"it_inventory.xlsx"), "-c", str(pack/"config.json")]),
            ("sample pack: all", ["-i", str(inbox/"delinea_export.csv"), "-p", str(inbox/"delinea_permissions.csv"),
                                  "-i", str(inbox/"keepass_export.xml"), "-i", str(inbox/"it_inventory.xlsx"),
                                  "-c", str(pack/"config.json")]),
        ]
    return s


def store_flow(work, py, net, pack):
    """ingest / map / set / query / extract against one database each."""
    problems = []
    inputs = ["-i", str(SAMPLES/"delinea_export.csv"), "-p", str(SAMPLES/"delinea_permissions.csv"),
              "-i", str(SAMPLES/"keepass_export.xml")]
    if pack:
        inputs += ["-i", str(pack/"inbox"/"it_inventory.xlsx")]
    steps = [
        ("ingest", ["ingest", "--db", "{db}", "--insecure-plaintext-secrets"] + inputs),
        ("map", ["map", "--db", "{db}", "-c", str(SAMPLES/"config_generic.json")]),
        ("set by where", ["set", "--db", "{db}", "--where", "status = 'ERROR'", "--migrate", "N", "--reason", "parity"]),
        ("set name", ["set", "--db", "{db}", "--where", "target_safe LIKE 'UNIX%'", "--name", "renamed-account"]),
        ("query list", ["query", "--db", "{db}", "--report", "list"]),
        ("query summary", ["query", "--db", "{db}", "--report", "summary"]),
        ("query safes", ["query", "--db", "{db}", "--report", "safes"]),
        ("query members", ["query", "--db", "{db}", "--report", "members"]),
        ("query secret", ["query", "--db", "{db}", "SELECT record_id, secret_enc FROM records ORDER BY record_id LIMIT 5"]),
        ("query bad sql", ["query", "--db", "{db}", "SELECT nope FROM accounts"]),
        ("query csv", ["query", "--db", "{db}", "--report", "errors", "--csv", "{out}/errors.csv"]),
        ("extract", ["extract", "--db", "{db}", "-o", "{out}/x"]),
        ("extract wave", ["extract", "--db", "{db}", "-o", "{out}/wave", "--where", "target_safe LIKE 'W%'", "--include-secrets"]),
        ("extract again refused", ["extract", "--db", "{db}", "-o", "{out}/x"]),
    ]
    for side, cmd in (("python", py), ("dotnet", net)):
        (work / side / "flow").mkdir(parents=True, exist_ok=True)
    results = {}
    for label, args in steps:
        outs = []
        for side, cmd in (("python", py), ("dotnet", net)):
            d = work / side / "flow"
            a = [x.replace("{db}", "migration.db").replace("{out}", str(d)) for x in args]
            rc, so, se = run(cmd + a, d)
            outs.append((rc, so.replace(str(d), "<WORK>"), se.replace(str(d), "<WORK>")))
        results[label] = outs
        problems += compare_output(f"flow {label}", outs[0], outs[1], work / "python" / "flow")
    for sub in ("x", "wave"):
        problems += compare_dirs(work / "python" / "flow" / sub, work / "dotnet" / "flow" / sub, work)
    a, b = (work / "python" / "flow" / "errors.csv"), (work / "dotnet" / "flow" / "errors.csv")
    if a.exists() and b.exists() and a.read_bytes() != b.read_bytes():
        problems.append("flow query csv: errors.csv differs")
    # Same database contents (apart from timestamps, salt and owner).
    problems += compare_databases(work / "python" / "flow" / "migration.db", work / "dotnet" / "flow" / "migration.db")
    return problems


VOLATILE = {"meta": None, "audit": None}
TIME_COLS = {"loaded_utc", "changed_utc", "approved_utc", "ts", "loaded_by", "changed_by"}


def compare_databases(a, b):
    problems = []
    ca, cb = sqlite3.connect(str(a)), sqlite3.connect(str(b))
    tables = [r[0] for r in ca.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name")]
    tables_b = [r[0] for r in cb.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name")]
    if tables != tables_b:
        problems.append(f"database tables differ: {tables} / {tables_b}")
    for t in tables:
        if t in VOLATILE:
            continue
        cols = [r[1] for r in ca.execute(f"PRAGMA table_info({t})")]
        keep = [c for c in cols if c not in TIME_COLS]
        sel = ", ".join(f'"{c}"' for c in keep)
        ra = ca.execute(f"SELECT {sel} FROM {t} ORDER BY rowid" if t != "accounts" else f"SELECT {sel} FROM {t}").fetchall()
        rb = cb.execute(f"SELECT {sel} FROM {t} ORDER BY rowid" if t != "accounts" else f"SELECT {sel} FROM {t}").fetchall()
        if t == "inputs":
            ra = [r[:2] + r[3:] for r in ra]
            rb = [r[:2] + r[3:] for r in rb]
        if ra != rb:
            for x, y in zip(ra, rb):
                if x != y:
                    problems.append(f"database table {t} differs, first difference:\n  python {x}\n  dotnet {y}")
                    break
            else:
                problems.append(f"database table {t}: {len(ra)} rows vs {len(rb)}")
    audit_a = [r[0] for r in ca.execute("SELECT action FROM audit ORDER BY id")]
    audit_b = [r[0] for r in cb.execute("SELECT action FROM audit ORDER BY id")]
    if audit_a != audit_b:
        problems.append(f"audit actions differ: {audit_a} / {audit_b}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--imw", default=str(ROOT / "dotnet/src/Imw/bin/Debug/net10.0/IMW.dll"))
    ap.add_argument("--keep", help="Keep the work folder here")
    ap.add_argument("--no-pack", action="store_true", help="Skip the generated sample pack")
    ap.add_argument("--only", help="Run only scenarios whose name contains this")
    args = ap.parse_args()
    py = [sys.executable, "-m", "imw"]
    net = dotnet_cmd(args.imw)
    work = Path(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="imw-parity-"))
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    work = work.resolve()      # the long form (C:\Users\runneradmin, not RUNNER~1), as both programs print it
    pack = None
    if not args.no_pack:
        pack = work / "pack"
        subprocess.run([sys.executable, str(ROOT / "tools/generate_sample_pack.py"), "--out", str(pack), "--seed", "7"],
                       check=True, capture_output=True)
    failures = 0
    for name, cmd_args in scenarios(pack):
        if args.only and args.only not in name:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        outs = []
        for side, cmd in (("python", py), ("dotnet", net)):
            out = work / side / slug
            outs.append(run(cmd + ["convert"] + cmd_args + ["-o", str(out)], work))
        problems = compare_output(name, (outs[0][0], outs[0][1].replace(str(work / "python" / slug), "<OUT>"), outs[0][2]),
                                  (outs[1][0], outs[1][1].replace(str(work / "dotnet" / slug), "<OUT>"), outs[1][2]), work)
        if (work / "python" / slug).exists() or (work / "dotnet" / slug).exists():
            problems += compare_dirs(work / "python" / slug, work / "dotnet" / slug, work)
        print(("OK    " if not problems else "DIFF  ") + name)
        for p in problems:
            print("      " + p.replace("\n", "\n      "))
        failures += bool(problems)
    if not args.only or "flow" in args.only:
        problems = store_flow(work, py, net, pack)
        print(("OK    " if not problems else "DIFF  ") + "database flow (ingest, map, set, query, extract)")
        for p in problems:
            print("      " + p.replace("\n", "\n      "))
        failures += bool(problems)
    print(f"\n{failures} scenario(s) with differences. Work folder: {work}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
