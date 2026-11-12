#!/usr/bin/env python3
"""
End-to-end test of Phase 2 against tests/mock_apis.py. No real tenant needed.

  python tests/run_e2e_test.py

Covers: rate limiting on both sides, secrets fetched per account and never
written to disk, failure logging with hints, --only-failed retry, re-run with
no duplicates, a lost create response, a hard crash mid-run, and audit
hash-chain verification and tamper detection.
"""
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
P2 = HERE.parent / "cyberark_phase2_execute.py"
P1_OUT = HERE.parent.parent / "phase1" / "sample" / "output"
CFG = HERE / "phase2_config_mock.json"
PORT = 8765
MOCK = f"http://127.0.0.1:{PORT}"
ENV = dict(os.environ, CYBERARK_CLIENT_SECRET="test-secret", DELINEA_PASSWORD="delinea-test")
EXPECTED = {"svc_sql_prod": "P@ssw0rd!1", "svc_backup": "Bkp#2024x", "root@web01": "R00t!web01",
            "oracle@db01": "0ra#Cl3", "Vendor Portal": "V3nd0r!", "Firewall Admin GUI": "Fw@dm1n", "svc_flaky": "Fl4ky!svc"}
failures = []


def check(cond, msg):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def get(path):
    return json.loads(urllib.request.urlopen(MOCK + path).read())


def post(path, body):
    req = urllib.request.Request(MOCK + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req).read()


def p2(*args, cfg=CFG):
    r = subprocess.run([sys.executable, str(P2), *args[:1], "--config", str(cfg), *args[1:]],
                       capture_output=True, text=True, env=ENV)
    return r.returncode, r.stdout + r.stderr


def main():
    work = Path(tempfile.mkdtemp(prefix="p2e2e_"))
    state = work / "state"
    # Test review: the Phase 1 sample plus a row whose create response is lost, a row CyberArk
    # rejects, and a member that does not exist in the directory. Secret 106 is denied by Delinea.
    rows = list(csv.DictReader(open(P1_OUT / "Migration_Review.csv", encoding="utf-8-sig")))
    flaky = dict(rows[0], **{"Account Name": "svc_flaky", "Address": "flaky.example.com",
                             "Username": "svc_flaky", "Delinea Secret ID": "109"})
    rows[1]["Address"] = "reject.example.com"
    rows.append(flaky)
    review = work / "Migration_Review.csv"
    with open(review, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    members_rows = list(csv.DictReader(open(P1_OUT / "Safe_Members_Review.csv", encoding="utf-8-sig")))
    members_rows.append(dict(members_rows[0], Member_Name="CORP\\Ghost-Group"))
    members = work / "Safe_Members_Review.csv"
    with open(members, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=members_rows[0].keys())
        w.writeheader()
        w.writerows(members_rows)
    io = ["--review", str(review), "--members", str(members), "--state-dir", str(state)]

    mock = subprocess.Popen([sys.executable, str(HERE / "mock_apis.py"), str(PORT)])
    time.sleep(1)
    try:
        print("1. plan")
        code, out = p2("plan", *io)
        check(code == 0 and "NEW" in out, "plan runs and shows NEW objects")
        check("svc_flaky" not in out or "pre-check" not in out, "plan pre-check passes for valid rows")

        print("2. first run (rate limits, failures, lost response)")
        post("/_control", {"limits": {"cyberark": 8, "delinea": 2}})
        code, out = p2("run", *io, "--yes")
        check(code == 3, f"exit code 3 when some objects failed (got {code})")
        st = get("/_state")
        check(st["throttled"]["cyberark"] + st["throttled"]["delinea"] > 0, "mock rate limits were hit and absorbed")
        check("x 429" in out, "run reports 429 count per system")
        check(sum(1 for a in st["accounts"] if a["address"] == "flaky.example.com") == 1,
              "lost create response did not cause a duplicate")
        check("confirmed after ambiguous create error" in out, "lost response confirmed by lookup")
        check("Ghost-Group" in out and "Group not found in the directory" in out, "missing group has a clear hint")
        check("cannot view this secret" in out, "Delinea 403 has a clear hint")
        check("rejected the request data" in out, "CyberArk 400 has a clear hint")
        check("--only-failed" in out, "run prints the retry path")
        got = get("/_received_secrets")
        check(all(got.get(n) == v for n, v in EXPECTED.items() if n != "svc_backup"),
              "each account received its own Delinea secret")

        print("3. fix causes, retry only failures")
        post("/_control", {"limits": {"cyberark": 50, "delinea": 20}})
        post("/_control", {"deny": []})
        rows[1]["Address"] = "backup01.example.com"
        with open(review, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        before = len(get("/_state")["accounts"])
        code, out = p2("run", *io, "--yes", "--only-failed")
        after = get("/_state")["accounts"]
        check(len(after) == before + 2, f"only the 2 fixed accounts were created ({len(after) - before})")
        check("Ghost-Group" in out, "unfixable member is still reported")

        print("4. full re-run creates nothing")
        before = len(get("/_state")["accounts"])
        code, out = p2("run", *io, "--yes")
        check(len(get("/_state")["accounts"]) == before, "re-run created no accounts")
        check("ALREADY_DONE" in out, "re-run skips DONE objects from the ledger")

        print("5. hard crash mid-run, then resume")
        state2 = work / "state2"
        post("/_control", {"accounts": [], "safes": {}, "members": {}})
        slow = work / "slow.json"
        cfg = json.load(open(CFG))
        cfg["cyberark"]["requests_per_minute"] = 120
        json.dump(cfg, open(slow, "w"))
        io2 = ["--review", str(review), "--members", str(members), "--state-dir", str(state2)]
        proc = subprocess.Popen([sys.executable, str(P2), "run", "--config", str(slow), *io2, "--yes"],
                                env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(21)
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        partial = len(get("/_state")["accounts"])
        code, out = p2("run", *io2, "--yes")
        check("Another run holds" in out, "lock left by the crashed run is detected")
        code, out = p2("run", *io2, "--yes", "--force-unlock")
        accts = get("/_state")["accounts"]
        keys = [(a["safeName"], a["userName"], a["address"]) for a in accts]
        check(0 < partial < 9, f"crash landed mid-accounts ({partial} of 9 created)")
        check(len(keys) == len(set(keys)), f"no duplicates after crash and resume ({partial} before resume, {len(accts)} after)")
        check(len(accts) == 9, f"all 9 accounts present after resume (got {len(accts)})")

        print("6. audit log")
        code, out = p2("verify-audit", "--state-dir", str(state))
        check(code == 0 and "chain intact" in out, "audit hash chain verifies")
        audit = state / "audit_log.jsonl"
        lines = audit.read_text().splitlines()
        tampered = json.loads(lines[5])
        tampered["outcome"] = "CREATED_BY_SOMEONE_ELSE"
        lines[5] = json.dumps(tampered, separators=(",", ":"))
        shutil.copy(audit, work / "audit_backup.jsonl")
        audit.write_text("\n".join(lines) + "\n")
        code, out = p2("verify-audit", "--state-dir", str(state))
        check(code != 0 and "line 6" in out, "tampering is detected and located")
        shutil.copy(work / "audit_backup.jsonl", audit)

        print("7. no secret values on disk")
        leaked = []
        for f in list(state.rglob("*")) + list(state2.rglob("*")):
            if f.is_file():
                data = f.read_bytes()
                for v in list(EXPECTED.values()) + ["b3BlbnNzaC1rZXktdjE="]:
                    if v.encode() in data:
                        leaked.append(f"{f.name}: {v[:4]}...")
        check(not leaked, "no secret appears in the ledger, audit log or run logs" + (f" {leaked}" if leaked else ""))

        print("8. status and report")
        code, out = p2("status", "--state-dir", str(state))
        check("Outstanding" in out and "fix:" in out, "status lists outstanding items with fixes")
        code, out = p2("report", "--state-dir", str(state), "--out", str(work / "report.csv"))
        check((work / "report.csv").exists(), "report CSV written")
        print("9. synthetic data -> Phase 1 -> rehearsal against the (mock) tenant")
        syn = work / "syn"
        gen = HERE.parent.parent / "tools" / "generate_synthetic_delinea.py"
        p1 = HERE.parent.parent / "phase1" / "delinea_phase1_mapping.py"
        subprocess.run([sys.executable, str(gen), "--secrets", "60", "--out", str(syn),
                        "--groups", "CORP\\PAM-Windows-Admins", "CORP\\Ghost-Unix-Admins"], check=True, capture_output=True)
        subprocess.run([sys.executable, str(p1), "--input", str(syn / "delinea_export_synthetic.csv"),
                        "--permissions", str(syn / "delinea_permissions_synthetic.csv"),
                        "--config", str(syn / "mapping_config_synthetic.json"), "--output-dir", str(syn / "p1")],
                       check=True, capture_output=True)
        post("/_control", {"accounts": [], "safes": {}, "members": {}, "deny": []})
        reads_before = get("/_state")["secret_reads"]
        rio = ["--review", str(syn / "p1" / "Migration_Review.csv"), "--members",
               str(syn / "p1" / "Safe_Members_Review.csv"), "--state-dir", str(work / "rehearsal")]
        code, out = p2("run", *rio, "--yes", "--rehearsal-prefix", "TEST-")
        check(code == 2 and "must start with ZZ" in out, "rehearsal refuses a prefix not starting with ZZ")
        code, out = p2("run", "--review", str(review), "--state-dir", str(state), "--yes", "--rehearsal-prefix", "ZZTEST-")
        check(code == 2 and "production ledger" in out, "rehearsal refuses a production state dir")
        code, out = p2("run", *rio, "--yes", "--rehearsal-prefix", "ZZTEST-")
        st = get("/_state")
        check(st["secret_reads"] == reads_before, "rehearsal never contacted Delinea")
        check(st["safes"] and all(k.startswith("zztest-") for k in st["safes"]), "every rehearsal Safe is ZZTEST- prefixed")
        check(len(st["accounts"]) > 40, f"rehearsal onboarded accounts with fake secrets ({len(st['accounts'])})")
        check("Ghost-Unix-Admins" in out and "Group not found" in out, "rehearsal surfaces an unknown real group")
        code, out = p2("run", *rio[:-2], "--state-dir", str(work / "rehearsal"), "--yes")
        check(code == 2 and "rehearsal state dir" in out, "a real run refuses the rehearsal state dir")

        print("10. cleanup-rehearsal")
        post("/_control", {"safes": dict(get("/_state")["safes"], **{"real-safe": {"safeName": "Real-Safe"}})})
        code, out = p2("cleanup-rehearsal", "--state-dir", str(work / "rehearsal"), "--yes")
        st = get("/_state")
        check(code == 0 and not st["accounts"], "cleanup deleted every rehearsal account")
        check(list(st["safes"]) == ["real-safe"], "cleanup deleted only rehearsal Safes, not others")
        code, out = p2("cleanup-rehearsal", "--state-dir", str(state), "--yes")
        check(code == 2, "cleanup refuses a production state dir")

        print("11. preflight (read-only)")
        tenant = lambda: json.dumps({k: v for k, v in get("/_state").items()
                                     if k in ("safes", "members", "accounts")}, sort_keys=True)
        before = tenant()
        code, out = p2("preflight", "--state-dir", str(work / "pre"), "--review", str(syn / "p1" / "Migration_Review.csv"),
                       "--members", str(syn / "p1" / "Safe_Members_Review.csv"), "--platform", "NoSuchPlatform")
        after = tenant()
        check(before == after, "preflight changed nothing in the tenant")
        check("Platform NoSuchPlatform: not active" in out, "preflight flags a missing platform")
        check("Group CORP\\Ghost-Unix-Admins: not found" in out, "preflight flags an unknown group")
        check("Safe name Real-Safe" not in out and "free" in out, "preflight checks target Safe names")

        print("12. probe-delinea (migration day)")
        post("/_control", {"deny": [10005]})
        code, out = p2("probe-delinea", "--review", str(syn / "p1" / "Migration_Review.csv"), "--state-dir", str(work / "probe"))
        check("Delinea authentication OK" in out and " chars," in out, "probe reads one secret per template and prints only length")
        check("Synth!" not in out, "probe never prints a value")
        print("13. tokens expire every 3s during a long run")
        post("/_control", {"token_ttl": 3, "accounts": [], "safes": {}, "members": {}, "deny": [], "token_grants": []})
        tcfg = json.load(open(CFG))
        tcfg["cyberark"]["requests_per_minute"] = 600
        tcfg["delinea"]["requests_per_minute"] = 600
        tpath = work / "ttl.json"
        json.dump(tcfg, open(tpath, "w"))
        code, out = p2("run", "--review", str(syn / "p1" / "Migration_Review.csv"), "--members",
                       str(syn / "p1" / "Safe_Members_Review.csv"), "--state-dir", str(work / "ttl"), "--yes", cfg=tpath)
        grants = get("/_state")["token_grants"]
        check(grants.count("dl:refresh") >= 2, f"Delinea session renewed with refresh tokens ({grants.count('dl:refresh')}x)")
        check(grants.count("ca:login") >= 3, f"CyberArk (no refresh token issued) re-signed in ({grants.count('ca:login')}x)")
        check("401" not in out or "renewing" not in out, "no request hit an expired token")
        check("token renewals" in out, "run summary reports token renewals")
        aud = (work / "ttl" / "audit_log.jsonl").read_text()
        check('"token_refreshes"' in aud, "token renewals are in the audit log")
        post("/_control", {"token_ttl": 900})

        print("14. a password and a key for the same login stay separate accounts")
        post("/_control", {"accounts": [], "safes": {}, "members": {}, "deny": []})
        base = dict(rows[2], **{"Target CyberArk Safe": "Pair-Safe", "Username": "root", "Address": "pair01.example.com"})
        pair = [dict(base, **{"Account Name": "root@pair01", "Secret Type": "password", "Delinea Secret Field": "password",
                              "Delinea Secret ID": "201"}),
                dict(base, **{"Account Name": "root@pair01_key", "Secret Type": "key", "Delinea Secret Field": "private-key",
                              "Delinea Secret ID": "202", "Target Platform ID": "UnixSSHKeys"}),
                dict(base, **{"Account Name": "root@pair01_2", "Secret Type": "password", "Delinea Secret Field": "password",
                              "Delinea Secret ID": "203"})]
        ppath = work / "pair.csv"
        with open(ppath, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=pair[0].keys())
            w.writeheader()
            w.writerows(pair)
        code, out = p2("run", "--review", str(ppath), "--state-dir", str(work / "pair"), "--yes")
        accts = [a for a in get("/_state")["accounts"] if a["safeName"] == "Pair-Safe"]
        check(len(accts) == 3 and "ADOPTED" not in out, f"three Delinea secrets became three accounts ({len(accts)})")
        code, out = p2("run", "--review", str(ppath), "--state-dir", str(work / "pair2"), "--yes")
        accts = [a for a in get("/_state")["accounts"] if a["safeName"] == "Pair-Safe"]
        check(len(accts) == 3 and out.count("[ACCOUNT] ADOPTED") == 3, "a fresh ledger adopts each existing account by name, no duplicates")
    finally:
        mock.terminate()
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
