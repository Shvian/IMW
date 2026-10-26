# Migration server readiness (Test-MigrationReadiness.ps1)

This script checks that the migration server is ready **before** any rehearsal or cutover. Then it helps you fix what it finds.

It never reads, stores or prints a secret. The optional sign-in tests discard their tokens straight away, and the reports hold only check results.

> Status: the script has been reviewed statically (bracket balance, no syntax that needs PowerShell 7). It has **not yet been run on Windows**. On its first run, use `-Mode Check` so it only reads, and look over the report before using the fix menu.

## Quick start

1. Copy the whole `delinea-migration` folder to a **local** drive on the migration server, for example `D:\Migration`. Do not put it on a share or a OneDrive or Dropbox folder.
2. Open **Windows PowerShell as Administrator**. Most checks don't need it, but most fixes do.
3. Allow the script for this session only:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   Unblock-File D:\Migration\setup\Test-MigrationReadiness.ps1
   ```
4. Do a first pass that only reads and changes nothing:
   ```powershell
   D:\Migration\setup\Test-MigrationReadiness.ps1 -Mode Check
   ```
5. Fill in `phase2\phase2_config.json`, with no secrets in it. Then run the full check with sign-in tests and the open menu:
   ```powershell
   D:\Migration\setup\Test-MigrationReadiness.ps1 -TestAuth -RunPreflight
   ```
6. In the menu, choose **1** to auto-fix the low-risk items. Use **2** to fix single items by ID and **3** to read the remediation for the rest. Choose **5** to re-run the checks until everything passes, or until what's left is accepted by your security team.

## Parameters

| Parameter | Meaning |
|---|---|
| `-Mode Resolve` (default) | Runs the checks, then opens the resolve menu |
| `-Mode Check` | Runs the checks and writes the report. Exit code 0 means all passed, 1 means warnings, 2 means failures |
| `-MigrationRoot` | The folder holding `phase1\`, `phase2\` and `tools\`. Defaults to the parent of `setup\` |
| `-ConfigPath` | The Phase 2 config. Defaults to `phase2\phase2_config.json` |
| `-StateDir` | The Phase 2 state folder you will use. Defaults to `migration_state` |
| `-ReportDir` | Where reports and logs go. Defaults to `readiness\` |
| `-TestAuth` | Signs in once to CyberArk and once to Delinea. It uses the env vars named in the config if they are set, otherwise it prompts with hidden input |
| `-RunPreflight` | Runs the Phase 2 read-only `preflight` against the real tenant |
| `-NonInteractive -FixIds A,B` | Fixes the listed IDs without the menu, for scripted builds |
| `-Force` | Skips the per-fix confirmation |

## What it checks

**Software**

| ID | Check |
|---|---|
| SW-01 | PowerShell 5.1 or later |
| SW-02 | Python 3.8 or later. Fix: installs Python 3.12 machine-wide with winget |
| SW-03 | Python ssl (TLS 1.2), sqlite3, json and urllib |
| SW-04 | The migration scripts are present, with their SHA-256 hashes recorded in the report |
| SW-05 | The Phase 2 config exists and its placeholders are filled in. Fix: writes a default config |
| SW-06 | ssh-keygen is available, for the fake SSH keys in rehearsals |
| SW-07 | The clock is in sync, because tokens are time-sensitive |

**Connectivity**

These checks run for every endpoint in the config: the CyberArk Identity token URL, the CyberArk API, and the Delinea base URL and token URL.

| ID | Check |
|---|---|
| NET-nA | DNS |
| NET-nB | TCP 443 |
| NET-nC | TLS 1.2 or later, and the certificate chain and expiry |
| NET-nD | HTTPS through the system proxy |
| NET-nE | HTTPS from Python itself. This catches TLS inspection certificates that Python doesn't trust |
| NET-90 | Proxy settings |
| NET-95 / NET-96 | Optional sign-in tests (`-TestAuth`) |

**Permissions**

| ID | Check |
|---|---|
| PERM-01 | The script runs as a named, non-SYSTEM account |
| PERM-02 | The migration folder ACL allows only you, Administrators and SYSTEM. Fix: uses icacls, medium risk |
| PERM-03 | The folder is local, not synced and not on a share |
| PERM-04 | No credentials are persisted in env vars or the config. Fix: removes the persistent env vars |
| PERM-05 | The state folder is writable |
| PERM-06 | The Delinea API account requirements. This is a manual checklist |
| PERM-07 | The CyberArk preflight (`-RunPreflight`) |

**Security**

This is a CIS Windows Server Benchmark (Level 1) aligned subset that matters for a machine handling privileged credentials.

| ID | Check | Auto-fix |
|---|---|---|
| SEC-01 | BitLocker on the OS and data drives | No, manual only, because of the recovery key |
| SEC-02 | Defender real-time protection, signatures current | Yes, low risk |
| SEC-03 | Firewall on for all profiles, inbound blocked | Yes, medium risk |
| SEC-04 | SMBv1 disabled | Yes, low risk, reboot needed |
| SEC-05 | TLS 1.0/1.1 off, TLS 1.2 on (SCHANNEL) | Yes, medium risk, reboot needed |
| SEC-06 | .NET strong cryptography | Yes |
| SEC-07 | Updates installed in the last 35 days | No, use your patching process |
| SEC-08 | No memory dumps, because secrets pass through process memory | Yes, medium risk, reboot needed |
| SEC-09 | RDP requires NLA | Yes |
| SEC-10 | RDP drive redirection off | Yes |
| SEC-11 | Audit policy for credential validation, logon and process creation | Yes |
| SEC-12 | PowerShell script block logging. Never type a secret on a command line | Yes |
| SEC-13 | Inactivity lock at 15 minutes or less | Yes |
| SEC-14 | Guest account disabled | Yes |
| SEC-15 | LSA protection (RunAsPPL) | Yes, medium risk, reboot needed |
| SEC-16 | WDigest off | Yes |
| SEC-17 | LLMNR off | Yes |
| SEC-18 | AlwaysInstallElevated off | Yes |
| SEC-19 | AutoPlay off | Yes |
| SEC-20 | No file-sync clients running | Stops them for now, but they may restart at next sign-in |

All other auto-fixes are low risk. Menu option 1 applies only the low-risk fixes. Medium-risk fixes, such as the firewall, TLS, LSA protection and the folder ACL, go through option 2 so you can choose them one at a time.

Domain GPOs can override local fixes. If a fixed item fails again after `gpupdate`, change the GPO instead. This script is not a full CIS assessment, so use CIS-CAT or your organisation's baseline for that.

## The resolve menu

```
1  Auto-fix all failing items rated Low risk
2  Fix specific items by ID
3  Show remediation steps for failing items
4  Show results again
5  Re-run all checks
6  Export report
Q  Quit
```

Each fix:
- checks that the session is elevated when the fix needs it,
- asks for confirmation unless `-Force` is set,
- is written to the log,
- and is followed by a re-run of that check.

Fixes that need a reboot are listed when you quit.

## Output

The script writes these files to `readiness\`:
- `readiness_<timestamp>.json`: the full results
- `readiness_<timestamp>.csv`: the full results
- `readiness_<timestamp>.log`: every check and fix

Keep these files with the migration audit evidence.
