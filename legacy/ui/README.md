# Migration Console (local web UI)

The Migration Console is a guided browser front end for the migration tools. It runs on the migration server itself.

You don't have to edit files in the tool folders. The console lets you:
- run the readiness checks and apply fixes
- enter the connections and credentials
- drag the Delinea exports in
- edit the mapping rules
- review and correct the mapping
- rehearse in test Safes
- run the migration with live progress
- review the results and the audit trail
- drag reports out

It drives the same scripts as the command line: `setup/Test-MigrationReadiness.ps1`, Phase 1 and Phase 2. It also uses the same ledger and audit logs, so resume and the no-duplicates guarantees don't change. You can use the CLI and the console side by side on the same workspace.

## Start it

1. Copy the whole `delinea-migration` folder to a local drive on the migration server, for example `D:\Migration`.
2. You need Python 3.8 or later. Node.js is not needed, because the built front end is already in `ui/server/static/`.
3. Double-click **`ui\start-ui.cmd`**, or run `py -3 ui\server\migration_ui.py`.
4. The browser opens on a one-time link such as `http://127.0.0.1:53123/launch?token=…`.
5. **Keep the console window open.**
   - Press **Enter** in it to print a fresh link, for example after the session has idled out.
   - Press **Ctrl+C** to stop the console. This also drops the credentials held in memory.

Options:
- `--workspace PATH` sets the data folder. The default is `delinea-migration\workspace`.
- `--port N` sets the port. The default is a free port.
- `--no-browser` stops the browser from opening.
- `--idle-minutes 15` sets the session timeout.

## The stages

| Page | What you do there |
|---|---|
| Server readiness | Runs the readiness checks with `-Mode Check`, shows them by category, and fixes the selected items. There is an option to run the fixes in an elevated window, where Windows asks for Administrator approval. Low-risk fixes can be pre-selected with one click. Medium-risk fixes are never pre-selected. |
| Connections | Enter the tenant URLs, service users, rate limits, directory mapping and Safe defaults. Enter each credential (held in memory only), test sign-in, and run the read-only tenant preflight. |
| Data files | Drag in the Delinea secret export and the permissions export. You can also drag back review files that were edited in Excel. All workspace files can be downloaded or dragged out. |
| Mapping rules | Edit the group rules (exact or regex, with a minimum permission), folder rules, fallback naming, Safe prefix, template-to-platform map, permission-to-role map and secret field slugs. Then generate the mapping (Phase 1). |
| Review | **Accounts**: a searchable, filterable grid with inline edits and bulk set for every matching row. **Safes**: length and validity checks, Safes without members, and rename (this updates the accounts and the members together). **Safe members**: edit the role, remove or add members. **Plan**: a dry run. |
| Rehearsal | A write test in the real tenant using `ZZ…` prefixed Safes and fake secrets. Delinea is never contacted. It has live progress, retry of failures, and cleanup that deletes only the Safes the rehearsal created. |
| Migration | A go / no-go checklist, the Delinea access probe for cutover day, an optional pilot for a few Safes, stage selection, a typed `MIGRATE` confirmation, live progress, Stop, and retry of failures. |
| Results | Per-stage totals. An object ledger with errors and fix hints. Run history. The migration, rehearsal and UI audit logs with hash-chain verification. The ledger report CSV and every download. |

Safety gates:
- The migration starts only after a clean **Plan** on the exact current review files. The SHA-256 hashes are compared, so any edit after the plan means running the plan again.
- The rehearsal, cleanup and migration each need a typed confirmation word.
- Only one job runs at a time.
- Review edits are locked while a run is in progress.

## Security model

The console keeps the existing rule: no secret values or credentials at rest.

| Risk | What the console does |
|---|---|
| Someone else on the network | It listens on 127.0.0.1 only. There is no option to bind anything else. |
| Another local user, or a web page in the browser | Opening it needs the one-time link from the console window, which is exchanged for an HttpOnly, SameSite=Strict session cookie. Only one session is active at a time. Every request is checked for the right Host header, which blocks DNS rebinding. Every change needs a custom header and a same-origin Origin, which blocks cross-site request forgery. |
| Browser-side attacks | Strict Content-Security-Policy (only same-origin scripts, no inline scripts, no framing). `nosniff`, `no-referrer` and `no-store` are set. Nothing loads from a CDN. |
| Credentials | They are typed into the console and held only in the server process's memory. They are never written to disk, logs, the config or reports, and never returned to the browser. Only the child process that needs one gets it, in its environment. It is dropped on End session, after 15 minutes idle (background refreshes don't count as activity), when a new link is opened, and on shutdown. The config refuses any key that looks like a credential. |
| Secret values in uploads | Uploads are parsed in memory. Password, passphrase, private key and attachment columns are removed **before** anything is written. The console counts the removed values and warns you to delete the original file securely. |
| TLS | `verify_tls` cannot be switched off. Endpoints must be `https://`. Plain http is accepted only for `127.0.0.1`, for the test mock, and is flagged. |
| Rate limits | The settings page shows the effective calls per 5 minutes and flags anything at or above the 5,000 starting policy. |
| Accountability | Every UI action goes into `workspace/ui_audit.jsonl`, which is hash-chained in the same format and uses the same verifier as Phase 2. That covers session start and end, operator name, credential set or cleared (never the value), settings changes with before and after values, uploads (with hashes and removed columns), review edits (row, column, old, new), Safe renames, job start and end, downloads and connection tests. Runs record the operator as `Name (Windows user, via UI)`. |

Honest limits:
- Traffic between the browser and the console is plain HTTP on the loopback interface. It never leaves the machine.
- Python cannot reliably wipe a string from memory. Credentials are dropped, not zeroed.
- A child process's environment can be read by the same Windows user and by administrators. This is the same exposure as the CLI's environment variables, and it lasts only while that job runs.
- Use the console on a hardened server (see the readiness checks) and lock the screen when you step away.

## Workspace layout

```
workspace/
  inputs/            delinea_export.csv, delinea_permissions.csv   (scrubbed, metadata only)
  config/            mapping_config.json, phase2_config.json        (no credentials)
  phase1_output/     Migration_Review.csv, Safes_Review.csv, Safe_Members_Review.csv
  history/           earlier review files, kept before every regenerate, edit or upload
  state/production/  ledger, audit_log.jsonl, run logs, reports   (the real migration)
  state/rehearsal/   the same for rehearsals (kept separate by design)
  state/preflight/   preflight reports
  readiness/         readiness reports and logs
  ui_audit.jsonl     UI action audit log (hash-chained)
```

The CLI works on these files directly too. For example:

```
python phase2\cyberark_phase2_execute.py status --config workspace\config\phase2_config.json --state-dir workspace\state\production
```

## Tests

- `python ui/tests/test_ui_backend.py` runs 71 checks against the Phase 2 mock APIs. They cover:
  - access control (link, cookie, Host, Origin and CSRF checks, headers, path traversal)
  - settings validation
  - credentials never echoed
  - upload scrubbing
  - Phase 1 and the review edits
  - the plan gate
  - rehearsal and cleanup
  - a migration stopped mid-run and resumed without duplicates
  - retry of failures, the probe and the report
  - all three audit chains
  - no credential or secret value in any workspace file
  - idle expiry dropping the credentials
- `node ui/tests/ui_browser_test.js [screenshot-dir]` drives the real pages in Chromium with Playwright through the whole flow. It fails on any console error or CSP violation.

Both pass on Linux with Chromium. They have **not yet been run on Windows, or in Edge**. The Server readiness page needs Windows PowerShell, so it has only been checked for its "not available here" state.

## Changing the front end

The source is in `ui/web/` (React 18 and Vite 5, no other runtime dependencies). On a workstation with Node.js:

```
cd ui/web
npm ci
npm run build      # writes ui/server/static/
```

Then copy the rebuilt `ui/server/static/` to the server. The server itself never needs Node.js.
