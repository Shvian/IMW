# Phase 2: Online API execution (secrets fetched at send time)

Python 3.8+, standard library only. Phase 2 loads the reviewed Phase 1 files into CyberArk Privilege Cloud in a fixed order: **Safes, then members, then accounts**. For each account it fetches the secret from the Delinea REST API, sends it straight to CyberArk, and drops it. Secrets are never written to disk, logs or the ledger.

## Commands
```
python cyberark_phase2_execute.py --write-default-config phase2_config.json     # then edit it
export CYBERARK_CLIENT_SECRET=...   DELINEA_PASSWORD=...                         # or you are prompted
ARGS="--config phase2_config.json --review Migration_Review.csv --members Safe_Members_Review.csv --state-dir migration_state"

python cyberark_phase2_execute.py plan $ARGS                    # validate + what would happen, no changes
python cyberark_phase2_execute.py run  $ARGS --safe UNIX-Admins # pilot one Safe
python cyberark_phase2_execute.py run  $ARGS                    # full run (type MIGRATE)
python cyberark_phase2_execute.py run  $ARGS --only-failed      # after fixing failures
python cyberark_phase2_execute.py status       --config phase2_config.json --state-dir migration_state
python cyberark_phase2_execute.py report       --config phase2_config.json --state-dir migration_state
python cyberark_phase2_execute.py verify-audit --config phase2_config.json --state-dir migration_state
```

## Audit, resume and no duplicates
Keep `--state-dir` for the whole migration. It holds:
- **`migration_state.db`**, a SQLite ledger with one row per Safe, member and account. Each row records the status (PENDING, IN_PROGRESS, DONE, FAILED), result (CREATED, EXISTS, ADOPTED), attempts, CyberArk id, last error, error code and a fix-it hint. It also records each run with its operator, host and SHA-256 of the input files.
- **`audit_log.jsonl`**, an append-only, SHA-256 hash-chained audit trail. It records every action and outcome, every secret read (by ID and field, never the value), auth events, rate-limit stats, run start and end, operator and host. `verify-audit` detects any edit or deletion and reports the line.
- **`logs/`** holds the human-readable run logs.

Re-running is always safe:
- An object already marked DONE in the ledger is skipped without calling the API.
- Every other object is looked up in CyberArk before it is created. An account that already exists there is ADOPTED, not created again. An exact account-name match wins. A username and address match counts only when the secret type is the same and no other Delinea secret in the ledger already owns that account. So a password and an SSH key for root@host, or two secrets for the same login, stay separate accounts.
- A create that times out or returns 5xx is never blindly retried. The script first checks whether the create went through.
- A crash leaves a lock file. Re-run with `--force-unlock`, and anything that was IN_PROGRESS is re-checked.

## Long runs and token renewal
The run never stops because a token expired:
- **Delinea** issues a refresh token with each access token. The script renews with the refresh token 60 seconds before expiry, or at 80% of a short token's lifetime. If the refresh token is refused, for example because it has expired too, the script signs in again with the stored credential.
- **CyberArk**'s Identity `platformtoken` client-credentials grant does not issue refresh tokens. That is standard for OAuth client credentials. The script requests a new token on the same early schedule. If CyberArk ever returns a refresh token, it is used automatically.
- If a token is revoked mid-run (HTTP 401), the script renews once and repeats the request.
- Token endpoint 429s and 5xx errors are retried with backoff, under the same rate limiter.
- The run summary and the audit log count renewals per system, by refresh token and by re-sign-in.

The credentials stay in process memory for the length of the run, so that it can sign in again. They are never written anywhere.

## Rate limits
The starting policy is to stay **below 5,000 calls per 5 minutes on each system**. Every call counts: token, lookup, Delinea secret read and create. Two limits enforce this, set separately under `cyberark` and `delinea`:
- `requests_per_minute: 950` paces calls evenly, which works out to at most 4,750 per 5 minutes.
- `max_calls_per_window: 4900` over `window_seconds: 300` is a hard ceiling. If it is ever reached, the script pauses until the oldest call leaves the window.

When a system returns HTTP 429, the script halves the rate for that system only, down to `min_rate_fraction` of the limit, and honors `Retry-After`. It climbs back after `rate_recovery_seconds` with no further 429. The run summary and the audit log show, per system, the number of 429s, the time spent waiting, and the peak calls in any 5-minute window.

## Validate before you have Delinea access
These commands need only the CyberArk tenant.

```
# 1. Read-only checks: auth, API rights, platforms, Identity directories, your groups, Safe-name clashes
python cyberark_phase2_execute.py preflight --config phase2_config.json --state-dir preflight \
    --mapping-config ../phase1/mapping_config.json --group "CORP\PAM-Unix-Admins" --group "CORP\PAM-DBA"

# 2. Synthetic Delinea data using your REAL group names, then Phase 1 as usual
python ../tools/generate_synthetic_delinea.py --secrets 500 --out synthetic --groups "CORP\PAM-Windows-Admins" "CORP\PAM-Unix-Admins" ...
python ../phase1/delinea_phase1_mapping.py --input synthetic/delinea_export_synthetic.csv \
    --permissions synthetic/delinea_permissions_synthetic.csv --config synthetic/mapping_config_synthetic.json --output-dir synthetic/p1

# 3. Rehearsal in the real tenant: ZZTEST- Safes, random fake secrets, Delinea never contacted
python cyberark_phase2_execute.py run --config phase2_config.json --rehearsal-prefix ZZTEST- \
    --review synthetic/p1/Migration_Review.csv --members synthetic/p1/Safe_Members_Review.csv --state-dir rehearsal_state

# 4. Remove only what the rehearsal created
python cyberark_phase2_execute.py cleanup-rehearsal --config phase2_config.json --state-dir rehearsal_state
```

Rehearsal safeguards:
- The prefix must start with `ZZ`.
- A rehearsal refuses a production state dir, and a real run refuses a rehearsal state dir.
- Cleanup deletes only the Safes that the rehearsal's own ledger shows it CREATED with that prefix. It never searches for Safes.
- Safes keep deleted accounts for their retention period. If a Safe can't be deleted yet, cleanup says so, and you re-run it after the retention period passes.

## Migration day: prove Delinea access first
```
python cyberark_phase2_execute.py probe-delinea --config phase2_config.json \
    --review phase1_output/Migration_Review.csv --state-dir migration_state
```
This reads one secret per template and field, and prints only OK or FAIL and the value's length. It confirms the API user's rights and the field slugs in minutes. Each read is audited.

## Exit codes
| Code | Meaning |
| --- | --- |
| 0 | All objects succeeded |
| 3 | Some objects failed; fix them and run `--only-failed` |
| 2 | Inputs invalid; nothing was sent |
| 1 | Auth failure, abort or interruption |

Stopping: Ctrl+C, Ctrl+Break (Windows) and SIGTERM all stop a run cleanly. The lock is released, and in-progress objects are re-checked on the next run. The UI's Stop button uses this.

## Test without a tenant
`python tests/run_e2e_test.py` starts `tests/mock_apis.py`, a mock of CyberArk and Delinea, and runs 48 checks, covering the following:
- rate limiting on both sides
- each account getting its own secret
- clear hints for failures
- `--only-failed` retries
- a re-run creating nothing
- a lost create response
- a hard crash and resume
- audit tamper detection
- no secret values on disk
- synthetic data, rehearsal guards and fake secrets
- cleanup touching only rehearsal Safes
- preflight making no changes
- the Delinea probe never printing a value
- tokens expiring every 3 seconds during a long run
- a password and a key for the same login staying separate accounts
