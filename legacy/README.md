# Legacy: live-API migration suite (not maintained)

This folder holds the first version of D2P. It was a Delinea-only migration that connected to both systems: it fetched each secret from the Delinea API just in time and created Safes, members and accounts through the CyberArk API.

On 2026-11-12 the project moved to the offline, multi-source converter in [`../pam2pc`](../pam2pc). This code is kept as it was, for reference. In particular, phase 2's rate limiting, resume ledger and hash-chained audit log could later become an uploader for the converter's `upload/` files.

| Folder | What it was |
|---|---|
| `phase1/` | Offline Delinea mapping (metadata only). Superseded by `pam2pc` with the `delinea` source. |
| `phase2/` | Online execution against the Delinea and CyberArk APIs |
| `setup/` | `Test-MigrationReadiness.ps1`, the migration host readiness checker |
| `ui/` | The Migration Console web UI, which drives phase 1 and phase 2 |

The paths inside these folders' READMEs and tests assume the old layout, where they sat at the top level of the repository.
