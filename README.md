# D2P: Delinea Secret Server to CyberArk Privilege Cloud migration

This suite migrates passwords, SSH keys and metadata (not file attachments) from Delinea Secret Server into CyberArk Privilege Cloud.

**No secret value is ever stored.** The mapping files carry only the Delinea Secret ID. Each secret is read from the Delinea API at the moment it is sent to CyberArk, and is held only in memory.

| Folder | What it is |
|---|---|
| `ui/` | **Migration Console**, a guided local web UI on the migration server. It is the recommended way to run everything below. Start it with `ui\start-ui.cmd`. See [ui/README.md](ui/README.md). |
| `setup/` | `Test-MigrationReadiness.ps1`: checks the migration server's software, connectivity, permissions and CIS-aligned hardening, and offers a fix menu. See [setup/README.md](setup/README.md). |
| `phase1/` | Offline mapping. It parses the multi-header Delinea export, maps secrets to Safes by access group (RBAC flattening), sanitizes Safe names (28 characters, invalid characters become `-`) and writes the review CSVs. See [phase1/README.md](phase1/README.md). |
| `phase2/` | Online execution. It creates Safes, then members, then accounts through the CyberArk REST API. It keeps a SQLite ledger and a hash-chained audit log, resumes without duplicates, retries only what failed, applies adaptive rate limits (below 5,000 calls per 5 minutes per system to start) and renews tokens. It also has the preflight, rehearsal and probe commands. See [phase2/README.md](phase2/README.md). |
| `tools/` | A synthetic Delinea data generator, for testing without Delinea access. |

Requirements: Python 3.8 or later (standard library only) and Windows PowerShell 5.1 for the readiness checks. Node.js is needed only to rebuild the UI front end.

Tests, all against a mock of CyberArk and Delinea:
- `python phase2/tests/run_e2e_test.py`
- `python ui/tests/test_ui_backend.py`
- `node ui/tests/ui_browser_test.js`
