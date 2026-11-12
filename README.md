# D2P: PAM exports to Privilege Cloud upload files

`pam2pc` is an **offline** converter. It reads credential exports from other PAM tools and password managers and turns them into CSV files ready to load into CyberArk Privilege Cloud through its REST API. It makes **no network connections** to the source or to Privilege Cloud. Its job is the heavy lifting of a migration: mapping, cleaning and validating the data.

```
  export files ──► source adapter ──► common model ──► rules ──► review/   (no secrets, shareable)
  (Delinea, KeePass,                   (accounts,      (Safes,     upload/   Safes.csv
   CSV, Excel...)                       grants)         platforms,           SafeMembers.csv
                                                        members,             Accounts.csv
                                                        checks)
```

Requirements: Python 3.8 or later, **standard library only** (Excel files included). There's nothing to `pip install` on the migration host.

## Easiest: the Migration Workbench (menus, no SQL)

Double-click `start-ui.cmd`, or run `python -m pam2pc ui`. A page opens in your browser and walks through five steps:

1. **Load exports.** Copy the export files into `pam2pc_workspace\inbox`, tick them and click Load. Secrets are encrypted as they load, and you can securely delete each export straight from this page.
2. **Mapping rules.** Fill in simple tables: which group goes to which Safe, which folder goes to which Safe, which record type uses which platform, and how permissions turn into roles. Group, folder and type names already loaded are suggested as you type. Record types with no platform yet are highlighted.
3. **Review & change.** Pick a list from the menu (Needs a look, Errors, Safe name was changed, No access groups, Possible duplicates, Changed by you...), narrow it with filters or search, tick accounts and use the buttons: Exclude, Include, Move to Safe, Set platform, Rename or Undo. You can add a reason, which goes into the log. Click a row to see everything about that account.
4. **Safes & members.** See the Safes and members the upload will create.
5. **Create upload files.** Choose everything or one wave (by Safe, platform or source), and a dry run or upload-ready. Upload-ready needs you to type a confirmation. Old upload files can be securely deleted from the same page.

An **Activity log** page lists every action and change.

![Review page](docs/ui/03_review.png)

The page is served only to this computer (`127.0.0.1`), through a one-time link that becomes a session cookie, and the session ends after 30 minutes idle. No page ever shows a secret. The UI runs as you, so DPAPI works the same as on the command line. Everything lives in the workspace folder: `migration.db`, `config.json`, `inbox\` and `output\`. More screenshots are in [docs/ui](docs/ui).

## Command line

**The staging database.** Load the exports once into an SQLite file on the migration host. Work on the data there with rules, edits and SQL queries, then extract upload files whenever you need them, all at once or in waves.

```
python -m pam2pc init-config my_config.json                       # starter config to edit

python -m pam2pc ingest  --db migration.db -i export.csv -p permissions.csv -i vault.xml
#   -> secrets are encrypted with Windows DPAPI as they are stored; securely delete the exports now
python -m pam2pc map     --db migration.db -c my_config.json      # apply the rules (rerun after config changes)
python -m pam2pc query   --db migration.db --report list          # built-in reports
python -m pam2pc query   --db migration.db --report invalid-safes
python -m pam2pc query   --db migration.db "SELECT target_safe, COUNT(*) FROM accounts GROUP BY 1"
python -m pam2pc set     --db migration.db --where "folder LIKE '\Unfiled%'" --migrate N --reason "out of scope"
python -m pam2pc set     --db migration.db -r delinea:export:1042 --safe "APP-Payments" --platform WinDomain
python -m pam2pc set     --db migration.db --from-review edited/Accounts_Review.csv
python -m pam2pc extract --db migration.db -o wave1 --where "target_safe LIKE 'WIN-%'"                     # dry run
python -m pam2pc extract --db migration.db -o wave1 --where "target_safe LIKE 'WIN-%'" --include-secrets --force
```

**One-shot: `convert`.** This does everything in memory in a single command and keeps nothing between runs. It's handy for quick looks and small jobs.

```
python -m pam2pc convert -i export.csv -p permissions.csv -c my_config.json -o run1          # dry run
python -m pam2pc convert ... -o run2 --overrides run1/review/Accounts_Review.csv --include-secrets
```

## The staging database

`ingest` creates the database on first use. Run it again to add more exports. Re-ingesting the same file replaces its records, matched by `Record_ID`, and your edits are kept. Records that are gone from the new export are not deleted.

| Table / view | Holds |
|---|---|
| `inputs` | Every file ingested, with its SHA-256, who loaded it and when. |
| `records`, `grants` | The common model of every record and its access grants. `secret_enc` holds the **DPAPI-encrypted** secret. |
| `edits` | Your deliberate changes to `migrate`, `target_safe`, `platform_id` and `account_name`, with who made them, when and why. Edits survive re-ingest and re-map. |
| `accounts` (view of `plan_accounts`), `plan_safes`, `plan_members` | The result of the last `map`: the same columns as the review CSVs. |
| `audit` | Every ingest, map, set and extract, with the user, host and time. |

- `set` re-runs the mapping straight away with the config from the last `map`.
- `query` opens the database **read-only**: it cannot change data or attach other files, and `secret_enc` always reads as NULL.
- `extract --where` limits the *upload* files to a wave. The review files always cover every record. Name suffixes and collisions are worked out across the whole database, so the waves never conflict with each other.

**How the secrets are protected.** Each secret is encrypted with Windows DPAPI (`CryptProtectData`, called through `ctypes`, so no install is needed). Only the **same Windows account on the same machine** can decrypt it. Each value is also bound to a random salt for this database and to its own `Record_ID`, so a copied value won't decrypt in another database or another row. The database file holds no plaintext. Practical consequences:
- Run `ingest` and `extract --include-secrets` as the same Windows account, on the migration host. A copy of the database taken elsewhere, or used by another account, exposes metadata only.
- If that Windows account or its profile is lost, the secrets are lost too. Keep the original exports offline under your normal controls until the migration is signed off, or be ready to export again.
- On Linux or macOS there's no DPAPI. There, `ingest` needs either `--no-secrets` (metadata only) or `--insecure-plaintext-secrets` (test data only).

You can pass several `-i` files in one run, including files from different sources (for example a Delinea export plus a KeePass vault plus a spreadsheet). The tool detects the format of each file. To force one, prefix the path with the source name: `-i keepass=vault.xml`, `-i table=inventory.xlsx`.

## Supported sources

| Source | Files | Notes |
|---|---|---|
| `delinea` | Delinea / Thycotic Secret Server CSV export | Handles the multi-template export, with one header row per template and an optional template-name line above each. Quoted multi-line values work. The template becomes the record type. Access groups come from `--permissions`. |
| `keepass` | KeePass 2.x **XML** export, KeePass / KeePassXC **CSV** export | Groups become folders. The Recycle Bin, entry history and attachments are skipped, and an `SSH Private Key` field makes the entry a key account. Encrypted `.kdbx` files are not read: export to XML in KeePass first (File > Export > KeePass XML (2.x)). |
| `table` | Any **CSV / TSV / Excel (.xlsx)** sheet, one account per row | Columns are found by name through `field_aliases`, or you name them in `sources.table.columns`. Access can be one column (`CORP\Admins=Owner; CORP\Helpdesk=Read`) or a group column plus a permission column with one grant per row; those rows are merged into one account. You can choose the sheet and the header row. A sheet may already carry `Target Safe` and `Platform ID` columns, which take precedence over the rules. |

To add a source, see [Adding a source adapter](#adding-a-source-adapter).

## Inputs

- **Export files** (`-i`), described above.
- **Permissions CSV** (`-p`, optional). Use it for sources whose export has no access data, such as Delinea and KeePass. It has one grant per row, with the columns `Folder Path, Secret Name, Secret ID, Group, Permission` and an optional `Member Type`. A row with an ID or name applies to that record. A row with only a folder applies to that folder and its subfolders, and the nearest folder wins. Record-level rows take precedence. Build it from a Secret Server folder and secret permissions report, or by hand.
- **Config** (`-c`, optional). It is JSON and only needs the keys you change; everything else uses the defaults. `init-config` writes a starter file with every key; the comments in `pam2pc/config.py` explain each one. Configs from the old phase 1 still load.
- **Overrides** (`--overrides`, `convert` only). This is an edited copy of `review/Accounts_Review.csv`. Only the values you *changed* in `Migrate`, `Target_Safe`, `Platform_ID` and `Account_Name` are applied, matched by `Record_ID`.

## How records are mapped

| Step | Rule |
|---|---|
| Safe | The tool checks these in order: an override, then a `Target Safe` column in the source, then `group_rules` (group-based, the first rule matching one of the record's groups wins, `min_role` ignores weak grants, `{1}` inserts regex captures, `{folder_leaf}` and `{folder_path}` insert the folder), then `folder_rules` (the longest prefix wins), then `fallback_strategy` (`folder_leaf`, `folder_path` or `unmapped`). |
| Safe name | At most **28 characters**. The forbidden characters `\ / : * ? " < > \|` become **`-`**, repeated `-` are collapsed, and an optional `prefix` is added. `Valid_Safe_Name=FALSE` means the name had to change. When two different names end up identical, the later one gets a `-2` style suffix that still fits in 28 characters. |
| Platform | The tool checks an override, then a `Platform ID` column, then `platform_rules` (a regex on type, folder, name, address, username or any source column), then `platform_map` (record type to platform), then `default_platform`. A record with no platform is an **ERROR**. |
| Members | Each source permission is mapped to a role through `permission_map` (for example Owner/Full to Owner, Edit/Write to Editor, View/Read to User, List to Viewer). Each Safe gets every group seen on its accounts, at the strongest role seen. `directory_map` turns `CORP\Group` into memberName `Group` and searchIn `corp.example.com`. `role_permissions` sets the permission flags for each role. |
| Accounts | The name comes from the source name, otherwise `address-username`. Invalid characters become `_`, and the name is made unique within the Safe. URL addresses are reduced to the host name. Mapped source columns go into `platformAccountProperties` (`account_property_map`). |
| Not migrated | File attachments and file fields (`exclude_field_patterns`). Each record that loses one says so in its Notes. |

Each record gets a Status:
- **OK**: nothing to report.
- **REVIEW**: there are warnings, and the record is still uploaded. Examples: the Safe name was changed, the record had no access groups, the secret is empty, or it looks like a duplicate.
- **ERROR**: the record is **left out of the upload files**. Examples: no platform, or no username.

`Migrate=N` (set through overrides) also leaves a record out.

## Outputs

```
<output-dir>/
  review/                       no secret values; safe to share with reviewers
    Accounts_Review.csv         one row per record: Record_ID, Migrate, Status, Notes, target values,
                                source pointer (file line / sheet row), access groups, Source.* columns
    Safes_Review.csv            one row per Safe: length, validity, original names, counts
    SafeMembers_Review.csv      one row per Safe and member: source permission, role, directory
  upload/                       columns named after the Privilege Cloud REST API body fields
    Safes.csv                   safeName, description, location, managingCPM, retention, olacEnabled...
    SafeMembers.csv             safeName, memberName, memberType, searchIn, role, permissions.<flag>...
    Accounts.csv                recordId, safeName, platformId, name, address, userName, secretType,
                                secret, secretManagement.*, platformAccountProperties.*
  manifest.json                 SHA-256 of every input and output file, counts, timestamp, host
```

Notes for whoever writes the uploader:
- Dotted column names map to nested JSON. For example `permissions.useAccounts` becomes `{"permissions": {"useAccounts": ...}}`.
- `recordId` (Accounts) and `role` (SafeMembers) are for traceability and are not API fields. Drop them from the request body. Keep `recordId` in your upload log.
- Boolean columns hold `true` or `false`, and empty cells mean "leave the field out".
- Load the files in order: Safes, then SafeMembers, then Accounts.

## Handling secrets: the trade-off

The earlier design never stored a secret: it fetched each one from Delinea just in time. With no live connections, that is no longer possible. The source exports hold secrets in plaintext, and so does `upload/Accounts.csv` once you pass `--include-secrets`. The tool limits the exposure this way:

- **Exports:** with the database workflow, `ingest` encrypts the secrets with DPAPI as it stores them. You can securely delete the plaintext exports straight away instead of keeping them for the whole project.
- **Outputs:** secrets are written **only** to `upload/Accounts.csv`, and only with `--include-secrets`. The default is a dry run. The review files, the query results and the manifest never contain secrets, and the tests check this. Any column whose name looks like a secret (password, passphrase, private key, PIN, TOTP/OTP) is left out of the review files.
- **File permissions:** the database and `Accounts.csv` are created as owner-only (`0600`) on Linux and macOS. On Windows, control access with the folder's ACLs.
- **Proof:** `manifest.json` records the SHA-256 of every input and output. The database `audit` table records who did what and when.

What you still need to do:
1. Work only on the migration host, on an **encrypted volume** (BitLocker or similar), in a folder only the migration operators can read.
2. Don't email, sync or copy the exports or `upload/` anywhere else. Don't open `Accounts.csv` in Excel: it can silently change values that start with `=`, `+`, `-` or `@`, and it strips leading zeros.
3. Extract with `--include-secrets` as late as possible. Upload, check the result, then **securely delete** the `upload/` folder. Delete the database once the migration is signed off. You can keep `review/` and `manifest.json` as the record of the migration.

## Adding a source adapter

1. Create `pam2pc/adapters/<name>.py` with a class that subclasses `Adapter`. Give it these members:
   - `name`, `description` and `extensions`
   - `sniff(path)`, which returns a score from 0 to 100
   - `read(path, cfg, encoding)`, which yields `SourceRecord` objects (see `pam2pc/model.py`)
2. For tabular data, reuse `adapters/rows.record_from_row()`. It already handles aliases, secrets, attachments, access columns and the extra columns.
3. Register the class in `ADAPTERS` in `pam2pc/adapters/__init__.py`, put a sample in `samples/` and add tests.

The rules, validation and writers need no changes: they only see the common model.

## Repository layout

| Path | What it is |
|---|---|
| `pam2pc/` | The converter: `adapters/`, `config.py`, `model.py`, `transform.py`, `writers.py`, `store.py` (staging database), `protect.py` (DPAPI), `ui/` (Workbench), `xlsx.py`, `cli.py` |
| `samples/` | Sample exports for every source, with matching configs |
| `tests/` | `python -m unittest discover -s tests`, plus `tests/ui_browser_test.js` (Playwright) for the UI |
| `docs/ui/` | UI screenshots |
| `start-ui.cmd` | Double-click launcher for the Workbench on Windows |
| `tools/` | A synthetic Delinea data generator, for volume testing |
| `legacy/` | The earlier live-API suite (phase 1 and 2, the readiness checker, the Migration Console UI). It is kept for reference and is not maintained. See [legacy/README.md](legacy/README.md). |
