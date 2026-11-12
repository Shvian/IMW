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

## Quick start

```
python -m pam2pc sources                                   # list supported formats
python -m pam2pc init-config my_config.json                # starter config to edit

# 1. Dry run: review files, plus upload files with an empty secret column
python -m pam2pc convert -i export.csv -p permissions.csv -c my_config.json -o run1

# 2. Fix the config, or edit review/Accounts_Review.csv and feed it back:
python -m pam2pc convert -i export.csv -p permissions.csv -c my_config.json -o run2 \
    --overrides run1/review/Accounts_Review.csv

# 3. Upload-ready files, with secrets
python -m pam2pc convert -i export.csv -p permissions.csv -c my_config.json -o final \
    --overrides run1/review/Accounts_Review.csv --include-secrets
```

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
- **Overrides** (`--overrides`, optional). This is an edited copy of `review/Accounts_Review.csv`. Only the values you *changed* in `Migrate`, `Target_Safe`, `Platform_ID` and `Account_Name` are applied, matched by `Record_ID`.

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

The earlier design never stored a secret: it fetched each one from Delinea just in time. With no live connections, that is no longer possible. **The source exports, and `upload/Accounts.csv` when you pass `--include-secrets`, hold secrets in plaintext.** The tool limits the exposure this way:

- Secrets are written **only** to `upload/Accounts.csv`, and only with `--include-secrets`. The review files and the manifest never contain them, and the tests check this. Any column whose name looks like a secret (password, passphrase, private key, PIN, TOTP/OTP) is left out of the review files.
- By default it runs dry, so you can review everything before a secret is ever written.
- `Accounts.csv` is created as owner-only (`0600`) on Linux and macOS. On Windows, control access through the folder's ACLs.
- `manifest.json` records SHA-256 hashes, so you can show later that the uploaded file is the one that was reviewed.

What you still need to do:
1. Work on the migration host only, on an **encrypted volume** (BitLocker or similar), in a folder only the migration operators can read.
2. Don't email, sync or copy the exports or `upload/` anywhere else. Don't open `Accounts.csv` in Excel: it can silently change values that start with `=`, `+`, `-` or `@`, and it strips leading zeros.
3. Generate the upload files as late as possible, upload them, check the result, then **securely delete** the source exports and the `upload/` folder. You can keep `review/` and `manifest.json` as the record of the migration.

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
| `pam2pc/` | The converter: `adapters/`, `config.py`, `model.py`, `transform.py`, `writers.py`, `xlsx.py`, `cli.py` |
| `samples/` | Sample exports for every source, with matching configs |
| `tests/` | `python -m unittest discover -s tests` |
| `tools/` | A synthetic Delinea data generator, for volume testing |
| `legacy/` | The earlier live-API suite (phase 1 and 2, the readiness checker, the Migration Console UI). It is kept for reference and is not maintained. See [legacy/README.md](legacy/README.md). |
