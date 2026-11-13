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

## Easiest: the Idira Migration Workbench (menus, no SQL)

Double-click `start-ui.cmd`, or run `python -m pam2pc ui`. A page opens in your browser over HTTPS. **Sign in with your Windows password first**: only the Windows user who started the Workbench can unlock it, and Windows itself checks the password (nothing is stored). The page then walks through these steps:

1. **Load exports.** Copy the export files into `pam2pc_workspace\inbox` (click the path to open it in Explorer), tick them under **Load** and click Load. For a permissions file also tick **Permissions file** (that ticks Load for you); several are merged. Secrets are encrypted as they load, and you can securely delete each export straight from this page. Invisible and control characters (zero-width spaces, line breaks inside a name) are removed as records load; the Overview counts the accounts this touched and links to them.
2. **Mapping rules**, one page per topic, each with its own **Save & apply** that saves only that page:
   - **A. Directory sources.** Where Privilege Cloud finds each group and user (searchIn), with name rules per source: drop the domain, find and replace, add text before or after, change case. A preview shows every member as it will be uploaded.
   - **B. Permissions: Safes.** Safe from folder (the default), folder exceptions, the naming convention (folder abbreviations, every placeholder's values, your own placeholders), Safe settings (CPM, description, retention by versions or days, automatic CPM management), and the optional access-group rules.
   - **B. Permissions: Safe members.** Source permission to role, with the Privilege Cloud presets and your own custom roles.
   - **C. Platforms.** Platform rules, record type to platform, and the default platform.
   - **D. Accounts.** How accounts are named, URL addresses, and extra account properties.
   - **Settings file (JSON)** for anything else.

   Input tables start folded: click the row (arrow or **Edit**) to open one. **Next** at the bottom goes to the next page. Every input has a tooltip that explains it and its syntax, and Safe names, platform IDs and account names warn as you type when they hold characters Privilege Cloud doesn't allow.
3. **Review & change**, in two parts:
   - **A. Safes & Safe members.** The Safes (with their CPM, description and retention) and the members the upload will create. Tick any number of Safes, then add a member to all of them (name, directory, user or group, role) or remove one from all of them. You can also tick rows in the Members table to remove them. Your member changes are listed with an Undo button and survive re-running the rules.
   - **B. Accounts & platforms.** Pick a list from the menu (Needs a look, Errors, Forbidden characters changed, Safe name was changed, No access groups, Possible duplicates, Changed by you...), narrow it with filters or search, tick accounts (or "all accounts in this list") and move them to another Safe, give them another platform or `(none)` for no platform, rename one, leave them out, or undo. You can add a reason, which goes into the log. Click a row to see everything about that account.
4. **Create upload files.** Choose everything or one wave (by Safe, platform or source), and a dry run or upload-ready. Upload-ready needs you to type a confirmation. Old upload files can be securely deleted from the same page.

The **Overview** boxes open the matching list (Needs a look opens Review with that list picked, and so on). It also lists every loaded file with its SHA-256 checksum, and marks a file loaded more than once as the same or different content. Loading a file with the same name again replaces its records (matched by record ID) and keeps your changes; loading the same content under another name loads every record twice.

The **Activity log** page shows a summary (by action, by person, changes by field) and the latest entries, and exports the whole log and every account change as CSV.

![Review page](docs/ui/03_review.png)

**Locking and ending.** After 10 minutes without activity, or when you click **Lock session**, the page goes back to the sign-in screen. **End session** explains what it does and needs you to type END SESSION: it stops the Workbench, and the database stays on disk, encrypted for your Windows account, until you start the Workbench again and sign in. Tick the box in that pop-up to securely delete the database as well. Output files and the inbox are kept either way.

**Only the Windows user who created the workspace can use it.** The first start records you as the owner of the workspace folder and its database, and sets the folder's permissions so that only you (and SYSTEM) can open anything in it: the inbox exports, the database, the config and the outputs. Inherited permissions are removed, so other users of the machine, including administrators, can't read the files without taking ownership (which needs admin rights and leaves a trace in Windows). Another user who starts the Workbench or the command line on your workspace or database gets a "belongs to" message and nothing opens. While the Workbench runs, it also checks which Windows user owns each browser connection and refuses everyone but you, because `127.0.0.1` is shared by every session on the machine. A workspace must be a new or empty folder (or an existing Workbench workspace), because its permissions are locked down.

**HTTPS.** The page is served over HTTPS with a certificate the Workbench makes for this computer on first start (RSA 2048, valid for `127.0.0.1` and `localhost` for 397 days; standard library only). It is kept in `<workspace>\tls\`, with the private key encrypted by DPAPI for your account. The browser warns once because the certificate is self-signed: choose Advanced, then Continue. To stop the warning, start once with `python -m pam2pc ui --trust-cert`, which adds the certificate to your own Windows user's Trusted Root store (Windows asks you to confirm). `--new-cert` makes a new one; `--no-tls` serves plain HTTP for troubleshooting only. The start-up window prints the certificate's SHA-256 fingerprint.

The page is served only to this computer (`127.0.0.1`), through a one-time link that becomes a Secure, HttpOnly session cookie. Five wrong passwords in a row add a growing wait, and every sign-in, lock and failed attempt is logged. Your Windows account lockout policy also counts failed attempts. No page ever shows a secret. The UI runs as you, so DPAPI works the same as on the command line. Everything lives in the workspace folder: `migration.db`, `config.json`, `inbox\` and `output\`. More screenshots are in [docs/ui](docs/ui).

Sign-in needs Windows. For automated tests on other systems, set `PAM2PC_UI_TEST_PASSWORD`; never use that with real data.

## Command line

**The staging database.** Load the exports once into an SQLite file on the migration host. Work on the data there with rules, edits and SQL queries, then extract upload files whenever you need them, all at once or in waves.

```
python -m pam2pc init-config my_config.json                       # starter config to edit

python -m pam2pc ingest  --db migration.db -i export.csv -p permissions.csv -p more_permissions.csv -i vault.xml
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
- **Permissions CSV** (`-p`, optional). Use it for sources whose export has no access data, such as Delinea and KeePass. It has one grant per row, with the columns `Folder Path, Secret Name, Secret ID, Group, Permission` and an optional `Member Type`. A row with an ID or name applies to that record. A row with only a folder applies to that folder and its subfolders, and the nearest folder wins. Record-level rows take precedence. Repeat `-p` to merge several permissions files; a group listed twice for the same folder or record counts once. Build it from a Secret Server folder and secret permissions report, or by hand.
- **Config** (`-c`, optional). It is JSON and only needs the keys you change; everything else uses the defaults. `init-config` writes a starter file with every key; the comments in `pam2pc/config.py` explain each one. Configs from the old phase 1 still load.
- **Overrides** (`--overrides`, `convert` only). This is an edited copy of `review/Accounts_Review.csv`. Only the values you *changed* in `Migrate`, `Target_Safe`, `Platform_ID` and `Account_Name` are applied, matched by `Record_ID`.

## How records are mapped

| Step | Rule |
|---|---|
| Safe | Safes are **object oriented by default: they follow the folders**. The tool checks an override, then a `Target Safe` column in the source, then `folder_rules` (exceptions; the longest folder prefix wins), then `group_rules`, then `fallback_strategy`, which names the Safe from the folders (`convention`, the default and described below; `folder_leaf`; `folder_path`; or `unmapped`). `group_rules` are optional and empty to start with, because role-oriented Safes don't scale as well. Each rule maps an access group to a Safe: the first rule matching one of the record's groups wins, `min_role` ignores weak grants, `{1}` inserts regex captures, and `{folder_leaf}` and `{folder_path}` insert the folder. Set `group_rules_first` to check them before the folder rules. |
| Safe name | At most **28 characters**. The forbidden characters `\ / : * ? " < > \|` become **`-`**, repeated `-` are collapsed, and an optional `prefix` is added. `Valid_Safe_Name=FALSE` means the name had to change. When two different names end up identical, the later one gets a `-2` style suffix that still fits in 28 characters. |
| Platform | The tool checks an override, then a `Platform ID` column, then `platform_rules` (a regex on type, folder, name, address, username or any source column), then `platform_map` (record type to platform), then `default_platform`. A record with no platform is an **ERROR**. |
| Members | Each source permission is mapped through `permission_map` to a role: one of the Privilege Cloud **permission presets** (Connect only, Read only, Approver, Accounts manager, Full) or one of your named `custom_roles`, where you choose every permission flag. The defaults are Owner/Full to Full, Edit/Write to Accounts manager, View/Read to Read only, Use/Connect to Connect only, Approve to Approver, and List to the custom role List only. Each Safe gets every group seen on its accounts, at the strongest role seen (the role with the most permissions). `directory_sources` decide each member's searchIn and name: each source matches a domain (`CORP`, `corp.example.com`), `*` or `re:<pattern>`, applies to groups, users or both, and can drop the domain, find and replace, add text before or after and change case. Members no source matches use `directory_map` (default: everything to `Vault`). |
| Safe settings | `safe_defaults` sets `managingCPM`, `description` (may use `{folder}` and `{safe}`) and retention (`numberOfVersionsRetention` or `numberOfDaysRetention`, not both). `safe_rules` override them for Safes whose name matches a pattern; the first match wins. `account_defaults.automaticManagementEnabled` turns CPM management on for migrated accounts. |
| Accounts | The name comes from `account_name.template` (default `{name}`), otherwise `account_name.fallback` (default `{address}-{username}`). Invalid characters become `_`, and the name is made unique within the Safe. URL addresses are reduced to the host name. Mapped source columns go into `platformAccountProperties` (`account_property_map`). |
| Not migrated | File attachments and file fields (`exclude_field_patterns`). Each record that loses one says so in its Notes. |

### Safe naming convention (abbreviations)

Existing structure comes first. A record with folders gets a Safe named after its folder levels, **in order, each level abbreviated**, and always within 28 characters:
- `\Applications\Storefront\Prod` becomes `APP-SF-P`.
- `\Databases\Oracle Finance` becomes `DB-ORC-FIN`.

Only records with no folders, such as flat KeePass files or spreadsheets, get the CyberArk example layers from `template_no_folders` (default `{env}-{tech}-{flavor}-{acct}`). For example, a local Windows service account with no folder becomes `P-SVR-WIN-LS` when the `{env}` default is P.

| Placeholder | Comes from | Codes |
|---|---|---|
| `{folder}` | Every folder level, in order. A whole folder name in `abbreviations` wins; otherwise each word gets a code from the dictionary, or an automatic code (compound words and CamelCase become initials, e.g. Storefront becomes SF and SharePoint becomes SP, and other words become consonants). `{folder_leaf}` is the last level only. | APP, SF, BOS, HR, FIN |
| `{env}` | A folder word such as Production, Dev, Test or QA, otherwise its default. With `{env}` in the template the code moves to that spot; without it, the code stays where the folder is. | P, D, T, Q |
| `{tech}` | The platform | SVR, DB, NET, DOM, WKS, WEB, CLD |
| `{flavor}` | The platform | WIN, UNX, SQL, ORC, CSC, AZ |
| `{acct}` | The platform, refined by username (root, sa, svc_*, enable) | LA, DA, LS, DS, RT, SA, EN |
| your own, e.g. `{region}` | Whatever its rows say, for example the address or a source column | HQ, EU |

Every placeholder except `{folder}` is a list of value rows in `safe_convention.layers`, all editable, including the built-in ones. Each row looks at one field, or two, and gives a code when the pattern matches; the first matching row wins, otherwise the placeholder's default. Fields: `folder_word`, `folder_level`, `folder`, `platform`, `username`, `address`, `name`, `type`, `source`, an earlier placeholder's code (`env`, `tech`, `flavor`, `acct`), or `column:<source column>`. For example, a `{region}` placeholder with the row `address` matches `\.eu\.example\.com$` gives `EU`, and the template `{region}-{folder}` turns `\Applications\Payments` into `EU-APP-PAY`.

To split a folder's accounts further (least privilege), add layers to `template`, for example `{folder}-{flavor}` or `{folder}-{acct}`. The full CyberArk style is `{env}-{folder}-{tech}-{flavor}-{acct}`, which gives `P-BOS-DC-WIN-SVR-HR-APP-LS` for `\Boston DC\Production\Windows Servers\HR App` with a `svc_hr` account.

A code that already appears earlier in the name is not repeated. When a name is too long, it is shortened in this order, so as many folder levels as possible survive:
1. Long upper folder names become their initials (`Customer Facing` becomes `CF`).
2. The last folder becomes its initials.
3. The most generic top levels are left out.

All of this is set under `safe_convention`:
- `template` and `template_no_folders`
- `layers`: the placeholders and their value rows
- `abbreviations`: folder names or words with your code, which win over the built-in list in `pam2pc/naming.py`
- `skip_folder_levels`
- `default_environment`, `environment_words` and `platform_codes`: older settings, still read

In the Workbench, the **B. Permissions: Safes** page lists every folder name found in the loaded exports with the code it gets. You can type over any code, or keep all the suggested codes so they stay fixed. The page also flags two folders that end up with the same automatic code, and has a live preview. Rules can use the layers too. For example, `{"group_pattern": "^CORP\\APP-(.+)-Owners$", "safe": "{env}-{1}-{tech}-{flavor}-{acct}"}` gives `P-PAY-SVR-WIN-LS`, and `{convention}` inserts the whole name.

Two things are flagged for review:
- A Safe built from more than one source folder (the abbreviations collided, or levels were skipped).
- A Safe with more than `safe_max_accounts` accounts (default 3,000). CyberArk recommends 3,000 to 5,000 accounts per Safe within its 20,000-object limit.

The Workbench saves only the settings you changed into `config.json`, so later updates to the defaults still reach you. A config saved by an older version is upgraded on load: settings that still equal the old defaults move to the new defaults (for example the role names Owner/Editor/User/Viewer become Full/Accounts manager/Read only/List only), and anything you changed is kept.

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
    FileCategories.csv          every property column used in Accounts.csv: file category name,
                                how many accounts fill it, which platforms use it
    PlatformProperties.csv      per platform, which file categories its accounts use (to check or
                                create the platforms before the upload)
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
