# Phase 1: Offline mapping generation (Delinea -> CyberArk Privilege Cloud)

Python 3.8+, standard library only. Makes no network calls.

```
python delinea_phase1_mapping.py --write-default-config mapping_config.json   # starter config
python delinea_phase1_mapping.py --input export.csv --config mapping_config.json \
    --permissions permissions.csv --output-dir phase1_output
```

## Inputs
- **Delinea export CSV.** This is the multi-template export, where each template section has its own header row (found by the `Secret Name` cell). It can have a template-name line just above each header, and quoted multi-line values are handled. It must include the **Secret ID** column, which Phase 2 uses to fetch each secret. Phase 1 needs only metadata. If your Secret Server can produce a report or export without secret values (Secret ID, Secret Name, Folder Path, template, address and username columns), use that instead. If you use a full export, it contains plaintext secrets: create it on the jump host's encrypted volume, run Phase 1 straight away, then securely delete it. The script warns when its input contains secret values.
- **Permissions CSV** (optional, but needed for RBAC flattening). It has the columns `Folder Path, Secret Name, Secret ID, Group, Permission`. Rows that have a Secret Name or ID are secret-level. Rows that have neither are folder-level and are inherited by subfolders. Secret-level rows take precedence over inherited ones. You can build this file from a Secret Server report of folder and secret permissions.
- **mapping_config.json**:
  - `group_rules` are checked in order. The first rule that matches one of the secret's access groups picks the Safe. A rule can be an exact `group`, or a `group_pattern` regex with `{1}` substitution. Set `min_permission` to ignore groups with weaker access.
  - `folder_rules` give explicit folder-to-Safe overrides. They are used only when no group rule matched.
  - `fallback_strategy` can be `folder_leaf`, `folder_path` or `unmapped`.
  - The config also holds `platform_map` (template to Platform ID), `key_templates`, `field_aliases`, `permission_map` and the Safe name rules (28 chars max, `\ / : * ? " < > |`).

## Outputs
- **Migration_Review.csv** has one row per secret. It holds `Migrate` (Y/N for Phase 2), `Review_Status` and `Review_Notes`, then `Target CyberArk Safe`, `Proposed_Safe_Name`, `Valid_Safe_Name`, `Safe_Name_Issues`, `Target Platform ID`, `Account Name`, `Address`, `Username` and `Secret Type` (password/key). Next are `Delinea Secret ID` and `Delinea Secret Field`, the field slug Phase 2 fetches. Last come the Delinea access groups and the original Delinea metadata columns, prefixed `Delinea.`. **No output file contains secret values.** Columns matching `secret_column_patterns` (password, passphrase, private key and so on) are never written.
- **Safes_Review.csv** has one row per target Safe, with its length, validity, the source names and the account count.
- **Safe_Members_Review.csv** has one row per Safe and group. It shows the strongest Delinea permission and the CyberArk role it maps to, which Phase 2 uses in step 2.

## Safe name handling
The script replaces invalid characters with `-` (set by `safe_name.replacement`), collapses repeated hyphens and whitespace, and truncates to 28 characters. `Valid_Safe_Name=FALSE` means the proposed name had to be changed. If two different source names end up with the same Safe name after this, the later one gets a numbered suffix (`-2`) that still fits in 28 characters, and it is flagged.

## Notes
- File attachment columns (`exclude_field_patterns`) are dropped. If one of them held a value, the row says so. SSH private keys are fetched by Phase 2 from the template's key field (`secret_field_slugs`, default `private-key`), even when Delinea stores the key as a file field.
- The review files hold no secret values, so they can be shared with reviewers. Saving them from Excel can still change values that begin with `=`, `+`, `-` or `@`, and can strip leading zeros. Edit them in a text editor, or import every column as Text.
- The `sample/` folder has an example export, permissions file and config, plus the output they produce.
