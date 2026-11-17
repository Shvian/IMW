IDIRA MIGRATION WORKBENCH SAMPLE DATA PACK - every name, host and password here is FAKE.

Copy this folder somewhere outside the repository (for example C:\IMW\sample_workspace),
then start the Workbench on the copy:
    IMW.exe ui --workspace "C:\IMW\sample_workspace"

inbox/
  delinea_export.csv       400 Delinea secrets in 8 templates, multi-header format, fake passwords and SSH keys
  delinea_permissions.csv  tick this one as the "permissions file" when loading the Delinea export
  delinea_export.xml       80 Delinea secrets as a Secret Server XML export (UTF-16), with its own folder
                           and secret permissions: no permissions file needed
  keepass_export.xml       60 KeePass entries in nested groups (plus a Recycle Bin entry and history that are skipped)
  it_inventory.xlsx        120 rows from a spreadsheet: one account per row, an Access column, some Target Safe values
config.json                starter mapping rules (open "Mapping rules" to see and change them)

Problems planted on purpose, so the review lists have something to show:
  - Safe names over 28 characters, two that collide after shortening (SQL ... Replicas EU West/East)
  - Invalid Safe-name characters (Batch: Nightly/Weekly Jobs, HR Portal "Self-Service")
  - A record type with no platform yet: "Mainframe Login" -> Errors list
  - Missing usernames (Errors) and missing addresses
  - Empty secrets, SSH keys with passphrases, attachments that are not migrated
  - Duplicate secret names, folders with no permissions (\Unfiled), mixed permissions
  - Safe members from three domains (CORP, EMEA, APAC): groups, and named users (Member Type User)
  - Spreadsheet rows with no Access value, and rows that name their Safe directly

Things to try:
  1. Load delinea_export.csv, keepass_export.xml and it_inventory.xlsx (tick delinea_permissions.csv as the
     permissions file). delinea_export.xml is a separate set of Delinea secrets: load it too, or on its own
     in a fresh workspace, to try the XML import with its built-in folder permissions.
  2. Mapping rules: give "Mainframe Login" a platform (pick one from the Platform ID list), Save.
  3. Review & change: open "Errors", "Safe name was changed", "No access groups"; move or exclude some accounts.
  4. Create upload files: first a dry run, then one wave (e.g. one Safe) upload-ready.
