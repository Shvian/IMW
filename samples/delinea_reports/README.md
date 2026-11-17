# Delinea report samples (synthetic)

Made-up data in the layouts of real Delinea Secret Server exports and reports (header rows as
they come out of Secret Server, values invented). Used by dotnet/tests/Imw.Tests/DelineaReportsTests.cs.

| File | What it is | Used for |
|---|---|---|
| secrets-export.csv | Secrets export: Secret Name, Domain, Username, Password, Notes, Folder, TOTP Key, TOTP Backup Codes. No template column. | The accounts |
| allsecrets.csv | Report: value, Name, Secret template, Folder | Each secret's template, matched on its name (folder breaks a tie) |
| whatfolderpermissionsexistforgroups.csv | Report: Folder Path, Inherit Permissions, Group, Permissions, Color | Groups as Safe members |
| whatfolderscanalluserssee.csv | Report: Folder Path, Inherit Permissions, Permissions, User, Color (effective access, full names) | Users with direct access; the rest wait for a decision |
| lauserslist.csv | Users list: Username (the UPN), Display name, ... | Full name to UPN |
| lagroups.csv, secret-template-list.csv, whatroleassignmentsexist.csv, whatrolepermissionassignmentsexist.csv | Other reports | Recognised, not needed |
