Privilege Cloud (ISPSS) bulk-upload CSV layouts, with made-up data.

These follow the column names, order and value formats of real Privilege Cloud sample
files (True/False booleans, MemberType User/Group/Role, Location "\" for the Vault root).
The Workbench writes upload/Safes.csv, upload/SafeMembers.csv and upload/Accounts.csv
with exactly these headers; tests check that the headers stay identical.
