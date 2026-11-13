"""Idira Migration Workbench (imw): offline converter from PAM exports to Privilege Cloud API-ready CSVs.

Reads exported data from any supported source (Delinea/Thycotic Secret Server,
KeePass, generic CSV/Excel, ...) through pluggable adapters, maps it onto one
common model, applies Safe/platform/permission rules and writes:

  review/   files a human checks (no secret values, shareable)
  upload/   Safes.csv, SafeMembers.csv, Accounts.csv whose columns match the
            Privilege Cloud REST API body fields (Accounts.csv carries secrets
            only when --include-secrets is given)

No network access of any kind. Python 3.8+, standard library only.
"""

__version__ = "2.0.0"
