"""Configuration: defaults, loading and the starter-config writer."""

import copy
import json
from collections import OrderedDict

# Every permission flag the Privilege Cloud "Add Safe member" API accepts.
ALL_PERMISSIONS = [
    "useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
    "updateAccountContent", "updateAccountProperties",
    "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
    "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe",
    "manageSafeMembers", "backupSafe", "viewAuditLog", "viewSafeMembers",
    "accessWithoutConfirmation", "createFolders", "deleteFolders",
    "moveAccountsAndFolders", "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
]


def _perms(*granted):
    return [p for p in ALL_PERMISSIONS if p in granted]


DEFAULT_CONFIG = {
    "safe_name": {
        "max_length": 28,
        # Characters Privilege Cloud does not allow in Safe names.
        "invalid_chars": "\\/:*?\"<>|",
        "replacement": "-",
        # Optional prefix added to every derived Safe name, e.g. "MIG-".
        "prefix": "",
    },
    # RBAC flattening, checked in order; the first rule matching one of the
    # record's access groups picks its Safe. "group" is an exact, case-insensitive
    # match; "group_pattern" is a regex and {1}, {2}... in "safe" insert its
    # capture groups. "min_role" (Viewer|User|Editor|Owner) ignores weaker grants.
    "group_rules": [],
    # Folder (and subfolder) -> Safe overrides, used when no group rule matched.
    # Folder paths use "\" between levels, whatever the source used.
    "folder_rules": [],
    # When no group or folder rule matched:
    #   folder_leaf  -> last folder level        (\IT\Windows\Servers -> Servers)
    #   folder_path  -> all levels joined by "-" (\IT\Windows\Servers -> IT-Windows-Servers)
    #   unmapped     -> literal "UNMAPPED", which forces a decision
    #   convention   -> naming convention built from abbreviations (see safe_convention)
    #                   \Prod\Windows\Member Servers + WinServerLocal -> P-WIN-SVR-LA
    "fallback_strategy": "convention",
    # Naming convention (fallback_strategy "convention", or {convention} / {env} /
    # {folder_abbrev} / {tech} / {flavor} / {acct} in a rule's Safe name). Layers follow
    # the CyberArk convention: environment, location/BU/app (from the folders),
    # technology, flavor, account type. See pam2pc/naming.py for the built-in codes.
    "safe_convention": {
        "template": "{env}-{folder}-{tech}-{flavor}-{acct}",
        "separator": "-",
        "default_environment": "",
        # Extra or replacement word -> code entries, e.g. {"Boston": "BOS", "Payroll": "PAY"}.
        "abbreviations": {},
        # Folder levels to leave out entirely, e.g. ["Infrastructure", "Applications"].
        "skip_folder_levels": [],
        "environment_words": [],
        # Platform ID -> {"tech": ..., "flavor": ..., "acct": ...}; adds to/overrides the built-ins.
        "platform_codes": {},
    },
    # Recommended maximum accounts per Safe (CyberArk: 3,000-5,000; hard limit 20,000 objects).
    "safe_max_accounts": 3000,
    # Platform rules are checked first, in order. "field" is one of: type, folder,
    # name, address, username, or a source column name. "pattern" is a regex.
    "platform_rules": [],
    # Record type (Delinea template, a "Type" column...) -> Platform ID, case-insensitive.
    "platform_map": {
        "Active Directory Account": "WinDomain",
        "Windows Account": "WinServerLocal",
        "Unix Account (SSH)": "UnixSSH",
        "Unix Account (SSH Key Rotation)": "UnixSSHKeys",
        "SQL Server Account": "MSSql",
        "Oracle Account": "Oracle",
        "Web Password": "GenericWebApp",
        "Password": "GenericWebApp",
    },
    "default_platform": "",
    # Turn URL addresses into host names (https://fw01.example.com/login -> fw01.example.com).
    # The full URL stays in the review file's Source.* columns.
    "url_address_to_host": True,
    # Record types whose secret is an SSH key, not a password.
    "key_types": ["Unix Account (SSH Key Rotation)", "SSH Key", "Unix Account (SSH Key)"],
    # Source permission/access level -> Privilege Cloud role (case-insensitive).
    # Covers Delinea's Owner/Edit/View/List plus common spreadsheet wording.
    "permission_map": {
        "Owner": "Owner", "Full": "Owner", "Admin": "Owner", "Manage": "Owner",
        "Edit": "Editor", "Write": "Editor", "Modify": "Editor",
        "View": "User", "Use": "User", "Read": "User", "Connect": "User",
        "List": "Viewer",
    },
    # Role -> permission flags written to SafeMembers.csv.
    "role_permissions": {
        "Owner": _perms(*[p for p in ALL_PERMISSIONS if not p.startswith("requestsAuthorization")]),
        "Editor": _perms("useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
                         "updateAccountContent", "updateAccountProperties",
                         "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
                         "renameAccounts", "unlockAccounts", "viewAuditLog", "viewSafeMembers",
                         "accessWithoutConfirmation", "createFolders", "deleteFolders",
                         "moveAccountsAndFolders"),
        "User": _perms("useAccounts", "retrieveAccounts", "listAccounts", "viewAuditLog",
                       "accessWithoutConfirmation"),
        "Viewer": _perms("listAccounts"),
    },
    # "DOMAIN\Group" or "group@domain" -> memberName + searchIn. "*" is the default
    # directory. strip_domain_prefix drops "DOMAIN\" from memberName.
    "directory_map": {"*": "Vault"},
    "strip_domain_prefix": True,
    "default_member_type": "Group",
    # Body fields for every Safe in Safes.csv. Use either numberOfDaysRetention
    # or numberOfVersionsRetention, not both.
    "safe_defaults": {
        "description": "",
        "location": "",
        "managingCPM": "",
        "numberOfDaysRetention": 7,
        "numberOfVersionsRetention": "",
        "olacEnabled": False,
        "autoPurgeEnabled": False,
    },
    "account_defaults": {
        "automaticManagementEnabled": False,
        "manualManagementReason": "Migrated - CPM management pending review",
    },
    # Source column -> platformAccountProperties key, e.g. {"Notes": "Notes", "Port": "Port"}.
    # The key must exist on the target platform or the API rejects the account.
    "account_property_map": {},
    # File attachment columns are not migrated; columns matching these are dropped.
    "exclude_field_patterns": [r"\battach", r"\bfiles?\b", r"\.(ppk|pem|key|pfx|p12|crt|cer)$"],
    # Column names holding secret values. Never written to review files.
    "secret_column_patterns": [r"password", r"passphrase", r"private ?key", r"^secret$", r"^pin$",
                               r"^totp$", r"\botp\b"],
    # Column aliases tried in order (case-insensitive) by the Delinea and table adapters.
    "field_aliases": {
        "id": ["Secret ID", "SecretId", "ID", "Id", "UUID", "Record ID"],
        "name": ["Secret Name", "SecretName", "Account Name", "Title", "Name", "Entry"],
        "folder": ["Folder Path", "FolderPath", "Folder", "Group", "Path", "Location"],
        "type": ["Secret Template", "Template", "Template Name", "Type", "Account Type", "Platform"],
        "address": ["Address", "Machine", "Server", "Host", "Hostname", "Host Name", "Domain",
                    "URL", "Web Site", "Website", "IP Address", "IP", "Resource"],
        "username": ["Username", "User Name", "UserName", "Login", "Login Name", "User", "Account"],
        "password": ["Password", "Secret", "Passphrase", "Pass"],
        "private_key": ["Private Key", "PrivateKey", "SSH Private Key", "SSH Key"],
        "access": ["Access", "Permissions", "Access Groups"],
        "safe": ["Target Safe", "Safe", "Safe Name"],
        "platform": ["Platform ID", "PlatformId", "Target Platform"],
    },
    "sources": {
        "delinea": {
            # Header cells that identify a header row in the multi-header export.
            "header_markers": ["Secret Name", "SecretName"],
            # Delinea template field that holds the key passphrase.
            "passphrase_columns": ["Private Key Passphrase", "Passphrase"],
        },
        "keepass": {
            # Drop the database's root group from folder paths.
            "drop_root_group": True,
            # Group names skipped entirely (with everything under them).
            "skip_groups": ["Recycle Bin", "Backup"],
            # Record "type" for platform mapping: "group" uses the KeePass group
            # path, or set a fixed value such as "Password".
            "type_from": "fixed",
            "fixed_type": "Password",
        },
        "table": {
            # Optional explicit mapping: logical field -> column name. Anything
            # not listed falls back to field_aliases.
            "columns": {},
            # Separator for folder paths in the folder column ("\\" or "/").
            "folder_separator": "auto",
            # Excel only: sheet name (default: first sheet) and header row number.
            "sheet": "",
            "header_row": 1,
            # Group/permission columns for one-grant-per-row sheets.
            "group_column": "",
            "permission_column": "",
        },
    },
}

# Keys whose dict value replaces the default wholesale instead of merging.
NO_MERGE = {"platform_map", "permission_map", "role_permissions", "directory_map",
            "account_property_map"}


def _merge(base, user, path=""):
    for key, value in user.items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict) and isinstance(base.get(key), dict) and key not in NO_MERGE:
            _merge(base[key], value, path + key + ".")
        else:
            base[key] = value


def config_from_dict(user):
    """Defaults merged with a user config given as a dict."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    _merge(cfg, copy.deepcopy(user or {}))
    return cfg


def load_config(path=None):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        with open(path, encoding="utf-8-sig") as fh:
            user = json.load(fh)
        # Backward compatibility with the old phase 1 config keys.
        if "key_templates" in user and "key_types" not in user:
            user["key_types"] = user.pop("key_templates")
        if "header_markers" in user:
            user.setdefault("sources", {}).setdefault("delinea", {})["header_markers"] = \
                user.pop("header_markers")
        _merge(cfg, user)
    return cfg


def write_default_config(path):
    out = OrderedDict()
    out["_comment"] = ("pam2pc config. Only keep the keys you change; everything else uses the "
                       "built-in default. See README for each key.")
    out.update(copy.deepcopy(DEFAULT_CONFIG))
    out["group_rules"] = [
        {"group": "CORP\\Unix-Admins", "safe": "UNIX-Admins"},
        {"group_pattern": "^CORP\\\\APP-(.+)-Owners$", "safe": "APP-{1}", "min_role": "Owner"},
    ]
    out["folder_rules"] = [{"folder_prefix": "\\Infrastructure\\Network", "safe": "NET-Devices"}]
    out["platform_rules"] = [{"field": "folder", "pattern": "(?i)linux|unix", "platform": "UnixSSH"}]
    out["directory_map"] = {"CORP": "corp.example.com", "*": "Vault"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
