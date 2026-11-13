"""Configuration: defaults, loading and the starter-config writer."""

import copy
import json
from collections import OrderedDict

from .naming import LAYER_FIELDS, default_layers

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


# Privilege Cloud's built-in Safe member permission presets (Add Safe member > Permissions).
# Fixed: to change one, make a custom role (custom_roles) starting from it.
PERMISSION_PRESETS = {
    "Connect only": _perms("listAccounts", "useAccounts"),
    "Read only": _perms("listAccounts", "useAccounts", "retrieveAccounts"),
    "Approver": _perms("listAccounts", "viewSafeMembers", "manageSafeMembers",
                       "requestsAuthorizationLevel1"),
    "Accounts manager": _perms(*[p for p in ALL_PERMISSIONS
                                 if p not in ("manageSafe", "backupSafe", "requestsAuthorizationLevel2")]),
    "Full": _perms(*[p for p in ALL_PERMISSIONS if p != "requestsAuthorizationLevel2"]),
}

# Role names used before the presets existed -> nearest preset.
LEGACY_ROLES = {"owner": "Full", "editor": "Accounts manager", "user": "Read only", "viewer": "List only"}

# Defaults of config version 1; a stored config still equal to these is upgraded.
_V1_PERMISSION_MAP = {
    "Owner": "Owner", "Full": "Owner", "Admin": "Owner", "Manage": "Owner",
    "Edit": "Editor", "Write": "Editor", "Modify": "Editor",
    "View": "User", "Use": "User", "Read": "User", "Connect": "User",
    "List": "Viewer",
}
_V1_ROLE_PERMISSIONS = {
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
}
_V1_TEMPLATE = "{env}-{folder}-{tech}-{flavor}-{acct}"
CONFIG_VERSION = 2


DEFAULT_CONFIG = {
    "config_version": CONFIG_VERSION,
    "safe_name": {
        "max_length": 28,
        # Characters Privilege Cloud does not allow in Safe names.
        "invalid_chars": "\\/:*?\"<>|",
        "replacement": "-",
        # Optional prefix added to every derived Safe name, e.g. "MIG-".
        "prefix": "",
    },
    # Safes are object oriented by default: each account's Safe comes from its folder.
    # Folder (and subfolder) -> Safe rules; the most specific folder wins.
    # Folder paths use "\" between levels, whatever the source used.
    "folder_rules": [],
    # Optional, role oriented: access group -> Safe, checked in order; the first rule
    # matching one of the record's access groups picks its Safe. Used for records no
    # folder rule matched (or before folder rules with group_rules_first). "group" is an
    # exact, case-insensitive match; "group_pattern" is a regex and {1}, {2}... in "safe"
    # insert its capture groups. "min_role" ignores grants weaker than that role.
    "group_rules": [],
    "group_rules_first": False,
    # When no rule matched, the Safe is named from the record's folders:
    #   convention   -> folder levels as abbreviations (\Applications\Storefront\Prod -> APP-SF-P),
    #                   see safe_convention
    #   folder_leaf  -> last folder level        (\IT\Windows\Servers -> Servers)
    #   folder_path  -> all levels joined by "-" (\IT\Windows\Servers -> IT-Windows-Servers)
    #   unmapped     -> literal "UNMAPPED", which forces a decision
    "fallback_strategy": "convention",
    # Naming convention (fallback_strategy "convention", or {convention} / {env} /
    # {folder_abbrev} / {tech} / {flavor} / {acct} in a rule's Safe name). Layers follow
    # the CyberArk convention: environment, location/BU/app (from the folders),
    # technology, flavor, account type. See pam2pc/naming.py for the built-in codes.
    "safe_convention": {
        # Records with folders: the folder structure, each level abbreviated, in order.
        # Environment words (Prod, Dev...) stay where they are unless the template has {env}.
        "template": "{folder}",
        # Records with no folders (flat KeePass, spreadsheets): the CyberArk layers.
        "template_no_folders": "{env}-{tech}-{flavor}-{acct}",
        "separator": "-",
        "default_environment": "",
        # Folder name or word -> code, e.g. {"Storefront": "SF", "Boston": "BOS"}. Whole folder
        # names are matched first. The workbench suggests one per folder name it finds.
        "abbreviations": {},
        # Folder levels to leave out entirely, e.g. ["Infrastructure", "Applications"].
        "skip_folder_levels": [],
        # Placeholder layers: {env}, {tech}, {flavor}, {acct} and any you add (e.g. {region}).
        # Each layer: {"label", "default", "rules": [{"field", "pattern", "code",
        # optional "field2", "pattern2"}]}; the first rule that matches gives the code.
        # Fields: folder_word, folder_level, folder, platform, username, address, name, type,
        # source, env/tech/flavor/acct (an earlier layer's code) or column:<source column>.
        "layers": default_layers(),
        # Older settings, still read: extra environment words and platform codes.
        "environment_words": [],
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
    # Source permission/access level -> Privilege Cloud role (case-insensitive). A role
    # is one of the built-in presets (PERMISSION_PRESETS) or a custom role below.
    "permission_map": {
        "Owner": "Full", "Full": "Full", "Admin": "Full", "Manage": "Full",
        "Edit": "Accounts manager", "Write": "Accounts manager", "Modify": "Accounts manager",
        "View": "Read only", "Read": "Read only", "Use": "Connect only", "Connect": "Connect only",
        "Approve": "Approver", "List": "List only",
    },
    # Your own named roles: name -> permission flags written to SafeMembers.csv.
    "custom_roles": {
        "List only": _perms("listAccounts"),
    },
    # Directory sources for Safe members, checked in order; the first that matches a member
    # gives its searchIn directory and how its name is converted. Each source:
    #   name, members ("both" | "groups" | "users"),
    #   match: "*" (anything), a domain ("CORP", "corp.example.com") or "re:<regex>",
    #   search_in: the directory name in Privilege Cloud ("Vault" for vault users/groups),
    #   strip_domain (drop "CORP\" / "@corp..."), find + replace (regex), add_prefix,
    #   add_suffix, case ("keep" | "lower" | "upper").
    "directory_sources": [],
    # Older, simpler form used when no directory source matches: domain -> searchIn.
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
    # Safe settings by Safe name (regex), checked in order; the first match overrides
    # safe_defaults. Keys: safe_pattern, managingCPM, description, numberOfVersionsRetention,
    # numberOfDaysRetention. Descriptions may use {folder} (the Safe's first source folder).
    "safe_rules": [],
    # Account names: template first, fallback when the template comes out empty.
    # Placeholders: {name} {address} {username} {platform} {safe} {folder_leaf}.
    "account_name": {"template": "{name}", "fallback": "{address}-{username}"},
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
NO_MERGE = {"platform_map", "permission_map", "role_permissions", "custom_roles", "directory_map",
            "account_property_map", "abbreviations", "layers"}


def all_roles(cfg):
    """Preset and custom role name -> permission flags (custom names cannot replace a preset)."""
    roles = {k: list(v) for k, v in PERMISSION_PRESETS.items()}
    custom = dict(cfg.get("role_permissions") or {})     # the old key, still read
    custom.update(cfg.get("custom_roles") or {})
    for name, perms in custom.items():
        if name not in roles:
            roles[name] = [p for p in ALL_PERMISSIONS if p in perms]
    return roles


def resolve_role(name, cfg):
    """Role name as written in permission_map / min_role -> a defined role name, or ''."""
    roles = all_roles(cfg)
    if not name:
        return ""
    for r in roles:
        if r.lower() == str(name).lower():
            return r
    legacy = LEGACY_ROLES.get(str(name).lower())
    return legacy if legacy in roles else ""


def upgrade_config(user):
    """Bring a stored config from an older version up to date. Settings that still equal
    the old built-in defaults move to the new defaults; anything the user changed stays."""
    user = dict(user or {})
    if int(user.get("config_version") or 1) >= CONFIG_VERSION:
        return user
    # Only whole-config dumps (workbench saves, init-config) carried the old defaults;
    # a hand-written config lists just what its author chose, so keep it as it is.
    if "field_aliases" not in user:
        return user
    if user.get("permission_map") == _V1_PERMISSION_MAP:
        user.pop("permission_map")
    old_roles = user.pop("role_permissions", None)
    if old_roles and old_roles != _V1_ROLE_PERMISSIONS:
        custom = dict(user.get("custom_roles") or {})
        for name, perms in old_roles.items():
            if _V1_ROLE_PERMISSIONS.get(name) != perms:
                custom.setdefault(name, perms)
        if custom:
            user["custom_roles"] = custom
    if user.get("fallback_strategy") == "folder_leaf":   # the version 1 default
        user["fallback_strategy"] = "convention"
    conv = user.get("safe_convention")
    if isinstance(conv, dict) and conv.get("template") == _V1_TEMPLATE:
        conv = dict(conv)
        conv.pop("template")
        user["safe_convention"] = conv
    user["config_version"] = CONFIG_VERSION
    return user


def config_diff(cfg, base=None):
    """Only the settings that differ from the defaults (what config.json should keep)."""
    base = DEFAULT_CONFIG if base is None else base
    out = {}
    for key, value in cfg.items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict) and isinstance(base.get(key), dict) and key not in NO_MERGE:
            sub = config_diff(value, base[key])
            if sub:
                out[key] = sub
        elif key not in base or base[key] != value:
            out[key] = value
    return out


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
    _merge(cfg, upgrade_config(copy.deepcopy(user or {})))
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
        _merge(cfg, upgrade_config(user))
    return cfg


def write_default_config(path):
    out = OrderedDict()
    out["_comment"] = ("pam2pc config. Only keep the keys you change; everything else uses the "
                       "built-in default. See README for each key.")
    out.update(copy.deepcopy(DEFAULT_CONFIG))
    out["folder_rules"] = [{"folder_prefix": "\\Infrastructure\\Network", "safe": "NET-Devices"}]
    out["platform_rules"] = [{"field": "folder", "pattern": "(?i)linux|unix", "platform": "UnixSSH"}]
    out["directory_map"] = {"CORP": "corp.example.com", "*": "Vault"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
