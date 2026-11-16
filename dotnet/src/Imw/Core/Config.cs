using Imw.Core;

namespace Imw.Core;

/// <summary>Configuration: defaults, loading, upgrading old files and the starter-config writer.</summary>
public static class Config
{
    // Every permission flag the Privilege Cloud "Add Safe member" API accepts.
    public static readonly string[] AllPermissions =
    {
        "useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
        "updateAccountContent", "updateAccountProperties",
        "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
        "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe",
        "manageSafeMembers", "backupSafe", "viewAuditLog", "viewSafeMembers",
        "accessWithoutConfirmation", "createFolders", "deleteFolders",
        "moveAccountsAndFolders", "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
    };

    static List<string> Perms(params string[] granted) => AllPermissions.Where(granted.Contains).ToList();

    // Privilege Cloud's built-in Safe member permission presets (Add Safe member > Permissions).
    public static readonly OrderedDictionary<string, List<string>> PermissionPresets = new()
    {
        ["Connect only"] = Perms("listAccounts", "useAccounts"),
        ["Read only"] = Perms("listAccounts", "useAccounts", "retrieveAccounts"),
        ["Approver"] = Perms("listAccounts", "viewSafeMembers", "manageSafeMembers", "requestsAuthorizationLevel1"),
        ["Accounts manager"] = Perms(AllPermissions.Where(p => p is not ("manageSafe" or "backupSafe" or "requestsAuthorizationLevel2")).ToArray()),
        ["Full"] = Perms(AllPermissions.Where(p => p != "requestsAuthorizationLevel2").ToArray()),
    };

    public static JObj PresetsJson() => new(PermissionPresets.Select(kv => new KeyValuePair<string, object>(kv.Key, kv.Value.Cast<object>().ToList())));

    // The suggested standard member groups (Mapping rules B: "Use the suggested set").
    public static List<object> StandardMemberSet() => new()
    {
        Json.O(("name", "{safe}-Owners"), ("member_type", "Group"), ("role", "Full"), ("search_in", "")),
        Json.O(("name", "{safe}-Users"), ("member_type", "Group"), ("role", "Connect only"), ("search_in", "")),
        Json.O(("name", "{safe}-Approvers"), ("member_type", "Group"), ("role", "Approver"), ("search_in", "")),
    };

    // Role names used before the presets existed -> nearest preset.
    static readonly Dictionary<string, string> LegacyRoles = new()
    {
        ["owner"] = "Full", ["editor"] = "Accounts manager", ["user"] = "Read only", ["viewer"] = "List only",
    };

    internal static JObj V1PermissionMap() => Json.O(
        ("Owner", "Owner"), ("Full", "Owner"), ("Admin", "Owner"), ("Manage", "Owner"),
        ("Edit", "Editor"), ("Write", "Editor"), ("Modify", "Editor"),
        ("View", "User"), ("Use", "User"), ("Read", "User"), ("Connect", "User"), ("List", "Viewer"));

    internal static JObj V1RolePermissions() => Json.O(
        ("Owner", Perms(AllPermissions.Where(p => !p.StartsWith("requestsAuthorization")).ToArray()).Cast<object>().ToList()),
        ("Editor", Perms("useAccounts", "retrieveAccounts", "listAccounts", "addAccounts", "updateAccountContent",
            "updateAccountProperties", "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
            "renameAccounts", "unlockAccounts", "viewAuditLog", "viewSafeMembers", "accessWithoutConfirmation",
            "createFolders", "deleteFolders", "moveAccountsAndFolders").Cast<object>().ToList()),
        ("User", Perms("useAccounts", "retrieveAccounts", "listAccounts", "viewAuditLog", "accessWithoutConfirmation").Cast<object>().ToList()),
        ("Viewer", Perms("listAccounts").Cast<object>().ToList()));

    const string V1Template = "{env}-{folder}-{tech}-{flavor}-{acct}";
    public const int ConfigVersion = 4;

    // The built-in defaults, exactly as the Python version defines them (imw/config.py DEFAULT_CONFIG).
    const string DefaultJson = """
{
 "config_version": 4,
 "safe_name": {
  "max_length": 28,
  "invalid_chars": "\\/:*?\"<>|",
  "replacement": "-",
  "prefix": ""
 },
 "folder_rules": [],
 "group_rules": [],
 "group_rules_first": false,
 "fallback_strategy": "convention",
 "safe_convention": {
  "template": "{folder}",
  "template_no_folders": "{env}-{tech}-{flavor}-{acct}",
  "separator": "-",
  "default_environment": "",
  "abbreviations": {},
  "skip_folder_levels": [],
  "layers": {
   "env": {
    "label": "Environment",
    "default": "",
    "rules": [
     {
      "field": "folder_word",
      "pattern": "^(production|prod|prd)$",
      "code": "P"
     },
     {
      "field": "folder_word",
      "pattern": "^(development|dev)$",
      "code": "D"
     },
     {
      "field": "folder_word",
      "pattern": "^(test|testing|tst)$",
      "code": "T"
     },
     {
      "field": "folder_word",
      "pattern": "^(qa|uat|quality assurance)$",
      "code": "Q"
     },
     {
      "field": "folder_word",
      "pattern": "^(staging|stage)$",
      "code": "S"
     }
    ]
   },
   "tech": {
    "label": "Technology",
    "default": "",
    "rules": [
     {
      "field": "platform",
      "pattern": "^(WinDomain)$",
      "code": "DOM"
     },
     {
      "field": "platform",
      "pattern": "^(WinServerLocal|WinService|UnixSSH|UnixSSHKeys)$",
      "code": "SVR"
     },
     {
      "field": "platform",
      "pattern": "^(WinDesktopLocal)$",
      "code": "WKS"
     },
     {
      "field": "platform",
      "pattern": "^(MSSql|Oracle|MySQL|PostgreSQL)$",
      "code": "DB"
     },
     {
      "field": "platform",
      "pattern": "^(CiscoSSH|CiscoEnable|PaloAltoNetworks)$",
      "code": "NET"
     },
     {
      "field": "platform",
      "pattern": "^(VMwareESX)$",
      "code": "VRT"
     },
     {
      "field": "platform",
      "pattern": "^(GenericWebApp)$",
      "code": "WEB"
     },
     {
      "field": "platform",
      "pattern": "^(AzureWebAccount|AWSAccessKeys)$",
      "code": "CLD"
     }
    ]
   },
   "flavor": {
    "label": "Flavor",
    "default": "",
    "rules": [
     {
      "field": "platform",
      "pattern": "^(WinDomain|WinServerLocal|WinDesktopLocal|WinService)$",
      "code": "WIN"
     },
     {
      "field": "platform",
      "pattern": "^(UnixSSH|UnixSSHKeys)$",
      "code": "UNX"
     },
     {
      "field": "platform",
      "pattern": "^(MSSql)$",
      "code": "SQL"
     },
     {
      "field": "platform",
      "pattern": "^(Oracle)$",
      "code": "ORC"
     },
     {
      "field": "platform",
      "pattern": "^(MySQL)$",
      "code": "MYS"
     },
     {
      "field": "platform",
      "pattern": "^(PostgreSQL)$",
      "code": "PGS"
     },
     {
      "field": "platform",
      "pattern": "^(CiscoSSH|CiscoEnable)$",
      "code": "CSC"
     },
     {
      "field": "platform",
      "pattern": "^(PaloAltoNetworks)$",
      "code": "PAN"
     },
     {
      "field": "platform",
      "pattern": "^(VMwareESX)$",
      "code": "ESX"
     },
     {
      "field": "platform",
      "pattern": "^(AzureWebAccount)$",
      "code": "AZ"
     },
     {
      "field": "platform",
      "pattern": "^(AWSAccessKeys)$",
      "code": "AWS"
     }
    ]
   },
   "acct": {
    "label": "Account type",
    "default": "",
    "rules": [
     {
      "field": "username",
      "pattern": "^root$",
      "code": "RT",
      "field2": "flavor",
      "pattern2": "^(UNX|LNX|HP|AIX|SOL)$"
     },
     {
      "field": "username",
      "pattern": "^sa$",
      "code": "SA",
      "field2": "tech",
      "pattern2": "^DB$"
     },
     {
      "field": "username",
      "pattern": "^enable$",
      "code": "EN",
      "field2": "tech",
      "pattern2": "^NET$"
     },
     {
      "field": "username",
      "pattern": "^(svc|srv|service)[_.-]",
      "code": "DS",
      "field2": "tech",
      "pattern2": "^DOM$"
     },
     {
      "field": "username",
      "pattern": "^(svc|srv|service)[_.-]",
      "code": "LS"
     },
     {
      "field": "platform",
      "pattern": "^(WinDomain)$",
      "code": "DA"
     },
     {
      "field": "platform",
      "pattern": "^(WinServerLocal|WinDesktopLocal|UnixSSH|UnixSSHKeys|MSSql|Oracle|MySQL|PostgreSQL|CiscoSSH|PaloAltoNetworks|VMwareESX|GenericWebApp|AzureWebAccount|AWSAccessKeys)$",
      "code": "LA"
     },
     {
      "field": "platform",
      "pattern": "^(WinService)$",
      "code": "LS"
     },
     {
      "field": "platform",
      "pattern": "^(CiscoEnable)$",
      "code": "EN"
     }
    ]
   }
  },
  "environment_words": [],
  "platform_codes": {}
 },
 "safe_max_accounts": 3000,
 "safe_split_over_max": false,
 "standard_members": {
  "apply_to": "no_source_members",
  "members": []
 },
 "platform_rules": [],
 "platform_map": {
  "Active Directory Account": "WinDomain",
  "Windows Account": "WinServerLocal",
  "Unix Account (SSH)": "UnixSSH",
  "Unix Account (SSH Key Rotation)": "UnixSSHKeys",
  "SQL Server Account": "MSSql",
  "Oracle Account": "Oracle",
  "Web Password": "GenericWebApp",
  "Password": "GenericWebApp",
  "Windows Local Admin": "WinServerLocal",
  "Active Directory Domain Admin": "WinDomain",
  "Cisco Account (SSH)": "CiscoSSH",
  "Palo Alto": "PaloAltoNetworks",
  "Palo Alto Networks Firewall": "PaloAltoNetworks",
  "VMware ESXi": "VMwareESX",
  "VMware ESX/ESXi": "VMwareESX",
  "PostgreSQL": "PostgreSQL",
  "PostgreSQL Account": "PostgreSQL",
  "MySQL": "MySQL",
  "MySQL Account": "MySQL",
  "AWS IAM Key": "AWSAccessKeys",
  "Amazon IAM Key": "AWSAccessKeys",
  "Azure AD Account": "AzureWebAccount",
  "Kee Pass": "GenericWebApp"
 },
 "default_platform": "",
 "url_address_to_host": true,
 "key_types": [
  "Unix Account (SSH Key Rotation)",
  "SSH Key",
  "Unix Account (SSH Key)"
 ],
 "permission_map": {
  "Owner": "Full",
  "Full": "Full",
  "Admin": "Full",
  "Manage": "Full",
  "Edit": "Accounts manager",
  "Write": "Accounts manager",
  "Modify": "Accounts manager",
  "View": "Read only",
  "Read": "Read only",
  "Use": "Connect only",
  "Connect": "Connect only",
  "Approve": "Approver",
  "List": "List only"
 },
 "custom_roles": {
  "List only": [
   "listAccounts"
  ]
 },
 "directory_sources": [],
 "domain_map": [],
 "directory_map": {
  "*": ""
 },
 "strip_domain_prefix": true,
 "default_member_type": "Group",
 "safe_defaults": {
  "description": "",
  "location": "",
  "managingCPM": "",
  "numberOfDaysRetention": 7,
  "numberOfVersionsRetention": "",
  "olacEnabled": false,
  "autoPurgeEnabled": false
 },
 "safe_rules": [],
 "account_name": {
  "mode": "pattern",
  "template": "{name}",
  "fallback": "{address}-{username}"
 },
 "account_defaults": {
  "automaticManagementEnabled": false,
  "manualManagementReason": "Migrated - CPM management pending review"
 },
 "account_property_map": {},
 "exclude_field_patterns": [
  "\\battach",
  "\\bfiles?\\b",
  "\\.(ppk|pem|key|pfx|p12|crt|cer)$"
 ],
 "secret_column_patterns": [
  "password",
  "passphrase",
  "private ?key",
  "^secret$",
  "^pin$",
  "^totp$",
  "\\botp\\b"
 ],
 "field_aliases": {
  "id": [
   "Secret ID",
   "SecretId",
   "ID",
   "Id",
   "UUID",
   "Record ID"
  ],
  "name": [
   "Secret Name",
   "SecretName",
   "Account Name",
   "Title",
   "Name",
   "Entry"
  ],
  "folder": [
   "Folder Path",
   "FolderPath",
   "Folder",
   "Group",
   "Path",
   "Location"
  ],
  "type": [
   "Secret Template",
   "Template",
   "Template Name",
   "Type",
   "Account Type",
   "Platform"
  ],
  "address": [
   "Address",
   "Machine",
   "Server",
   "Host",
   "Hostname",
   "Host Name",
   "Domain",
   "URL",
   "Web Site",
   "Website",
   "IP Address",
   "IP",
   "Resource"
  ],
  "username": [
   "Username",
   "User Name",
   "UserName",
   "Login",
   "Login Name",
   "User",
   "Account"
  ],
  "password": [
   "Password",
   "Secret",
   "Passphrase",
   "Pass"
  ],
  "private_key": [
   "Private Key",
   "PrivateKey",
   "SSH Private Key",
   "SSH Key"
  ],
  "access": [
   "Access",
   "Permissions",
   "Access Groups"
  ],
  "safe": [
   "Target Safe",
   "Safe",
   "Safe Name"
  ],
  "platform": [
   "Platform ID",
   "PlatformId",
   "Target Platform"
  ]
 },
 "sources": {
  "delinea": {
   "header_markers": [
    "Secret Name",
    "SecretName"
   ],
   "passphrase_columns": [
    "Private Key Passphrase",
    "Passphrase"
   ]
  },
  "keepass": {
   "drop_root_group": true,
   "skip_groups": [
    "Recycle Bin",
    "Backup"
   ],
   "type_from": "fixed",
   "fixed_type": "Password"
  },
  "table": {
   "columns": {},
   "folder_separator": "auto",
   "sheet": "",
   "header_row": 1,
   "group_column": "",
   "permission_column": ""
  }
 }
}

""";

    static readonly JObj Default = Json.ParseObj(DefaultJson);

    /// <summary>A fresh copy of the built-in defaults.</summary>
    public static JObj DefaultConfig() => Json.DeepCopy(Default);

    /// <summary>The defaults themselves (do not change).</summary>
    public static JObj DefaultsShared => Default;

    // Keys whose dict value replaces the default wholesale instead of merging.
    public static readonly HashSet<string> NoMerge = new()
    {
        "platform_map", "permission_map", "role_permissions", "custom_roles", "directory_map",
        "account_property_map", "abbreviations", "layers",
    };

    /// <summary>Preset and custom role name -> permission flags (custom names cannot replace a preset).</summary>
    public static OrderedDictionary<string, List<string>> AllRoles(JObj cfg)
    {
        var roles = new OrderedDictionary<string, List<string>>();
        foreach (var kv in PermissionPresets) roles[kv.Key] = kv.Value.ToList();
        var custom = new JObj();
        if (cfg.Get("role_permissions") is JObj old) custom.Update(old);
        if (cfg.Get("custom_roles") is JObj cr) custom.Update(cr);
        foreach (var kv in custom)
        {
            if (roles.ContainsKey(kv.Key)) continue;
            var perms = (kv.Value as List<object> ?? new List<object>()).Select(x => x as string).ToHashSet();
            roles[kv.Key] = AllPermissions.Where(perms.Contains).ToList();
        }
        return roles;
    }

    /// <summary>Role name as written in permission_map / min_role -> a defined role name, or "".</summary>
    public static string ResolveRole(object name, JObj cfg)
    {
        if (!Py.Truthy(name)) return "";
        var roles = AllRoles(cfg);
        var want = Py.Lower(Py.Str(name));
        foreach (var r in roles.Keys)
            if (Py.Lower(r) == want) return r;
        var legacy = LegacyRoles.GetValueOrDefault(want);
        return legacy != null && roles.ContainsKey(legacy) ? legacy : "";
    }

    /// <summary>Bring a stored config from an older version up to date, one version step at a time.</summary>
    public static JObj UpgradeConfig(JObj user)
    {
        user = user?.Copy() ?? new JObj();
        var cv = user.Get("config_version");
        long version = Py.Truthy(cv) ? Py.ToLong(cv) ?? throw new ValueError($"invalid literal for int() with base 10: {Py.Repr(cv)}") : 1;
        if (version >= ConfigVersion) return user;
        if (version < 2)
        {
            // A version 1 file has no config_version. Only whole-config dumps carried the old defaults,
            // and those always had field_aliases; a hand-written version 1 config is kept as it is.
            if (!user.ContainsKey("config_version") && !user.ContainsKey("field_aliases")) return user;
            UpgradeV1ToV2(user);
        }
        if (version < 3) AddPlatformTypes(user, V3NewPlatformTypes, 3);
        if (version < 4) AddPlatformTypes(user, V4NewPlatformTypes, 4);
        user["config_version"] = (long)ConfigVersion;
        return user;
    }

    static void UpgradeV1ToV2(JObj user)
    {
        if (Py.Eq(user.Get("permission_map"), V1PermissionMap())) user.Pop("permission_map");
        var oldRoles = user.Pop("role_permissions") as JObj;
        if (oldRoles != null && oldRoles.Count > 0 && !Py.Eq(oldRoles, V1RolePermissions()))
        {
            var custom = (user.Get("custom_roles") as JObj)?.Copy() ?? new JObj();
            var v1 = V1RolePermissions();
            foreach (var kv in oldRoles)
                if (!Py.Eq(v1.Get(kv.Key), kv.Value)) custom.SetDefault(kv.Key, kv.Value);
            if (custom.Count > 0) user["custom_roles"] = custom;
        }
        if (user.Get("fallback_strategy") as string == "folder_leaf") user["fallback_strategy"] = "convention";
        if (user.Get("safe_convention") is JObj conv && conv.Get("template") as string == V1Template)
        {
            conv = conv.Copy();
            conv.Pop("template");
            user["safe_convention"] = conv;
        }
        user["config_version"] = 2L;
    }

    static readonly string[] V3NewPlatformTypes =
    {
        "Windows Local Admin", "Active Directory Domain Admin", "Cisco Account (SSH)", "Palo Alto",
        "Palo Alto Networks Firewall", "VMware ESXi", "VMware ESX/ESXi", "PostgreSQL", "PostgreSQL Account",
        "MySQL", "MySQL Account", "AWS IAM Key", "Amazon IAM Key", "Azure AD Account",
    };

    static readonly string[] V4NewPlatformTypes = { "Kee Pass" };

    static void AddPlatformTypes(JObj user, string[] types, int version)
    {
        if (user.Get("platform_map") is JObj pmap)
        {
            var have = pmap.Keys.Select(k => Py.Lower(k)).ToHashSet();
            pmap = pmap.Copy();
            foreach (var t in types)
                if (!have.Contains(Py.Lower(t))) pmap[t] = Default.Obj("platform_map")[t];
            user["platform_map"] = pmap;
        }
        user["config_version"] = (long)version;
    }

    /// <summary>Only the settings that differ from the defaults (what config.json should keep).</summary>
    public static JObj ConfigDiff(JObj cfg, JObj @base = null)
    {
        bool top = @base == null;
        @base ??= Default;
        var out_ = new JObj();
        foreach (var kv in cfg)
        {
            if (kv.Key.StartsWith('_')) continue;
            if (kv.Value is JObj v && @base.Get(kv.Key) is JObj b && !NoMerge.Contains(kv.Key))
            {
                var sub = ConfigDiff(v, b);
                if (sub.Count > 0) out_[kv.Key] = sub;
            }
            else if (!@base.ContainsKey(kv.Key) || !Py.Eq(@base[kv.Key], kv.Value)) out_[kv.Key] = kv.Value;
        }
        if (top) out_["config_version"] = Py.Truthy(cfg.Get("config_version")) ? cfg["config_version"] : (long)ConfigVersion;
        return out_;
    }

    static void Merge(JObj @base, JObj user)
    {
        foreach (var kv in user)
        {
            if (kv.Key.StartsWith('_')) continue;
            if (kv.Value is JObj v && @base.Get(kv.Key) is JObj b && !NoMerge.Contains(kv.Key)) Merge(b, v);
            else @base[kv.Key] = kv.Value;
        }
    }

    /// <summary>Defaults merged with a user config given as a dict.</summary>
    public static JObj FromDict(JObj user)
    {
        var cfg = DefaultConfig();
        Merge(cfg, UpgradeConfig(Json.DeepCopy(user ?? new JObj())));
        return cfg;
    }

    public static JObj Load(string path = null)
    {
        var cfg = DefaultConfig();
        if (!string.IsNullOrEmpty(path))
        {
            var parsed = Json.Parse(Csv.ReadText(path, "utf-8-sig"));
            if (parsed is not JObj user) throw new ValueError($"{path}: the settings file must hold a JSON object");
            // Backward compatibility with the old phase 1 config keys.
            if (user.ContainsKey("key_templates") && !user.ContainsKey("key_types")) user["key_types"] = user.Pop("key_templates");
            if (user.ContainsKey("header_markers"))
            {
                var markers = user.Pop("header_markers");
                var sources = user.SetDefault("sources", new JObj()) as JObj;
                var del = sources.SetDefault("delinea", new JObj()) as JObj;
                del["header_markers"] = markers;
            }
            Merge(cfg, UpgradeConfig(user));
        }
        return cfg;
    }

    public static void WriteDefault(string path)
    {
        var out_ = new JObj();
        out_["_comment"] = "Idira Migration Workbench config. Only keep the keys you change; everything else uses the " +
                           "built-in default. See README for each key.";
        out_.Update(DefaultConfig());
        out_["folder_rules"] = Json.L(Json.O(("folder_prefix", "\\Infrastructure\\Network"), ("safe", "NET-Devices")));
        out_["platform_rules"] = Json.L(Json.O(("field", "folder"), ("pattern", "(?i)linux|unix"), ("platform", "UnixSSH")));
        out_["directory_map"] = Json.O(("CORP", "corp.example.com"), ("*", ""));
        PyFile.WriteText(path, Json.Dumps(out_, 2));
    }
}
