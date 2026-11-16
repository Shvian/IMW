using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_settings.py, tests/test_roles.py and tests/test_member_names.py

static class SettingsHelpers
{
    public static SourceRecord Rec(string folder, string username = "admin", string address = "h1.corp.example.com",
                                   (string, string)[] grants = null, Dictionary<string, string> extra = null, string name = "")
    {
        var r = new SourceRecord("t", "f", folder + username, "")
        {
            Name = name, Folder = SourceRecord.SplitFolder(folder), Username = username, Type = "Windows Account",
            Address = address, Secret = "x",
        };
        foreach (var kv in extra ?? new()) r.Extra[kv.Key] = kv.Value;
        r.Grants = (grants ?? Array.Empty<(string, string)>()).Select(g => new Grant(g.Item1, g.Item2)).ToList();
        return r;
    }

    public static (string, string, string) Target(string name, JObj cfg, string type = "")
    {
        var (n, s, src) = Transform.MemberTarget(name, cfg, type);
        return (n, s, src);
    }
}

public class DirectorySources
{
    static (string, string, string) MT(string n, JObj c, string t = "") => SettingsHelpers.Target(n, c, t);

    [Fact]
    public void SourcesInOrderWithNameRules()
    {
        var cfg = TestBase.Cfg(@"{""directory_sources"": [
            {""name"": ""AD groups"", ""members"": ""groups"", ""match"": ""CORP"", ""search_in"": ""corp.example.com"",
             ""strip_domain"": true, ""find"": ""^GRP-"", ""replace"": ""PAM-"", ""case"": ""upper""},
            {""name"": ""AD users"", ""members"": ""users"", ""match"": ""corp.example.com"", ""search_in"": ""corp.example.com"",
             ""add_suffix"": ""@corp.example.com"", ""strip_domain"": true},
            {""name"": ""Apps"", ""match"": ""re:^APP_"", ""search_in"": ""Vault"", ""strip_domain"": false}]}");
        Assert.Equal(("PAM-DBA", "corp.example.com", "AD groups"), MT("CORP\\grp-dba", cfg, "Group"));
        Assert.Equal(("jdoe@corp.example.com", "corp.example.com", "AD users"), MT("jdoe@corp.example.com", cfg, "User"));
        Assert.Equal(("APP_payments", "Vault", "Apps"), MT("APP_payments", cfg, "Group"));
        // Falls back to directory_map, whose default searchIn is empty: Privilege Cloud searches every directory.
        Assert.Equal(("x", "", ""), MT("OTHER\\x", cfg, "Group"));
    }

    [Fact]
    public void SearchInOptionalAndRolesUseGroupSources()
    {
        var cfg = TestBase.Cfg(@"{""directory_sources"": [
            {""name"": ""Groups"", ""members"": ""groups"", ""match"": ""*"", ""strip_domain"": true},
            {""name"": ""Users"", ""members"": ""users"", ""match"": ""*"", ""search_in"": ""abc-guid""}]}");
        Assert.Equal(("PAM-Admins", "", "Groups"), MT("CORP\\PAM-Admins", cfg, "Role"));
        Assert.Equal(("jdoe", "abc-guid", "Users"), MT("jdoe", cfg, "User"));
    }

    [Fact]
    public void MemberTypes()
    {
        Assert.Equal(new[] { "User", "Group", "Role", "Group", "Group" },
                     new[] { "user", "GROUPS", "Role", "", "weird" }.Select(v => Transform.NormalizeMemberType(v)));
        Assert.Equal("User", Transform.NormalizeMemberType("", "User"));
        var cfg = TestBase.Cfg(@"{""default_member_type"": ""Role""}");
        var plan = Transform.BuildPlan(new[] { SettingsHelpers.Rec("\\Apps", grants: new[] { ("PAM-Ops", "View") }) }, cfg);
        var m = plan.Members.Values.First();
        Assert.Equal(("Role", ""), (m.MemberType, m.SearchIn));
    }

    [Fact]
    public void MemberChangedEverywhereAndRolePerSafe()
    {
        var r1 = SettingsHelpers.Rec("\\Apps", grants: new[] { ("CORP\\DBA", "View") });
        var r2 = SettingsHelpers.Rec("\\Data", username: "sa", grants: new[] { ("CORP\\DBA", "View") });
        var plan = Transform.BuildPlan(new[] { r1, r2 }, Config.Load(),
            memberOverrides: new Dictionary<string, JObj> { ["corp\\dba"] = TestBase.J(@"{""member_name"": ""PAM-DBA"", ""member_type"": ""Role"", ""search_in"": null}") },
            memberEdits: new List<JObj> { TestBase.J(@"{""safe_name"": ""APPS"", ""member_name"": ""CORP\\DBA"", ""action"": ""add"", ""role"": ""Full"", ""member_type"": """", ""search_in"": """"}") });
        var ms = plan.Members.ToDictionary(kv => kv.Key.Safe, kv => (kv.Value.MemberName, kv.Value.MemberType, kv.Value.Role));
        Assert.Equal(new Dictionary<string, (string, string, string)>
        {
            ["APPS"] = ("PAM-DBA", "Role", "Full"), ["DATA"] = ("PAM-DBA", "Role", "Read only"),
        }, ms);
    }

    [Fact]
    public void OldDirectoryMapStillWorks()
    {
        var cfg = TestBase.Cfg(@"{""directory_map"": {""CORP"": ""corp.example.com"", ""*"": ""Vault""}}");
        var (n, s, _) = MT("CORP\\DBA", cfg);
        Assert.Equal(("DBA", "corp.example.com"), (n, s));
    }
}

public class Layers
{
    [Fact]
    public void BuiltInValuesAreEditable()
    {
        var layers = Naming.DefaultLayers();
        layers.Obj("env").List("rules").Insert(0, TestBase.J(@"{""field"": ""folder_word"", ""pattern"": ""^live$"", ""code"": ""PRD""}"));
        layers.Obj("tech")["rules"] = new List<object> { TestBase.J(@"{""field"": ""platform"", ""pattern"": ""^WinServerLocal$"", ""code"": ""SRV""}") };
        var user = TestBase.J(@"{""safe_convention"": {""template"": ""{env}-{folder}-{tech}""}}");
        user.Obj("safe_convention")["layers"] = layers;
        Assert.Equal("PRD-PAY-SRV", new Namer(Config.FromDict(user)).Build(SettingsHelpers.Rec("\\Live\\Payments"), "WinServerLocal").Name);
    }

    [Fact]
    public void CustomPlaceholderFromAColumnWithDefault()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {""template"": ""{site}-{folder}"", ""layers"": {
            ""site"": {""default"": ""GL"", ""rules"": [{""field"": ""column:Site"", ""pattern"": ""^bos"", ""code"": ""BOS""},
                                                {""field"": ""address"", ""pattern"": ""\\.eu\\."", ""code"": ""EU"",
                                                 ""field2"": ""tech"", ""pattern2"": ""^SVR$""}]}}}}");
        var n = new Namer(cfg);
        Assert.Equal("BOS-APPS", n.Build(SettingsHelpers.Rec("\\Apps", extra: new() { ["Site"] = "Boston" }), "WinServerLocal").Name);
        Assert.Equal("EU-APPS", n.Build(SettingsHelpers.Rec("\\Apps", address: "x.eu.example.com"), "WinServerLocal").Name);
        Assert.Equal("GL-APPS", n.Build(SettingsHelpers.Rec("\\Apps", address: "x.eu.example.com"), "MSSql").Name);
    }
}

public class SafeSettingsTests
{
    [Fact]
    public void DefaultsAndRules()
    {
        var cfg = TestBase.Cfg(@"{""safe_defaults"": {""managingCPM"": ""CPM1"", ""description"": ""From {folder}"", ""numberOfDaysRetention"": 7},
                                ""safe_rules"": [{""safe_pattern"": ""^DB-"", ""managingCPM"": ""CPM_DB"", ""numberOfVersionsRetention"": 10}]}");
        var info = new SafeInfo();
        info.Folders.Add("\\Databases\\SQL");
        var body = Transform.SafeSettings("DB-SQL", info, cfg);
        Assert.Equal("CPM_DB", body["managingCPM"]);
        Assert.Equal(10L, body["numberOfVersionsRetention"]);
        Assert.Equal("", body["numberOfDaysRetention"]);
        Assert.Equal("From \\Databases\\SQL", body["description"]);
        Assert.Equal("CPM1", Transform.SafeSettings("APP", new SafeInfo(), cfg)["managingCPM"]);
    }

    [Fact]
    public void AccountNameTemplate()
    {
        var cfg = TestBase.Cfg(@"{""account_name"": {""template"": ""{username}@{address}""}}");
        Assert.Equal("svc_x@app1", Transform.BuildPlan(new[] { SettingsHelpers.Rec("\\Apps", "svc_x", "app1") }, cfg).Accounts[0].AccountName);
        Assert.Equal("app1-svc_x", Transform.BuildPlan(new[] { SettingsHelpers.Rec("\\Apps", "svc_x", "app1", name: "") }, Config.Load()).Accounts[0].AccountName);
    }

    [Fact]
    public void AccountNameLeftToPrivilegeCloud()
    {
        var cfg = TestBase.Cfg(@"{""account_name"": {""mode"": ""none""}}");
        var a = SettingsHelpers.Rec("\\Apps", "svc_x", "app1", name: "Same");
        var b = SettingsHelpers.Rec("\\Apps", "svc_y", "app1", name: "Same");
        b.SourceId = "other";
        var plan = Transform.BuildPlan(new[] { a, b }, cfg);
        Assert.Equal(new[] { "", "" }, plan.Accounts.Select(p => p.AccountName));   // no _2 suffix on blanks
        Assert.DoesNotContain(plan.Accounts.SelectMany(p => p.Warnings), w => w.Contains("duplicate"));
        // One account left unnamed by an edit while the others keep their built names.
        plan = Transform.BuildPlan(new[] { a, b }, Config.Load(),
            overrides: new() { [b.RecordId] = new Dictionary<string, string> { ["Account_Name"] = "(none)" } }, @explicit: true);
        Assert.Equal(new[] { "Same", "" }, plan.Accounts.Select(p => p.AccountName));
    }
}

public class MergedPermissions : TestBase
{
    [Fact]
    public void TwoFilesMerge()
    {
        string a = T("a.csv"), b = T("b.csv");
        WriteText(a, "Folder Path,Group,Permission\n\\Apps,CORP\\A,Owner\n\\Apps,CORP\\B,View\n");
        WriteText(b, "Folder Path,Group,Permission\n\\Apps,CORP\\B,View\n\\Apps,CORP\\C,List\n");
        var (grants, how) = new Permissions(new[] { a, b }).Resolve(SettingsHelpers.Rec("\\Apps\\Web"));
        Assert.Equal(new[] { "CORP\\A", "CORP\\B", "CORP\\C" }, grants.Select(g => g.Member));
        Assert.Equal("folder", how);
    }
}

public class Roles
{
    static SourceRecord Rec(string folder, params (string, string)[] grants)
    {
        var r = new SourceRecord("t", "f", folder, "")
        {
            Folder = SourceRecord.SplitFolder(folder), Username = "admin", Type = "Windows Account", Address = "h", Secret = "x",
        };
        r.Grants = grants.Select(g => new Grant(g.Item1, g.Item2)).ToList();
        return r;
    }

    [Fact]
    public void Presets()
    {
        Assert.Equal(new[] { "Connect only", "Read only", "Approver", "Accounts manager", "Full" }, Config.PermissionPresets.Keys);
        Assert.Equal(new HashSet<string> { "listAccounts", "useAccounts" }, Config.PermissionPresets["Connect only"].ToHashSet());
        Assert.DoesNotContain("requestsAuthorizationLevel2", Config.PermissionPresets["Full"]);
        Assert.Equal(Config.AllPermissions.Length - 1, Config.PermissionPresets["Full"].Count);
    }

    [Fact]
    public void DefaultPermissionMapUsesPresets()
    {
        var plan = Transform.BuildPlan(new[] { Rec("\\App", ("CORP\\A", "Owner"), ("CORP\\B", "Edit"), ("CORP\\C", "View"), ("CORP\\D", "List")) }, Config.Load());
        var roles = plan.Members.Values.ToDictionary(m => m.SourceName, m => m.Role);
        Assert.Equal(new Dictionary<string, string>
        {
            ["CORP\\A"] = "Full", ["CORP\\B"] = "Accounts manager", ["CORP\\C"] = "Read only", ["CORP\\D"] = "List only",
        }, roles);
        Assert.All(plan.Members.Values, m => Assert.Empty(m.Notes));
    }

    [Fact]
    public void CustomRoleAndStrongestWins()
    {
        var cfg = TestBase.Cfg(@"{""custom_roles"": {""Break glass"": [""listAccounts"", ""useAccounts"", ""retrieveAccounts"", ""viewAuditLog""]},
                                ""permission_map"": {""BG"": ""Break glass"", ""View"": ""Read only""}}");
        Assert.True(Config.AllRoles(cfg).ContainsKey("Break glass"));
        var c2 = cfg.Copy();
        c2["fallback_strategy"] = "folder_leaf";
        c2["folder_rules"] = new List<object> { TestBase.J(@"{""folder_prefix"": ""\\App"", ""safe"": ""S""}") };
        var plan = Transform.BuildPlan(new[] { Rec("\\App", ("CORP\\A", "View")), Rec("\\App\\Sub", ("CORP\\A", "BG")) }, Config.FromDict(c2));
        Assert.Equal(new[] { "Break glass" }, plan.Members.Values.Select(m => m.Role));
    }

    [Fact]
    public void LegacyRoleNamesStillResolve()
    {
        var cfg = Config.Load();
        Assert.Equal("Full", Config.ResolveRole("Owner", cfg));
        Assert.Equal("List only", Config.ResolveRole("viewer", cfg));
        Assert.Equal("", Config.ResolveRole("Nope", cfg));
    }
}

public class Upgrade
{
    [Fact]
    public void OldDefaultsMoveToNewDefaults()
    {
        var old = TestBase.J(@"{""field_aliases"": {}, ""fallback_strategy"": ""folder_leaf"",
            ""safe_convention"": {""template"": ""{env}-{folder}-{tech}-{flavor}-{acct}"", ""abbreviations"": {""X"": ""Y""}}}");
        old["permission_map"] = Config.V1PermissionMap();
        old["role_permissions"] = Config.V1RolePermissions();
        var cfg = Config.FromDict(old);
        Assert.Equal("Full", cfg.Obj("permission_map")["Owner"]);
        Assert.Equal("convention", cfg["fallback_strategy"]);
        Assert.Equal("{folder}", cfg.Obj("safe_convention")["template"]);
        Assert.True(Py.Eq(TestBase.J(@"{""X"": ""Y""}"), cfg.Obj("safe_convention")["abbreviations"]));
        Assert.False(cfg.ContainsKey("role_permissions"));
    }

    [Fact]
    public void ChangedRolesBecomeCustomRoles()
    {
        var roles = Config.V1RolePermissions();
        roles["Auditor"] = new List<object> { "listAccounts", "viewAuditLog" };
        var user = TestBase.J(@"{""field_aliases"": {}, ""permission_map"": {""Audit"": ""Auditor""}}");
        user["role_permissions"] = roles;
        var cfg = Config.FromDict(user);
        Assert.Equal(new object[] { "listAccounts", "viewAuditLog" }, cfg.Obj("custom_roles").List("Auditor"));
        Assert.Equal("Auditor", Config.ResolveRole("Auditor", cfg));
    }

    [Fact]
    public void NewAndHandWrittenConfigsAreLeftAlone()
    {
        foreach (var user in new[] { @"{""config_version"": 2, ""field_aliases"": {}, ""fallback_strategy"": ""folder_leaf""}",
                                     @"{""fallback_strategy"": ""folder_leaf""}" })
            Assert.Equal("folder_leaf", TestBase.Cfg(user)["fallback_strategy"]);
    }

    [Fact]
    public void HandWrittenOldRoleNamesStillWork()
    {
        var cfg = TestBase.Cfg(@"{""role_permissions"": {""Auditor"": [""listAccounts""]}, ""permission_map"": {""A"": ""Auditor""}}");
        Assert.Equal("Auditor", Config.ResolveRole("Auditor", cfg));
    }

    [Fact]
    public void DiffKeepsOnlyChanges()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {""default_environment"": ""P""}, ""default_platform"": ""X""}");
        var want = TestBase.J(@"{""safe_convention"": {""default_environment"": ""P""}, ""default_platform"": ""X""}");
        want["config_version"] = (long)Config.ConfigVersion;
        Assert.True(Py.Eq(want, Config.ConfigDiff(cfg)), Json.Dumps(Config.ConfigDiff(cfg)));
    }
}

public class DomainConversion
{
    static JObj C(string rows, string extra = "")
    {
        var u = TestBase.J("{" + (extra.Length > 0 ? extra + ", " : "") + @"""domain_map"": " + rows + "}");
        return Config.FromDict(u);
    }
    static string N(string name, JObj cfg, string type) => Transform.MemberTarget(name, cfg, type).Name;

    [Fact]
    public void ManyToOneDropAndUpn()
    {
        var cfg = C(@"[{""from"": ""CORP, EMEA"", ""to"": ""corp.example.com""}, {""from"": ""APAC"", ""to"": """"},
                       {""from"": ""*"", ""to"": ""@groups.example.com"", ""members"": ""groups""},
                       {""from"": ""LAB"", ""to"": ""lab.example.com"", ""members"": ""users+groups""}]");
        Assert.Equal("jdoe@corp.example.com", N("CORP\\jdoe", cfg, "User"));
        Assert.Equal("kmuller@corp.example.com", N("EMEA\\kmuller", cfg, "User"));
        Assert.Equal("jx@corp.example.com", N("jx@emea.corp.example.com", cfg, "User"));
        Assert.Equal(("wtan", "", "domain conversion APAC"), SettingsHelpers.Target("APAC\\wtan", cfg, "User"));
        Assert.Equal("Admins@groups.example.com", N("CORP\\Admins", cfg, "Group"));
        Assert.Equal("bob", N("OTHER\\bob", cfg, "User"));                                 // the default
        Assert.Equal("ann@lab.example.com", N("LAB\\ann", cfg, "User"));
        Assert.Equal("Ops@groups.example.com", N("LAB\\Ops", cfg, "Group"));                // * row first
        var lab = C(@"[{""from"": ""LAB"", ""to"": ""lab.example.com"", ""members"": ""users+groups""}]");
        Assert.Equal("Ops@lab.example.com", N("LAB\\Ops", lab, "Group"));
        Assert.Equal("Auditor", N("LAB\\Auditor", lab, "Role"));                             // roles not ticked
        Assert.Equal("Admins", N("CORP\\Admins", C(@"[{""from"": ""CORP"", ""to"": ""x.com""}]"), "Group"));   // users only by default
    }

    [Fact]
    public void DirectorySourceWorksOnTheConvertedName()
    {
        var cfg = C(@"[{""from"": ""CORP"", ""to"": ""corp.example.com""}]",
                    @"""directory_sources"": [{""name"": ""AD"", ""members"": ""users"", ""match"": ""CORP"", ""search_in"": ""dir-1"", ""case"": ""upper""}]");
        var (n, s, _) = Transform.MemberTarget("CORP\\jdoe", cfg, "User");
        Assert.Equal(("JDOE@CORP.EXAMPLE.COM", "dir-1"), (n, s));
    }

    [Fact]
    public void UiValidation()
    {
        Assert.Throws<UiError>(() => UiApp.CheckSettings(C(@"[{""from"": ""CORP"", ""to"": ""bad domain""}]")));
        Assert.Throws<UiError>(() => UiApp.CheckSettings(C(@"[{""from"": """", ""to"": ""x.com""}]")));
        UiApp.CheckSettings(C(@"[{""from"": ""CORP"", ""to"": ""corp.example.com""}]"));
    }
}
