namespace Imw.Tests;

// Port of tests/test_naming.py

static class NamingHelpers
{
    public static SourceRecord Rec(string folder, string username = "admin", string type = "") =>
        new("t", "f", folder + username, "")
        {
            Folder = SourceRecord.SplitFolder(folder), Username = username, Type = type, Address = "h", Secret = "x",
        };

    public const string Layered = @"{""safe_convention"": {""template"": ""{env}-{folder}-{tech}-{flavor}-{acct}""}}";
}

/// <summary>Defaults: the folder structure names the Safe; CyberArk layers only without folders.</summary>
public class FolderFirst
{
    readonly Namer n = new(Config.Load());
    static SourceRecord Rec(string f, string u = "admin", string t = "") => NamingHelpers.Rec(f, u, t);

    [Fact]
    public void FolderLevelsInOrder()
    {
        Assert.Equal("APP-SF-P", n.Build(Rec("\\Applications\\Storefront\\Prod"), "UnixSSH").Name);
        Assert.Equal("APP-PAY-P", n.Build(Rec("\\Applications\\Payments\\Prod"), "WinServerLocal").Name);
    }

    [Fact]
    public void NoFoldersUsesCyberArkLayers()
    {
        Assert.Equal("SVR-WIN-LS", n.Build(Rec("", "svc_web"), "WinServerLocal").Name);
        var cfg = TestBase.Cfg(@"{""safe_convention"": {""default_environment"": ""P""}}");
        Assert.Equal("P-SVR-UNX-RT", new Namer(cfg).Build(Rec("", "root"), "UnixSSH").Name);
    }

    [Fact]
    public void CompoundAndCamelCaseWords()
    {
        Assert.Equal("WP", n.Auto("Webportal"));
        Assert.Equal("SP", n.Auto("SharePoint"));
    }

    [Fact]
    public void WholeFolderAbbreviationWins()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {""abbreviations"": {""Batch: Nightly/Weekly Jobs"": ""BNW""}}}");
        Assert.Equal("LNX-BNW", new Namer(cfg).Build(Rec("\\Linux\\Batch: Nightly/Weekly Jobs"), "UnixSSH").Name);
    }

    [Fact]
    public void SuggestionsFromFolderNames()
    {
        var counts = new Dictionary<string, long> { ["Storefront"] = 4, ["Prod"] = 9, ["Zebra"] = 1, ["Zbr"] = 1 };
        var rows = n.Suggest(counts).ToDictionary(r => (string)r["folder"]);
        Assert.Equal("SF", rows["Storefront"]["code"]);
        Assert.Equal(false, rows["Storefront"]["automatic"]);
        Assert.Equal(true, rows["Zebra"]["automatic"]);
        var zbr = (string)rows["Zbr"]["clash"];
        Assert.Equal(zbr.Length > 0 ? "Zebra" : "Zbr", zbr.Length > 0 ? zbr : rows["Zebra"]["clash"]);
    }
}

/// <summary>The CyberArk layered template from the cheat sheet.</summary>
public class LayeredNaming
{
    readonly Namer n = new(TestBase.Cfg(NamingHelpers.Layered));
    string Name(string folder, string platform, string user = "admin") => n.Build(NamingHelpers.Rec(folder, user), platform).Name;

    [Fact]
    public void CheatSheetStyle()
    {
        Assert.Equal("P-BOS-DC-WIN-SVR-HR-APP-LS", Name("\\Boston DC\\Production\\Windows Servers\\HR App", "WinServerLocal", "svc_hr"));
        Assert.Equal("D-ORC-HR-DB-LS", Name("\\Development\\Oracle\\HR", "Oracle", "svc_hr"));
        Assert.Equal("INF-WIN-DC-DOM-DS", Name("\\Infrastructure\\Windows\\Domain Controllers", "WinDomain", "svc_x"));
        Assert.Equal("NET-CSW-CSC-EN", Name("\\Network\\Core Switches", "CiscoSSH", "enable"));
    }

    [Fact]
    public void AccountTypeRulesRespectTechnology()
    {
        Assert.EndsWith("-RT", Name("\\Linux", "UnixSSH", "root"));
        Assert.EndsWith("-LA", Name("\\Windows", "WinServerLocal", "root"));   // root only means RT on Unix flavors
        Assert.EndsWith("-SA", Name("\\SQL", "MSSql", "sa"));
        Assert.EndsWith("-LA", Name("\\Windows", "WinServerLocal", "sa"));
    }

    [Fact]
    public void AlwaysFitsAndKeepsLevels()
    {
        foreach (var folder in new[]
                 {
                     "\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs",
                     "\\Customer Facing\\Development\\Oracle Finance Ledger Systems",
                     "\\A Very Long Business Unit Name\\Another Long Department\\Yet Another Deep Folder Level Here",
                     "\\L1 Alpha Beta\\L2 Gamma Delta\\L3 Epsilon Zeta\\L4 Eta Theta\\L5 Iota Kappa\\L6 Lambda",
                 })
        {
            var (name, notes) = n.Build(NamingHelpers.Rec(folder), "WinServerLocal");
            Assert.True(name.Length <= 28, name);
            Assert.NotEmpty(notes);
        }
        Assert.Equal("INF-LNX-BNWJ-SVR-UNX-RT", Name("\\Infrastructure\\Linux\\Batch: Nightly/Weekly Jobs", "UnixSSH", "root"));
    }

    [Fact]
    public void CollisionsStayDistinct()
    {
        var a = Name("\\Databases\\SQL Production Reporting Replicas EU West", "MSSql", "sa");
        var b = Name("\\Databases\\SQL Production Reporting Replicas EU East", "MSSql", "sa");
        Assert.Equal("P-DB-SQL-RPT-RPL-EU-W-SA", a);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void UserSettings()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {""template"": ""{env}-{folder}-{flavor}"", ""default_environment"": ""P"",
            ""abbreviations"": {""Payroll Systems"": ""PRS""}, ""skip_folder_levels"": [""Applications""]}}");
        var nm = new Namer(cfg);
        Assert.Equal("P-PRS-WIN", nm.Build(NamingHelpers.Rec("\\Applications\\Payroll Systems"), "WinServerLocal").Name);
        nm.Build(NamingHelpers.Rec("\\Zebra Unit"), "WinServerLocal");
        Assert.Equal("ZBR", nm.Unknown["Zebra"]);
    }
}

public class ConventionInPlan : TestBase
{
    static SourceRecord Rec(string f, string u = "admin", string t = "") => NamingHelpers.Rec(f, u, t);

    [Fact]
    public void DefaultFallbackUsesConvention()
    {
        var recs = new List<SourceRecord>
        {
            Rec("\\Production\\Windows\\Member Servers", "Administrator", "Windows Account"),
            Rec("\\Production\\Windows\\Member Servers", "svc_app", "Windows Account"),
        };
        var plan = Transform.BuildPlan(recs, Config.Load());
        Assert.Equal(new[] { "P-WIN-SVR", "P-WIN-SVR" }, plan.Accounts.Select(p => p.Safe));
        Assert.Equal("fallback:convention", plan.Accounts[0].SafeSource);
        Assert.All(plan.Accounts, p => Assert.True(p.ValidSafe));
        Assert.DoesNotContain(plan.Accounts[0].Warnings, w => w.Contains("fallback"));
        plan = Transform.BuildPlan(recs, Cfg(NamingHelpers.Layered));
        Assert.Equal(new[] { "P-WIN-SVR-LA", "P-WIN-SVR-LS" }, plan.Accounts.Select(p => p.Safe));
    }

    [Fact]
    public void FolderRulesBeatGroupRulesByDefault()
    {
        var r = Rec("\\Applications\\Payments", "svc_pay", "Windows Account");
        r.Grants = new List<Grant> { new("CORP\\Payments-Team", "Owner") };
        var user = J(@"{""group_rules"": [{""group"": ""CORP\\Payments-Team"", ""safe"": ""ROLE-PAY""}],
                       ""folder_rules"": [{""folder_prefix"": ""\\Applications\\Payments"", ""safe"": ""APP-PAYMENTS""}]}");
        Assert.Equal("APP-PAYMENTS", Transform.BuildPlan(new[] { r }, Config.FromDict(user)).Accounts[0].Safe);
        user["group_rules_first"] = true;
        Assert.Equal("ROLE-PAY", Transform.BuildPlan(new[] { r }, Config.FromDict(user)).Accounts[0].Safe);
        user.Remove("folder_rules");
        user["group_rules_first"] = false;
        Assert.Equal("ROLE-PAY", Transform.BuildPlan(new[] { r }, Config.FromDict(user)).Accounts[0].Safe);
    }

    [Fact]
    public void RulePlaceholders()
    {
        var cfg = Cfg(@"{""group_rules"": [{""group_pattern"": ""^CORP\\\\APP-(.+)-Owners$"", ""safe"": ""{env}-{1}-{tech}-{flavor}-{acct}""}]}");
        var r = Rec("\\Production\\Payments", "svc_pay", "Windows Account");
        r.Grants = new List<Grant> { new("CORP\\APP-PAY-Owners", "Owner") };
        Assert.Equal("P-PAY-SVR-WIN-LS", Transform.BuildPlan(new[] { r }, cfg).Accounts[0].Safe);
    }

    [Fact]
    public void CapacityWarning()
    {
        var cfg = Cfg(@"{""safe_max_accounts"": 2}");
        var recs = Enumerable.Range(0, 3).Select(i => Rec("\\Prod\\Windows", $"u{i}", "Windows Account")).ToList();
        var issues = Transform.BuildPlan(recs, cfg).Safes.Values.First().Issues;
        Assert.Contains(issues, i => i.Contains("over the 2 recommended"));
    }

    [Fact]
    public void SharedSafeWarning()
    {
        var cfg = Cfg(@"{""safe_convention"": {""skip_folder_levels"": [""Team A"", ""Team B""]}}");
        var recs = new[] { Rec("\\Team A\\Windows", "x", "Windows Account"), Rec("\\Team B\\Windows", "y", "Windows Account") };
        var plan = Transform.BuildPlan(recs, cfg);
        // A Safe-level note: it shows on the Safe, and doesn't make the accounts need a look.
        Assert.DoesNotContain(plan.Accounts[0].Warnings, w => w.Contains("shared by"));
        Assert.Contains(plan.Safes.Values.First().Issues, i => i.Contains("shared by 2 source folders"));
    }
}
