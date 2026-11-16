namespace Imw.Tests;

// Port of tests/test_safe_overrides.py: your direct changes to whole Safes (rename one Safe, change its settings).

public class SafeOverridesInPlan
{
    const string CfgJson = "{\"default_platform\": \"WinServerLocal\", \"safe_defaults\": {\"numberOfDaysRetention\": 7, \"managingCPM\": \"RulesCPM\"}}";

    static SourceRecord Rec(string sid, string folder)
    {
        return new SourceRecord("t", "f", sid, sid)
        {
            Name = sid, Folder = new List<string> { folder }, Type = "Windows", Address = "h1", Username = "u" + sid, Secret = "x",
            Grants = new List<Grant> { new("CORP\\Ops", "View") },
        };
    }

    static string SafeOf(Plan plan, string folder) => plan.Accounts.First(p => p.Rec.Folder.SequenceEqual(new[] { folder })).Safe;

    static (Plan, JObj) MakePlan(Dictionary<string, JObj> ov)
    {
        var cfg = TestBase.Cfg(CfgJson);
        var p = Transform.BuildPlan(new[] { Rec("1", "Apps"), Rec("2", "Apps"), Rec("3", "Web") }, cfg, safeOverrides: ov);
        return (p, cfg);
    }

    static string D(object v) => Json.Dumps(v);

    [Fact]
    public void RenameMovesEveryAccountAndMembers()
    {
        var (b, _) = MakePlan(new());
        var old = SafeOf(b, "Apps");
        var (plan, _) = MakePlan(new() { [Py.Lower(old)] = Json.O(("new_name", "MY-APPS")) });
        Assert.True(plan.Safes.ContainsKey("MY-APPS"));
        Assert.False(plan.Safes.ContainsKey(old));
        Assert.Equal(2, plan.Safes["MY-APPS"].Accounts);
        Assert.Equal(new[] { "MY-APPS" }, plan.Accounts.Where(p => p.Rec.Folder.SequenceEqual(new[] { "Apps" })).Select(p => p.Safe).Distinct());
        var other = plan.Safes.Keys.First(n => n != "MY-APPS");
        Assert.Equal(new HashSet<string> { "MY-APPS", other }, plan.Members.Keys.Select(k => k.Safe).ToHashSet());
    }

    [Fact]
    public void SettingsWinOverRulesAndRetentionIsOneOrTheOther()
    {
        var (b, _) = MakePlan(new());
        var old = SafeOf(b, "Web");
        var (plan, cfg) = MakePlan(new()
        {
            [Py.Lower(old)] = Json.O(("description", "Mine"), ("numberOfVersionsRetention", 12), ("olacEnabled", true)),
        });
        var body = Transform.SafeSettings(old, plan.Safes[old], cfg);
        Assert.Equal(new[] { "\"Mine\"", "12", "\"\"", "true", "\"RulesCPM\"" },
                     new[] { "description", "numberOfVersionsRetention", "numberOfDaysRetention", "olacEnabled", "managingCPM" }.Select(k => D(body.Get(k))));
        var rules = Transform.SafeSettings(old, plan.Safes[old], cfg, withOverride: false);
        Assert.Equal(new[] { "\"\"", "7" }, new[] { "description", "numberOfDaysRetention" }.Select(k => D(rules.Get(k))));
    }

    [Fact]
    public void RenameOntoExistingSafeMergesAndWarns()
    {
        var (b, _) = MakePlan(new());
        var apps = SafeOf(b, "Apps");
        var web = SafeOf(b, "Web");
        var (plan, _) = MakePlan(new() { [Py.Lower(web)] = Json.O(("new_name", apps)) });
        Assert.Equal(new[] { apps }, plan.Safes.Keys);
        Assert.DoesNotContain(plan.Accounts.SelectMany(p => p.Warnings), w => w.Contains("already has"));
        Assert.Contains(plan.Safes[apps].Issues, i => i.Contains("already has"));
    }
}

public class SafeOverridesInStore : TestBase
{
    [Fact]
    public void StoreUploadAndUndo()
    {
        var db = T("m.db");
        var (rc, text) = RunCli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", S("delinea_export.csv"), "-p", S("delinea_permissions.csv"));
        Assert.True(rc == 0, text);
        (rc, text) = RunCli("map", "--db", db, "-c", S("config_delinea.json"));
        Assert.True(rc == 0, text);
        using var st = new Store(db);
        var old = (string)st.Db.Scalar("SELECT safe_name FROM plan_safes ORDER BY safe_name");
        st.SetMemberEdits(new List<string> { old }, "PAM-Auditors", "add", role: "Read only");
        st.SetSafeOverride(old, Json.O(("new_name", "X-MINE"), ("managingCPM", "MyCPM"), ("numberOfVersionsRetention", 5)),
                           "test", oldName: old, newName: "X-MINE");
        st.Map(st.StoredConfig());
        var row = st.Db.One("SELECT managing_cpm, retention, rule_names, override_json FROM plan_safes WHERE safe_name = 'X-MINE'");
        Assert.Equal(("MyCPM", "5 versions", old), ((string)row[0], (string)row[1], (string)row[2]));
        Assert.False(string.IsNullOrEmpty(row[3] as string));
        // the per-Safe member change followed the rename
        Assert.NotNull(st.Db.One("SELECT 1 FROM plan_members WHERE safe_name = 'X-MINE' AND member_name = 'PAM-Auditors'"));
        var out_ = T("o");
        Store.RunExtract(st, out_);
        var safes = ReadCsv(Path.Combine(out_, "upload", "Safes.csv")).ToDictionary(s => s["safeName"]);
        Assert.Equal(("MyCPM", "5"), (safes["X-MINE"]["managingCPM"], safes["X-MINE"]["numberOfVersionsRetention"]));
        st.SetSafeOverride(old, new JObj(), undo: true, oldName: "X-MINE", newName: old);
        st.Map(st.StoredConfig());
        Assert.NotNull(st.Db.One("SELECT 1 FROM plan_safes WHERE safe_name = ?", old));
        Assert.NotNull(st.Db.One("SELECT 1 FROM plan_members WHERE safe_name = ? AND member_name = 'PAM-Auditors'", old));
    }
}
