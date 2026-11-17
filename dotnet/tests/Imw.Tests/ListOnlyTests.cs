using System.Text;
using Imw.Adapters;

namespace Imw.Tests;

// Port of tests/test_list_only.py: a plain accounts list (no folders, no permissions): Safe names from account
// details, splitting big Safes, standard member groups per Safe and the groups-to-create list.

static class ListOnly
{
    public static string List => TestBase.S("accounts_list_only.csv");
    public static List<SourceRecord> Records(JObj cfg) => Adapter.Get("table").Read(List, cfg);
    public static string Std => Json.Dumps(Config.StandardMemberSet());
    public static bool Has(IEnumerable<string> items, string text) => items.Any(i => i.Contains(text, StringComparison.Ordinal));
}

public class SafeNamesFromDetails
{
    [Fact]
    public void AddressDomain()
    {
        Assert.Equal("boston.corp.example.com", Naming.AddressDomain("srv01.boston.corp.example.com"));
        Assert.Equal("", Naming.AddressDomain("SRV01"));
        Assert.Equal("", Naming.AddressDomain("10.1.2.3"));
        Assert.Equal("", Naming.AddressDomain("fe80::1"));
    }

    [Fact]
    public void ColumnLayerAndEnvFromColumn()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {
            ""template_no_folders"": ""{env}-{site}-{tech}-{flavor}-{acct}"",
            ""layers"": {""site"": {""label"": ""Site"", ""default"": """", ""rules"": [
                {""field"": ""column:Site"", ""pattern"": ""^Boston$"", ""code"": ""BOS""},
                {""field"": ""column:site"", ""pattern"": ""^London$"", ""code"": ""LON""}]},
                ""env"": {""label"": ""Environment"", ""default"": """", ""rules"": [
                    {""field"": ""column:Environment"", ""pattern"": ""^Production$"", ""code"": ""P""}]}}}}");
        var safes = Transform.BuildPlan(ListOnly.Records(cfg), cfg).Safes.Keys;
        Assert.Contains("P-BOS-SVR-WIN-LA", safes);
        Assert.Contains("LON-DB-SQL-SA", safes);            // Development: no {env} code
        Assert.Contains("P-SVR-UNX-RT", safes);              // Singapore: no {site} code
    }

    [Fact]
    public void AddressDomainLayer()
    {
        var cfg = TestBase.Cfg(@"{""safe_convention"": {
            ""template_no_folders"": ""{dom}-{tech}-{flavor}"",
            ""layers"": {""dom"": {""label"": ""Domain"", ""rules"": [
                {""field"": ""address_domain"", ""pattern"": ""^london\\."", ""code"": ""LON""}]}}}}");
        Assert.Contains("LON-SVR-WIN", Transform.BuildPlan(ListOnly.Records(cfg), cfg).Safes.Keys);
    }
}

public class Split
{
    static Plan MakePlan(string extra = "")
    {
        var cfg = TestBase.Cfg("{\"safe_max_accounts\": 10" + extra + "}");
        return Transform.BuildPlan(ListOnly.Records(cfg), cfg);
    }

    [Fact]
    public void FlagOnlyByDefault()
    {
        var plan = MakePlan();
        Assert.Equal(24, plan.Safes["SVR-WIN-LA"].Accounts);
        Assert.True(ListOnly.Has(plan.Safes["SVR-WIN-LA"].Issues, "over the 10"));
    }

    [Fact]
    public void SplitEvenAndByAddress()
    {
        var plan = MakePlan(", \"safe_split_over_max\": true");
        var counts = plan.Accounts.Where(p => p.Safe.StartsWith("SVR-WIN-LA", StringComparison.Ordinal))
                                  .GroupBy(p => p.Safe).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int> { ["SVR-WIN-LA-01"] = 8, ["SVR-WIN-LA-02"] = 8, ["SVR-WIN-LA-03"] = 8 }, counts);
        var first = Py.Sorted(plan.Accounts.Where(p => p.Safe == "SVR-WIN-LA-01").Select(p => p.Rec.Address));
        var allw = Py.Sorted(plan.Accounts.Where(p => p.Safe.StartsWith("SVR-WIN-LA", StringComparison.Ordinal)).Select(p => p.Rec.Address));
        Assert.Equal(allw.Take(8), first);
        var issues = plan.Safes["SVR-WIN-LA-02"].Issues;
        Assert.True(ListOnly.Has(issues, "part 2 of 3"), string.Join("; ", issues));
        Assert.False(ListOnly.Has(issues, "recommended per Safe"));
        Assert.All(plan.Safes.Keys, n => Assert.True(n.Length <= 28));
    }

    [Fact]
    public void SplitKeeps28CharactersAndSkipsOverrides()
    {
        var cfg = TestBase.Cfg("{\"safe_max_accounts\": 2, \"safe_split_over_max\": true, \"safe_name\": {\"prefix\": \"MIGRATION-LONG-PREFIX-\"}}");
        var recs = ListOnly.Records(cfg);
        var plan = Transform.BuildPlan(recs, cfg, overrides: new() { [recs[0].RecordId] = new() { ["Target_Safe"] = "Mine" } }, @explicit: true);
        Assert.All(plan.Safes.Keys, n => Assert.True(n.Length <= 28, n));
        Assert.Contains("Mine", plan.Safes.Keys);
        Assert.Contains(plan.Safes.Keys, n => n.EndsWith("-01", StringComparison.Ordinal));
    }
}

public class StandardMembers : TestBase
{
    static JObj StdCfg(string std = "") => Cfg("{\"standard_members\": {\"members\": " + ListOnly.Std + std + "}}");

    static SourceRecord Rec(string rid, string folder, List<Grant> grants) =>
        new("t", "f", rid, "")
        {
            Folder = new List<string> { folder }, Username = "admin", Address = "h" + rid, Type = "Windows Account", Secret = "x", Grants = grants,
        };

    [Fact]
    public void EverySafeGetsTheSet()
    {
        var cfg = StdCfg();
        var plan = Transform.BuildPlan(ListOnly.Records(cfg), cfg);
        var names = plan.Members.Select(kv => (kv.Key.Safe, kv.Value.MemberName, kv.Value.Role)).ToHashSet();
        Assert.Contains(("SVR-WIN-LA", "SVR-WIN-LA-Owners", "Full"), names);
        Assert.Contains(("SVR-WIN-LA", "SVR-WIN-LA-Users", "Connect only"), names);
        Assert.Contains(("SVR-WIN-LA", "SVR-WIN-LA-Approvers", "Approver"), names);
        Assert.Equal(3 * plan.Safes.Count, plan.Members.Count);
        foreach (var s in plan.Safes.Values)
            Assert.False(ListOnly.Has(s.Issues, "no member with full") || ListOnly.Has(s.Issues, "no access groups"), string.Join("; ", s.Issues));
        var m = plan.Members[("SVR-WIN-LA", "svr-win-la-owners")];
        Assert.Contains(Transform.StandardNote["Group"], m.Notes);
        Assert.Equal(plan.Safes["SVR-WIN-LA"].Accounts, m.Accounts);
    }

    [Fact]
    public void OffAndEmpty()
    {
        foreach (var cfg in new[] { Cfg(), StdCfg(", \"apply_to\": \"off\"") })
        {
            var plan = Transform.BuildPlan(ListOnly.Records(cfg), cfg);
            Assert.Equal(0, plan.Members.Count);
            Assert.True(ListOnly.Has(plan.Safes["SVR-WIN-LA"].Issues, "no member with full"));
        }
    }

    [Fact]
    public void OnlySafesWithoutSourceMembersUnlessAll()
    {
        List<SourceRecord> Recs() => new() { Rec("1", "Apps", new() { new Grant("CORP\\App-Admins", "Owner", "Group") }), Rec("2", "Web", new()) };
        var plan = Transform.BuildPlan(Recs(), StdCfg());
        Assert.Equal(new HashSet<string> { "APPS", "WEB" }, plan.Members.Keys.Select(k => k.Safe).ToHashSet());
        Assert.Equal(1, plan.Members.Keys.Count(k => k.Safe == "APPS"));
        plan = Transform.BuildPlan(Recs(), StdCfg(", \"apply_to\": \"all\""));
        Assert.Equal(4, plan.Members.Keys.Count(k => k.Safe == "APPS"));
    }

    [Fact]
    public void SameNameAsSourceMemberMergesAndIsNotToCreate()
    {
        var cfg = Cfg("{\"standard_members\": {\"apply_to\": \"all\", \"members\": [{\"name\": \"App-Admins\", \"member_type\": \"Group\", \"role\": \"Connect only\"}]}}");
        var plan = Transform.BuildPlan(new[] { Rec("1", "Apps", new() { new Grant("CORP\\App-Admins", "Owner", "Group") }) }, cfg);
        Assert.Equal(1, plan.Members.Count);
        var m = plan.Members.Values.First();
        Assert.Equal("Full", m.Role);                        // the strongest wins
        Assert.False(m.Standard);
        Assert.Empty(Writers.GroupsToCreate(plan));
    }

    [Fact]
    public void FixedMemberDomainConversionAndChecks()
    {
        var cfg = Cfg("{\"domain_map\": [{\"from\": \"CORP\", \"to\": \"corp.example.com\", \"members\": \"groups\"}], " +
                      "\"standard_members\": {\"members\": [" +
                      "{\"name\": \"CORP\\\\{safe}-Users\", \"member_type\": \"Group\", \"role\": \"Connect only\"}, " +
                      "{\"name\": \"PAM-Vault-Admins\", \"member_type\": \"Group\", \"role\": \"Full\", \"search_in\": \"Vault\"}, " +
                      "{\"name\": \"{safe}+" + new string('x', 60) + "\", \"member_type\": \"Group\", \"role\": \"Read only\"}]}}");
        var plan = Transform.BuildPlan(ListOnly.Records(cfg), cfg);
        var m = plan.Members[("SVR-WIN-LA", "svr-win-la-users@corp.example.com")];
        Assert.Equal("SVR-WIN-LA-Users@corp.example.com", m.MemberName);
        var admins = plan.Members.Values.Where(x => x.MemberName == "PAM-Vault-Admins").ToList();
        Assert.Equal(plan.Safes.Count, admins.Count);
        Assert.Equal("Vault", admins[0].SearchIn);
        var lng = plan.Members.Values.First(x => x.MemberName.EndsWith(new string('x', 60), StringComparison.Ordinal));
        Assert.True(ListOnly.Has(lng.Notes, "does not allow +"), string.Join("; ", lng.Notes));
        Assert.True(ListOnly.Has(lng.Notes, "at most 64"), string.Join("; ", lng.Notes));
        var vault = Writers.GroupsToCreate(plan).First(g => g.MemberName == "PAM-Vault-Admins");
        Assert.Equal(plan.Safes.Count, vault.Safes.Count);
    }

    [Fact]
    public void ReviewFileAndSplitNames()
    {
        var cfg = Cfg("{\"safe_max_accounts\": 10, \"safe_split_over_max\": true, \"standard_members\": {\"members\": " + ListOnly.Std + "}}");
        var plan = Transform.BuildPlan(ListOnly.Records(cfg), cfg);
        var files = Writers.WriteReview(plan, Tmp);
        Assert.Equal("MemberGroups_To_Create.csv", Path.GetFileName(files[^1]));
        var rows = ReadCsv(files[^1]);
        Assert.Contains("SVR-WIN-LA-02-Owners", rows.Select(r => r["Member_Name"]));
        Assert.Equal(3 * plan.Safes.Count, rows.Count);
        Assert.Equal(new[] { "1" }, rows.Select(r => r["Safes"]).Distinct());
        var plain = Transform.BuildPlan(ListOnly.Records(Cfg()), Cfg());
        Assert.DoesNotContain("MemberGroups_To_Create.csv", Writers.WriteReview(plain, T("none")).Select(Path.GetFileName));
    }
}

public class NamingConventionFile : TestBase
{
    [Fact]
    public void PartsOfTheSafeNames()
    {
        var cfg = Cfg("{\"standard_members\": {\"members\": " + ListOnly.Std + "}, " +
                      "\"safe_convention\": {\"template_no_folders\": \"{env}-{site}-{tech}\", " +
                      "\"layers\": {\"site\": {\"label\": \"Site\", \"default\": \"X\", \"rules\": [" +
                      "{\"field\": \"column:Site\", \"pattern\": \"^Boston$\", \"code\": \"BOS\"}]}}}}");
        var plan = Transform.BuildPlan(ListOnly.Records(cfg), cfg);
        Assert.Equal(new[] { "BOS-DB", "BOS-DOM", "BOS-SVR", "X-DB", "X-DOM", "X-SVR" }, plan.Safes.Keys.OrderBy(x => x, StringComparer.Ordinal));
        var path = Writers.WriteConvention(plan, cfg, Tmp);
        Assert.Equal(new[] { "var1,var2", "BOS,DB", "X,DOM", ",SVR" }, ReadText(path).Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries));
        foreach (var p in plan.Accounts) if (p.Safe.StartsWith("X-", StringComparison.Ordinal)) p.Migrate = "N";
        Transform.RebuildTotals(plan, cfg);
        var rows = Writers.ConventionRows(plan, cfg).Item2.Select(r => string.Join(",", r.Select(Py.Str))).ToList();
        Assert.Equal(new[] { "BOS,DB", ",DOM", ",SVR" }, rows);
    }
}

public class ListOnlyUi : UiTestBase
{
    protected override IEnumerable<string> InboxFiles => new[] { "accounts_list_only.csv" };

    static List<JObj> Values(JObj v) => Rows(v, "values");

    [Fact]
    public void ValuesHintsAndValidation()
    {
        Login();
        var (st, r) = Post("/api/ingest", J("{\"files\": [{\"name\": \"accounts_list_only.csv\", \"source\": \"table\"}]}"));
        Assert.True(st == 200, Json.Dumps(r));
        var (_, c) = Get("/api/config");
        var hints = (JObj)c.Get("hints");
        Assert.Equal("[120, 120, 0]", Json.Dumps(new List<object> { hints.Get("records"), hints.Get("without_folder"), hints.Get("with_grants") }));
        Assert.Equal(ListOnly.Std, Json.Dumps(c.Get("standard_member_set")));
        var (st2, v) = Post("/api/rules/values", "{\"field\": \"column:Site\"}");
        Assert.True(st2 == 200, Json.Dumps(v));
        Assert.Equal("BOS", Values(v).First(x => (string)x.Get("value") == "Boston").Get("code"));
        Assert.Equal("3", Json.Dumps(v.Get("distinct")));
        (_, v) = Post("/api/rules/values", "{\"field\": \"column:Environment\"}");
        Assert.Equal("P", Values(v).First(x => (string)x.Get("value") == "Production").Get("code"));
        (_, v) = Post("/api/rules/values", "{\"field\": \"address_domain\"}");
        Assert.Contains("boston.corp.example.com", Values(v).Select(x => (string)x.Get("value")));
        Assert.Equal(400, Post("/api/rules/values", "{\"field\": \"nope\"}").Status);
        foreach (var row in new[] { "{\"name\": \"{site}-Users\", \"role\": \"Full\"}", "{\"name\": \"{safe}-Users\", \"role\": \"Nobody\"}",
                                    "{\"name\": \"\", \"role\": \"Full\"}" })
        {
            var (s, b) = Post("/api/config", "{\"patch\": {\"standard_members\": {\"members\": [" + row + "]}}}");
            Assert.True(s == 400, row + " " + Json.Dumps(b));
        }
        (st, r) = Post("/api/rules/preview", "{\"kind\": \"members\", \"patch\": {\"standard_members\": {\"members\": " + ListOnly.Std + "}}}");
        Assert.True(st == 200, Json.Dumps(r));
        var prows = Rows(r);
        Assert.NotEmpty(prows);
        Assert.All(prows, x => Assert.True(Py.Truthy(x.Get("standard"))));
        Assert.StartsWith("(standard member group", (string)prows[0].Get("source"));
        (st, r) = Post("/api/config", "{\"patch\": {\"standard_members\": {\"members\": " + ListOnly.Std + "}, \"safe_split_over_max\": true, \"safe_max_accounts\": 10}}");
        Assert.True(st == 200, Json.Dumps(r));
        var (_, s2) = Get("/api/safes");
        Assert.Contains("SVR-WIN-LA-03", Rows(s2, "safes").Select(x => (string)x.Get("safe_name")));
        var (st3, outp) = Post("/api/extract", "{\"name\": \"t1\"}");
        Assert.True(st3 == 200, Json.Dumps(outp));
        var files = outp.List("files").Cast<string>().Select(f => f.Replace('\\', '/')).ToList();   // \ on Windows, as in Python
        Assert.Contains("review/MemberGroups_To_Create.csv", files);
        Assert.Contains("review/SafeNamingConvention.csv", files);
        var (st4, text, _) = Req("GET", "/api/export/convention.csv");
        Assert.Equal(200, st4);
        var conv = Encoding.UTF8.GetString((byte[])text).TrimStart('\ufeff');
        Assert.StartsWith("var1,", conv);
        Assert.Contains("LA", conv);
    }
}
