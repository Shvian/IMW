using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_delinea_reports.py and UiServer.test_add_files_and_decide in tests/test_ui.py

public class DelineaReportsTests : TestBase
{
    static string R(string name) => Path.Combine(Samples, "delinea_reports", name);
    static readonly string[] ReportSecrets = { "Pw1!", "Pw2!", "Pw3!", "Pw4!", "Pw5!", "Pw6!", "JBSWY3DPEHPK3PXP", "111-222" };

    sealed class Rec
    {
        public static SourceRecord At(params string[] folder)
        {
            var r = new SourceRecord("x", "f", "x", "line 1") { Name = "n" };
            r.Folder.AddRange(folder);
            return r;
        }
    }

    [Fact]
    public void EachReportIsRecognised()
    {
        var want = new Dictionary<string, string>
        {
            ["allsecrets.csv"] = "templates", ["lauserslist.csv"] = "users", ["lagroups.csv"] = "groups",
            ["secret-template-list.csv"] = "template_list", ["whatroleassignmentsexist.csv"] = "roles",
            ["whatrolepermissionassignmentsexist.csv"] = "roles", ["secrets-export.csv"] = "",
            ["whatfolderpermissionsexistforgroups.csv"] = "", ["whatfolderscanalluserssee.csv"] = "",
        };
        foreach (var (name, kind) in want) Assert.True(Reference.Kind(R(name)) == kind, name);
    }

    [Fact]
    public void PermissionReportsOnly()
    {
        var perms = Directory.GetFiles(Path.Combine(Samples, "delinea_reports"), "*.csv").Where(UiApp.LooksLikePermissions)
                             .Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "whatfolderpermissionsexistforgroups.csv", "whatfolderscanalluserssee.csv" }, perms);
    }

    static References Refs() => new(Reference.ReadTemplates(R("allsecrets.csv")), Reference.ReadUsers(R("lauserslist.csv")));

    [Fact]
    public void TemplateByNameAndFolder()
    {
        var refs = Refs();
        Assert.Equal(("Windows Account", ""), refs.TemplateFor("DB admin", new[] { "IT", "Servers", "Windows" }));
        Assert.Equal(("Windows Account", ""), refs.TemplateFor("db ADMIN", Array.Empty<string>()));
        Assert.Equal("Web Password", refs.TemplateFor("Twin", new[] { "IT", "Web" }).Item1);
        Assert.Equal("Unix Account (SSH)", refs.TemplateFor("Twin", new[] { "Unix", "Linux" }).Item1);
        var (tmpl, note) = refs.TemplateFor("Twin", new[] { "Other" });
        Assert.Equal("", tmpl);
        Assert.Contains("different templates", note);
        Assert.Contains("not in the template list", refs.TemplateFor("Lost", Array.Empty<string>()).Item2);
    }

    [Fact]
    public void FullNameToUpn()
    {
        var refs = Refs();
        Assert.Equal(("jane.smith@corp.example.com", ""), refs.UpnFor("jane smith"));
        Assert.Equal(((string)null, ""), refs.UpnFor("jane.smith@corp.example.com"));
        Assert.Contains("not in the users list", refs.UpnFor("Nobody Known").Item2);
        var two = new References(null, new[] { ("Pat Lee", "pat1@x.com", ""), ("Pat Lee", "pat2@x.com", "") });
        Assert.Contains("2 users", two.UpnFor("Pat Lee").Item2);
        Assert.Equal(((string)null, ""), new References().UpnFor("Pat Lee"));
    }

    [Fact]
    public void DirectAndUndecided()
    {
        var perms = new Permissions(new[] { R("whatfolderpermissionsexistforgroups.csv"), R("whatfolderscanalluserssee.csv") });
        var (grants, how) = perms.Resolve(Rec.At("Unix", "Linux"));
        Assert.Equal("folder", how);
        var got = grants.Select(g => (g.Member, g.Basis, g.Hint)).ToList();
        Assert.Contains(("Unix Team", "", ""), got);
        Assert.Contains(("Bob Jones", "direct", ""), got);
        Assert.Contains(("Jane Smith", "undecided", "Unix Team"), got);
        got = perms.Resolve(Rec.At("IT", "Web")).Item1.Select(g => (g.Member, g.Basis, g.Hint)).ToList();
        Assert.Contains(("Jane Smith", "undecided", "CORP\\IT Admins"), got);
    }

    [Fact]
    public void WithoutAGroupReportNothingIsDecided()
    {
        var perms = new Permissions(new[] { R("whatfolderscanalluserssee.csv") });
        Assert.Equal(new[] { "undecided" }, perms.Resolve(Rec.At("Unix", "Linux")).Item1.Select(g => g.Basis).Distinct());
    }

    [Fact]
    public void EndToEnd()
    {
        var (rc, text) = RunCli("convert", "-o", T("out"), "--force", "-i", R("secrets-export.csv"), "-i", R("allsecrets.csv"),
            "-i", R("lagroups.csv"), "--reference", R("lauserslist.csv"),
            "-p", R("whatfolderpermissionsexistforgroups.csv"), "-p", R("whatfolderscanalluserssee.csv"));
        Assert.True(rc == 0, text);
        var review = ReadCsv(T("out", "review", "Accounts_Review.csv")).ToDictionary(r => r["Record_ID"].Split(':').Last());
        Assert.Equal("Web Password", review["row2"]["Source_Type"]);
        Assert.Equal("GenericWebApp", review["row2"]["Platform_ID"]);
        Assert.Equal("Unix Account (SSH)", review["row5"]["Source_Type"]);
        Assert.Equal("ERROR", review["row6"]["Status"]);
        Assert.Contains("not in the template list", review["row6"]["Notes"]);
        var users = ReadCsv(T("out", "review", "SafeMembers_Review.csv")).Where(m => m["Member_Type"] == "User").ToList();
        Assert.Equal(new[] { ("Bob Jones", "bob.jones@corp.example.com") }, users.Select(m => (m["Source_Member"], m["Member_Name"])));
        Assert.DoesNotContain("jane.smith@corp.example.com", ReadCsv(T("out", "upload", "SafeMembers.csv")).Select(m => m["MemberName"]));
        var decide = ReadCsv(T("out", "review", "Users_To_Decide.csv"));
        Assert.Equal(new[] { ("Jane Smith", "jane.smith@corp.example.com", "not decided"), ("Nobody Known", "Nobody Known", "not decided") },
                     decide.Select(d => (d["Source_Member"], d["Member_Name"], d["Decision"])).Distinct().OrderBy(x => x.Item1));
        Assert.Contains("not in the users list", decide.First(d => d["Source_Member"] == "Nobody Known")["Notes"]);
        foreach (var f in Directory.GetFiles(T("out", "review"), "*.csv"))
        {
            var body = ReadText(f);
            foreach (var s in ReportSecrets) Assert.DoesNotContain(s, body);
        }
    }

    [Fact]
    public void StoreDecisions()
    {
        var db = T("m.db");
        var (rc, text) = RunCli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", R("secrets-export.csv"), "-i", R("allsecrets.csv"),
            "--reference", R("lauserslist.csv"), "-p", R("whatfolderpermissionsexistforgroups.csv"), "-p", R("whatfolderscanalluserssee.csv"));
        Assert.True(rc == 0, text);
        using var st = new Store(db);
        var cfg = Config.Load(null);
        st.Map(cfg);
        var rows = st.Db.Query("SELECT folder, member, decision FROM plan_undecided ORDER BY member, folder")
                        .Select(r => ((string)r[0], (string)r[1], (string)r[2])).ToList();
        Assert.Equal(new[] { ("\\IT\\Web", "Jane Smith", ""), ("\\Unix\\Linux", "Jane Smith", ""), ("\\Unix\\Linux", "Nobody Known", "") }, rows);
        st.SetDecisions(new[] { ("\\IT\\Web", "Jane Smith") }, "include", "owns the web portal");
        st.SetDecisions(new[] { ("\\Unix\\Linux", "nobody known") }, "exclude");
        var plan = st.Map(cfg);
        var jane = plan.Members.Values.Where(m => m.MemberName == "jane.smith@corp.example.com").ToList();
        Assert.Equal(new[] { "Full" }, jane.Select(m => m.Role));
        Assert.Contains("included by you", jane[0].Notes[0]);
        var dec = st.Db.Query("SELECT folder, member, decision FROM plan_undecided")
                       .ToDictionary(r => ((string)r[0], (string)r[1]), r => (string)r[2]);
        Assert.Equal("exclude", dec[("\\Unix\\Linux", "Nobody Known")]);
        st.SetDecisions(new[] { ("\\IT\\Web", "Jane Smith") }, "");
        plan = st.Map(cfg);
        Assert.DoesNotContain(plan.Members.Values, m => m.MemberName.StartsWith("jane", StringComparison.Ordinal));
        var n = (long)st.Db.Scalar("SELECT COUNT(*) FROM ref_users");
        st.IngestReference("users", R("lauserslist.csv"), Reference.ReadUsers(R("lauserslist.csv")));
        Assert.Equal(n, (long)st.Db.Scalar("SELECT COUNT(*) FROM ref_users"));
    }
}

public class DelineaReportsUiTests : UiTestBase
{
    [Fact]
    public void AddFilesAndDecide()
    {
        Login();
        foreach (var f in Directory.GetFiles(Path.Combine(Samples, "delinea_reports"), "*.csv"))
            File.Copy(f, WsPath("inbox", Path.GetFileName(f)));
        var (_, state) = Get("/api/state");
        var kinds = Rows(state, "inbox_files").ToDictionary(f => (string)f["name"], f => (string)f["kind"]);
        Assert.Equal("templates", kinds["allsecrets.csv"]);
        Assert.Equal("users", kinds["lauserslist.csv"]);
        Assert.Equal("roles", kinds["whatroleassignmentsexist.csv"]);
        Assert.Equal("permissions", kinds["whatfolderscanalluserssee.csv"]);
        Assert.Equal("accounts", kinds["secrets-export.csv"]);
        Assert.False((bool)state.Obj("kinds").Obj("roles")["used"]);
        var (st, r) = Post("/api/ingest", @"{""files"": [{""name"": ""secrets-export.csv"", ""source"": """"}],
            ""permissions"": [""whatfolderpermissionsexistforgroups.csv"", ""whatfolderscanalluserssee.csv""],
            ""references"": [{""name"": ""allsecrets.csv"", ""kind"": ""templates""}, {""name"": ""lauserslist.csv"", ""kind"": ""users""}]}");
        Assert.True(st == 200, Json.Dumps(r));
        Assert.Equal(new object[] { "templates", "users", "delinea" }, Rows(r, "results").Select(x => x["source"]));
        (_, state) = Get("/api/state");
        Assert.Equal(3L, state["undecided"]);
        Assert.True(Py.Eq(state["references"], J(@"{""templates"": 5, ""users"": 2}")));
        var (_, u) = Get("/api/undecided");
        Assert.Equal(3, Rows(u).Count);
        var jane = Rows(u).Where(x => (string)x["member"] == "Jane Smith")
                          .Select(x => (object)Json.O(("folder", x["folder"]), ("member", x["member"]))).ToList();
        (st, r) = Post("/api/decide", Json.O(("items", jane), ("decision", "include")));
        Assert.Equal((200, 2L), (st, r["changed"]));
        (_, state) = Get("/api/state");
        Assert.Equal(1L, state["undecided"]);
        var (_, s) = Get("/api/safes");
        Assert.Contains("jane.smith@corp.example.com", Rows(s, "members").Select(m => m["member_name"]));
        Assert.DoesNotContain("Nobody Known", Rows(s, "people").Select(p => p["source_member"]));
        Assert.Equal(400, Post("/api/decide", @"{""items"": [], ""decision"": ""include""}").Status);
    }
}
