using System.Text;
using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_ui.py

public class UiServerTests : UiTestBase
{
    static string Text(object body) => body is byte[] b ? Encoding.UTF8.GetString(b) : Json.Dumps(body);

    [Fact]
    public void HintsAndColumnPicker()
    {
        Login();
        WriteText(WsPath("inbox", "inventory.csv"), "Title,SAMAccountName,TargetHost,Port\nWeb admin,svc_web,web01,8443\n");
        var (st, r) = Post("/api/ingest", @"{""files"": [{""name"": ""inventory.csv"", ""source"": ""table""}]}");
        Assert.True(st == 200, Json.Dumps(r));
        var cols = Rows(r, "results")[0].Obj("columns");
        Assert.Equal(new object[] { "username", "address" }, cols.List("missing"));
        Assert.Contains("SAMAccountName", cols.List("headers"));
        var (_, c) = Get("/api/config");
        Assert.Contains(c.Obj("hints").List("columns"), x => Py.Eq(x, J(@"{""name"": ""Port"", ""records"": 1, ""filled"": 1}")));
        var ids = c.Obj("hints").List("platforms").Cast<JObj>().Select(p => p["id"]).ToList();
        Assert.Contains("WinDomain", ids);
        Assert.Contains("PaloAltoNetworks", ids);
        var sources = c.Obj("config").Obj("sources");
        sources.Obj("table")["columns"] = J(@"{""username"": ""SAMAccountName"", ""address"": ""TargetHost""}");
        Assert.Equal(200, Post("/api/config", Json.O(("patch", Json.O(("sources", sources))))).Status);
        (_, r) = Post("/api/ingest", @"{""files"": [{""name"": ""inventory.csv"", ""source"": ""table""}]}");
        Assert.False(Rows(r, "results")[0].ContainsKey("columns"));
    }

    [Fact]
    public void HttpsOnly()
    {
        var (st, _, resp) = Req("GET", $"/?t={Token}");
        Assert.Equal(303, st);
        var setCookie = resp.Headers.GetValues("Set-Cookie").First();
        Assert.Contains("Secure", setCookie);
        Assert.Contains("HttpOnly", setCookie);
        using (var plain = Client("http"))
        {
            Assert.ThrowsAny<Exception>(() => plain.Send(new HttpRequestMessage(HttpMethod.Get, "/api/session")).Content.ReadAsByteArrayAsync().Result);
        }
        Assert.Equal(200, Get("/api/session").Status);                         // server still fine afterwards
    }

    [Fact]
    public void OtherWindowsUsersAreRefused()
    {
        App.PeerCheck = (_, _, _, _) => false;
        var (st, body, _) = Req("GET", $"/?t={Token}");
        Assert.Equal(403, st);
        Assert.Contains("Connections from other Windows users are refused", Text(body));
        App.PeerCheck = (_, _, _, _) => throw new IOException("table failed");
        Assert.Equal(403, Get("/api/session").Status);                         // can't confirm: refused
        App.PeerCheck = (_, _, _, _) => true;
        Assert.Equal(303, Req("GET", $"/?t={Token}").Status);
    }

    [Fact]
    public void SignInAndLock()
    {
        Login(unlock: false);
        var (_, s) = Get("/api/session");
        Assert.Equal(true, s["locked"]);
        Assert.Equal(423, Get("/api/state").Status);                           // locked until sign-in
        Assert.Equal(400, Post("/api/unlock", @"{""password"": ""nope""}").Status);
        Assert.Equal(200, Post("/api/unlock", Json.O(("password", Password))).Status);
        Assert.Equal(200, Get("/api/state").Status);
        Assert.Equal(200, Post("/api/lock", "{}").Status);
        Assert.Equal(423, Get("/api/state").Status);
        Post("/api/unlock", Json.O(("password", Password)));
        var real = UiApp.Now();
        UiApp.Clock = () => real + 11 * 60;                                     // idle for 11 minutes
        Assert.Equal(423, Get("/api/state").Status);
        UiApp.Clock = null;
        for (int i = 0; i < UiApp.MaxFailures; i++) Post("/api/unlock", @"{""password"": ""nope""}");
        Assert.Equal(429, Post("/api/unlock", Json.O(("password", Password))).Status);   // slowed down
    }

    [Fact]
    public void EndSessionCanDeleteDatabase()
    {
        Login();
        Post("/api/ingest", @"{""files"": [{""name"": ""keepass_export.xml"", ""source"": """"}]}");
        Assert.True(File.Exists(WsPath("migration.db")));
        Assert.Equal(400, Post("/api/end", @"{""confirm"": ""end""}").Status);
        Assert.Equal(400, Post("/api/end", @"{""confirm"": ""END SESSION"", ""delete_db"": true}").Status);   // needs DELETE DB
        var (st, r) = Post("/api/end", @"{""confirm"": ""DELETE DB"", ""delete_db"": true}");
        Assert.Equal((200, (object)true), (st, r["database_deleted"]));
        Assert.False(File.Exists(WsPath("migration.db")));
        Ended = true;
    }

    [Fact]
    public void Guards()
    {
        Assert.Equal(401, Get("/api/state").Status);
        Assert.Equal(403, Req("GET", $"/?t={Token}", host: "evil.example").Status);
        Login();
        Assert.Equal(200, Req("GET", $"/?t={Token}").Status);                 // token is one-time; cookie works
        Assert.Equal(200, Get("/api/state").Status);
        Assert.Equal(403, Api("POST", "/api/ingest", new JObj(), new() { ["X-IMW"] = "" }).Status);
        Assert.Equal(403, Api("POST", "/api/ingest", new JObj(), new() { ["Origin"] = "http://evil.example" }).Status);
        Assert.Equal(403, Api("POST", "/api/ingest", new JObj(), new() { ["Origin"] = $"http://127.0.0.1:{Port}" }).Status);  // the http:// twin
        Assert.Equal(400, Post("/api/inbox/delete", @"{""name"": ""../x""}").Status);
        Cookie = "imw_sid=forged";
        Assert.Equal(401, Get("/api/state").Status);
    }

    [Fact]
    public void Flow()
    {
        Login();
        var (st, r) = IngestSamples("delinea_export.csv", "keepass_export.xml");
        Assert.True(st == 200, Json.Dumps(r));
        Assert.Equal(new object[] { 8L, 4L }, Rows(r, "results").Select(x => x["records"]));
        Post("/api/ingest", @"{""files"": [{""name"": ""keepass_export.xml"", ""source"": """"}]}");
        var (_, state) = Get("/api/state");
        var inputs = Rows(state, "inputs");
        Assert.Equal(64, ((string)inputs[0]["sha256"]).Length);
        Assert.Contains("same content as load #2", (string)inputs[2]["repeat"]);
        (st, r) = Post("/api/config", @"{""patch"": {""default_platform"": ""WinServerLocal""}}");
        Assert.True(st == 200, Json.Dumps(r));
        var saved = Json.ParseObj(File.ReadAllText(WsPath("config.json")));
        Assert.True(Py.Eq(Json.O(("default_platform", "WinServerLocal"), ("config_version", (long)Config.ConfigVersion)), saved));
        Assert.Equal(400, Post("/api/config", @"{""patch"": {""safe_rules"": [{""safe_pattern"": ""("", ""managingCPM"": ""x""}]}}").Status);

        var (_, cfg) = Get("/api/config");
        Assert.Contains("Web Password", cfg.Obj("hints").List("types").Cast<JObj>().Select(t => t["name"]));
        const string user = @"""group_rules"": [{""group"": ""CORP\\DBA-Team"", ""safe"": ""DB-Prod""}], ""fallback_strategy"": ""folder_path""";
        Assert.Equal(200, Post("/api/config", "{\"config\": {" + user + "}}").Status);
        Assert.Equal(400, Post("/api/config", @"{""config"": {""group_rules"": [{""safe"": ""X""}]}}").Status);
        saved = Json.ParseObj(File.ReadAllText(WsPath("config.json")));
        Assert.Equal(new HashSet<string> { "group_rules", "fallback_strategy", "config_version" }, saved.Keys.ToHashSet());   // only changes kept
        foreach (var bad in new[]
                 {
                     @"""custom_roles"": {""Full"": [""listAccounts""]}",
                     @"""custom_roles"": {""X"": [""listAccounts"", ""requestsAuthorizationLevel1"", ""requestsAuthorizationLevel2""]}",
                     @"""permission_map"": {""View"": ""Nobody""}",
                 })
            Assert.Equal(400, Post("/api/config", "{\"config\": {" + user + ", " + bad + "}}").Status);
        Assert.Equal(200, Post("/api/config", "{\"config\": {" + user + "}}").Status);

        var (_, d) = Post("/api/accounts", @"{""view"": ""all"", ""filters"": {""search"": ""svc_sql""}}");
        Assert.Equal(1L, d["total"]);
        Assert.Equal("DB-Prod", Rows(d)[0]["target_safe"]);
        (_, d) = Post("/api/accounts", @"{""view"": ""errors""}");
        Assert.Equal(1L, d["total"]);
        Assert.Equal(400, Post("/api/accounts", @"{""view"": ""nope""}").Status);
        Assert.Equal(200, Post("/api/accounts", @"{""view"": ""all"", ""sort"": ""secret_enc; DROP TABLE records""}").Status);   // unknown sort ignored

        (st, r) = Post("/api/edit", @"{""view"": ""errors"", ""values"": {""migrate"": ""N""}, ""reason"": ""t""}");
        Assert.Equal((200, (object)1L), (st, r["changed"]));
        Assert.Equal(200, Post("/api/edit", @"{""ids"": [""delinea:delinea_export:107""], ""values"": {""target_safe"": ""FIN:Portals""}}").Status);
        Assert.Equal(400, Post("/api/edit", @"{""ids"": [""x""], ""values"": {""secret_enc"": ""x""}}").Status);
        var (_, rec) = Post("/api/record", @"{""id"": ""delinea:delinea_export:101""}");
        Assert.False(rec.ContainsKey("secret_enc"));
        Assert.DoesNotContain("P@ssw0rd", Json.Dumps(rec));

        Assert.Equal(400, Post("/api/extract", @"{""name"": ""w1"", ""include_secrets"": true}").Status);   // needs typed confirmation
        (st, r) = Post("/api/extract", @"{""name"": ""w1"", ""include_secrets"": true, ""confirm"": ""INCLUDE SECRETS"",
                                         ""scope"": ""filter"", ""view"": ""all"", ""filters"": {""source"": ""delinea""}}");
        Assert.True(st == 200, Json.Dumps(r));
        var accounts = ReadCsv(WsPath("output", "w1", "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.Equal("FIN-Portals", accounts["Vendor Portal"]["SafeName"]);
        Assert.Equal("P@ssw0rd!1", accounts["svc_sql_prod"]["Secret"]);
        Assert.Equal(200, Post("/api/output/delete", @"{""name"": ""w1"", ""what"": ""upload""}").Status);
        Assert.False(Directory.Exists(WsPath("output", "w1", "upload")));
        Assert.True(Directory.Exists(WsPath("output", "w1", "review")));

        Assert.Equal(200, Post("/api/inbox/delete", @"{""name"": ""delinea_export.csv""}").Status);
        Assert.False(File.Exists(WsPath("inbox", "delinea_export.csv")));
        var (_, a) = Get("/api/audit");
        Assert.Contains("extract", Rows(a, "audit").Select(x => x["action"]));
        Assert.Contains("extract", a.Obj("summary").List("by_action").Cast<JObj>().Select(x => x["action"]));
        var (st2, text, _) = Req("GET", "/api/export/audit.csv");
        Assert.Equal(200, st2);
        Assert.StartsWith("\uFEFFid,ts,user,host,action,detail", Text(text));
        (_, text, _) = Req("GET", "/api/export/edits.csv");
        Assert.StartsWith("\uFEFFrecord_id,field,value", Text(text));
    }

    [Fact]
    public void ApproveNeedsALookUntilItChanges()
    {
        Login();
        var (st, r) = IngestSamples("delinea_export.csv", "keepass_export.xml");
        Assert.True(st == 200, Json.Dumps(r));
        // Safe-level notes (no access groups, shared Safe, name shortened) are not account notes.
        var (_, d) = Post("/api/accounts", @"{""view"": ""all""}");
        foreach (var row in Rows(d))
            foreach (var bad in new[] { "no access groups", "Safe shared by", "Safe name" })
                Assert.DoesNotContain(bad, (row["notes"] as string) ?? "");
        (_, d) = Post("/api/accounts", @"{""view"": ""review""}");
        Assert.True((long)d["total"] > 0);
        var rid = (string)Rows(d)[0]["record_id"];
        var okId = (string)Rows(Post("/api/accounts", @"{""view"": ""all""}").Body).First(x => (string)x["status"] == "OK")["record_id"];
        (st, r) = Post("/api/approve", Json.O(("ids", Json.L(rid, okId)), ("reason", "checked")));
        Assert.Equal((200, (object)1L), (st, r["changed"]));                    // only "needs a look" can be approved
        Assert.Equal(1L, Get("/api/state").Body["approved"]);
        (_, d) = Post("/api/accounts", @"{""view"": ""approved""}");
        Assert.Equal(new object[] { rid }, Rows(d).Select(x => x["record_id"]));
        Assert.Equal("REVIEW", Rows(d)[0]["status"]);                           // still needs a look, with a tick
        (_, d) = Post("/api/accounts", @"{""view"": ""review_open""}");
        Assert.DoesNotContain(rid, Rows(d).Select(x => x["record_id"]));
        var (_, rec) = Post("/api/record", Json.O(("id", rid)));
        Assert.Equal("checked", rec.Obj("approval")["reason"]);
        // Applying the same rules again keeps the approval ...
        Assert.Equal(200, Post("/api/config", @"{""patch"": {}}").Status);
        Assert.Equal(1L, Get("/api/state").Body["approved"]);
        // ... a change to the account drops it.
        Post("/api/edit", Json.O(("ids", Json.L(rid)), ("values", Json.O(("account_name", "Changed-Name")))));
        Assert.Equal(0L, Get("/api/state").Body["approved"]);
        Assert.Null(Post("/api/record", Json.O(("id", rid))).Body["approval"]);
        Assert.Contains("approval_cleared", Rows(Get("/api/audit").Body, "audit").Select(x => x["action"]));
        // Approve again, then take it back.
        Post("/api/approve", Json.O(("ids", Json.L(rid))));
        (_, r) = Post("/api/approve", Json.O(("ids", Json.L(rid)), ("approve", false)));
        Assert.Equal(1L, r["changed"]);
        Assert.Equal(0L, Get("/api/state").Body["approved"]);
    }

    [Fact]
    public void SafesPreviewShowsUnsavedSettings()
    {
        Login();
        IngestSamples("delinea_export.csv");
        var (_, cfgResp) = Get("/api/config");
        var user = cfgResp.Obj("config").Copy();
        var defaults = user.Obj("safe_defaults").Copy();
        defaults["managingCPM"] = "CPM-Preview";
        user["safe_defaults"] = defaults;
        user["safe_rules"] = new List<object> { J(@"{""safe_pattern"": ""DB"", ""managingCPM"": ""CPM-DB""}") };
        var (st, r) = Post("/api/safes/preview", Json.O(("config", user)));
        Assert.True(st == 200, Json.Dumps(r));
        Assert.Equal(8L, r["accounts"]);
        Assert.NotEmpty(Rows(r));
        foreach (var row in Rows(r))
        {
            Assert.Equal(Py.Lower((string)row["safe"]).Contains("db") ? "CPM-DB" : "CPM-Preview", row["cpm"]);
            Assert.Contains("cpm", row.List("changed"));                       // differs from what is saved
        }
        Assert.Contains("P@ssw0rd", File.ReadAllText(S("delinea_export.csv")));
        Assert.DoesNotContain("P@ssw0rd", Json.Dumps(r));
        Assert.DoesNotContain("CPM-Preview", Json.Dumps(Get("/api/safes").Body));   // nothing was saved
        var bad = user.Copy();
        bad["safe_rules"] = new List<object> { J(@"{""safe_pattern"": ""("", ""managingCPM"": ""x""}") };
        Assert.Equal(400, Post("/api/safes/preview", Json.O(("config", bad))).Status);
        // The other rules pages: a patch on top of the saved settings.
        (st, r) = Post("/api/rules/preview", @"{""kind"": ""members"", ""patch"": {""permission_map"": {""View"": ""Full"", ""Edit"": ""Full"", ""Owner"": ""Full"", ""List"": ""Full""}}}");
        Assert.True(st == 200, Json.Dumps(r));
        Assert.NotEmpty(Rows(r));
        Assert.All(Rows(r), m => Assert.Equal("Full", m["role"]));
        Assert.Contains(Rows(r), m => m.List("changed").Contains("role"));
        (_, r) = Post("/api/rules/preview", @"{""kind"": ""platforms"", ""patch"": {""platform_rules"": [{""field"": ""type"", ""pattern"": ""."", ""platform"": ""OnePlatform""}]}}");
        Assert.Equal(new HashSet<object> { "OnePlatform" }, Rows(r).Select(x => x["platform"]).ToHashSet());
        Assert.All(Rows(r), x => Assert.Equal(new object[] { "platform" }, x.List("changed")));
        (_, r) = Post("/api/rules/preview", @"{""kind"": ""accounts"", ""patch"": {""account_name"": {""mode"": ""pattern"", ""template"": ""X-{username}"", ""fallback"": ""{address}""}}}");
        Assert.All(Rows(r), x => Assert.StartsWith("X-", (string)x["account_name"]));
        Assert.DoesNotContain("P@ssw0rd", Json.Dumps(r));
        Assert.Equal(400, Post("/api/rules/preview", @"{""kind"": ""nope"", ""patch"": {}}").Status);
    }

    [Fact]
    public void MembersPlatformsAndSanitizing()
    {
        var text = ReadText(S("delinea_export.csv"));
        int at = text.IndexOf("svc_sql", StringComparison.Ordinal);
        WriteText(WsPath("inbox", "delinea_export.csv"), text.Substring(0, at) + "svc\u200b_sql" + text.Substring(at + 7));
        Login();
        var (st, r) = IngestSamples("delinea_export.csv");
        Assert.True(st == 200, Json.Dumps(r));
        Assert.Equal(1L, Rows(r, "results")[0]["sanitized"]);
        var (_, d) = Post("/api/accounts", @"{""view"": ""sanitized""}");
        Assert.Equal(1L, d["total"]);
        Assert.Equal("svc_sql_prod", Rows(d)[0]["username"]);

        var (_, s) = Get("/api/safes");
        var safes = Rows(s, "safes").Where(x => Py.Truthy(x["accounts_to_upload"])).Select(x => (string)x["safe_name"]).Take(2).ToList();
        Assert.Equal(2, safes.Count);
        (st, r) = Post("/api/members/edit", Json.O(("action", "add"), ("member_name", "PAM-Auditors"), ("safes", Json.L(safes[0], safes[1])),
            ("search_in", "corp.example.com"), ("member_type", "Group"), ("role", "Read only")));
        Assert.Equal((200, (object)2L), (st, r["changed"]));
        Assert.Equal(400, Post("/api/members/edit", Json.O(("action", "add"), ("member_name", "X"), ("safes", Json.L(safes[0], safes[1])), ("role", "nope"))).Status);
        (_, s) = Get("/api/safes");
        var added = Rows(s, "members").Where(m => (string)m["member_name"] == "PAM-Auditors").ToList();
        Assert.Equal(safes.OrderBy(x => x, StringComparer.Ordinal), added.Select(m => (string)m["safe_name"]).OrderBy(x => x, StringComparer.Ordinal));
        Assert.Equal(new HashSet<object> { "corp.example.com" }, added.Select(m => m["search_in"]).ToHashSet());
        var victim = Rows(s, "members").First(m => (string)m["safe_name"] == safes[0] && (string)m["member_name"] != "PAM-Auditors");
        var victimName = (string)victim["member_name"];
        (st, r) = Post("/api/members/edit", Json.O(("action", "remove"), ("pairs", Json.L(Json.L(safes[0], victimName)))));
        Assert.True(st == 200, Json.Dumps(r));
        (_, s) = Get("/api/safes");
        Assert.DoesNotContain((safes[0], victimName), Rows(s, "members").Select(m => ((string)m["safe_name"], (string)m["member_name"])));
        Assert.Equal(3, s.List("member_edits").Count);
        Post("/api/members/edit", Json.O(("action", "undo"), ("pairs", Json.L(Json.L(safes[0], victimName)))));
        (_, s) = Get("/api/safes");
        Assert.Contains((safes[0], victimName), Rows(s, "members").Select(m => ((string)m["safe_name"], (string)m["member_name"])));

        (_, d) = Post("/api/accounts", @"{""view"": ""all"", ""filters"": {""search"": ""svc_sql""}}");
        var rid = Rows(d)[0]["record_id"];
        (st, r) = Post("/api/edit", Json.O(("ids", Json.L(rid)), ("values", Json.O(("platform_id", "(none)")))));
        Assert.True(st == 200, Json.Dumps(r));
        (_, d) = Post("/api/accounts", @"{""view"": ""all"", ""filters"": {""search"": ""svc_sql""}}");
        Assert.Equal(("", "ERROR"), ((string)Rows(d)[0]["platform_id"], (string)Rows(d)[0]["status"]));
        Assert.Contains("no platform", (string)Rows(d)[0]["notes"]);
        Post("/api/edit", Json.O(("ids", Json.L(rid)), ("values", Json.O(("platform_id", "Win Server/Local")))));
        (_, d) = Post("/api/accounts", @"{""view"": ""all"", ""filters"": {""search"": ""svc_sql""}}");
        Assert.Equal("Win_Server_Local", Rows(d)[0]["platform_id"]);

        (st, r) = Post("/api/extract", @"{""name"": ""o1""}");
        Assert.True(st == 200, Json.Dumps(r));
        var up = WsPath("output", "o1", "upload");
        Assert.Contains(ReadCsv(Path.Combine(up, "FileCategories.csv")), c => c["column"] == "Address");
        Assert.NotEmpty(ReadCsv(Path.Combine(up, "PlatformProperties.csv")));
        Assert.Equal(2, ReadCsv(Path.Combine(up, "SafeMembers.csv")).Count(m => m["MemberName"] == "PAM-Auditors"));
    }

    [Fact]
    public void TypedValuesLoseInvisibleCharacters()
    {
        Login();
        var (st, r) = IngestSamples("delinea_export.csv");
        Assert.True(st == 200, Json.Dumps(r));
        var (_, s) = Get("/api/safes");
        var safe = (string)Rows(s, "safes").First(x => Py.Truthy(x["accounts_to_upload"]))["safe_name"];
        (st, r) = Post("/api/safes/change", Json.O(("key", safe), ("current", safe), ("settings", Json.O(
            ("description", "Line1\r\nLine2\u200b"), ("location", "\\Win\u0007"), ("managingCPM", "CPM\t1")))));
        Assert.Equal((200, (object)3L), (st, r["cleaned"]));
        (st, r) = Post("/api/members/edit", Json.O(("action", "add"), ("member_name", "PAM\u200b-Ops\n"), ("safes", Json.L(safe)),
            ("search_in", "corp\u2060"), ("role", "Read only")));
        Assert.Equal((200, (object)2L), (st, r["cleaned"]));
        (st, r) = Post("/api/config", Json.O(("patch", Json.O(("safe_defaults", Json.O(("description", "Def\u2028ault")))))));
        Assert.Equal((200, (object)1L), (st, r["cleaned"]));
        (_, s) = Get("/api/safes");
        var row = Rows(s, "safes").First(x => (string)x["safe_name"] == safe);
        Assert.Equal(("Line1Line2", "\\Win", "CPM1"), ((string)row["description"], (string)row["location"], (string)row["managing_cpm"]));
        var added = Rows(s, "members").Where(m => (string)m["member_name"] == "PAM-Ops").ToList();
        Assert.Equal(new[] { (safe, "corp") }, added.Select(m => ((string)m["safe_name"], (string)m["search_in"])));
        var key = Rows(s, "people").First(p => (string)p["member_name"] == "PAM-Ops")["key"];
        (st, r) = Post("/api/members/change", Json.O(("key", key), ("member_name", "PAM-Ops2\uFEFF"), ("search_in", "x\u200e")));
        Assert.Equal((200, (object)2L), (st, r["cleaned"]));
        var cfg = Json.ParseObj(File.ReadAllText(WsPath("config.json")));
        Assert.Equal("Default", cfg.Obj("safe_defaults")["description"]);
        // A damaged workbook or permissions file gives a message, not "Unexpected error"
        File.WriteAllBytes(WsPath("inbox", "broken.xlsx"), Encoding.ASCII.GetBytes("PK not really"));
        (st, r) = Post("/api/ingest", @"{""files"": [{""name"": ""broken.xlsx"", ""source"": """"}]}");
        Assert.True(st == 400, Json.Dumps(r));
        Assert.Contains("not a readable Excel workbook", (string)r["error"]);
        File.WriteAllBytes(WsPath("inbox", "perms.csv"), Encoding.ASCII.GetBytes("Group,Permission\n\"" + new string('x', 5000) + "\n"));
        Csv.FieldLimit = 1000;                    // stands in for a field over the 64 MB limit
        try { (st, r) = Post("/api/ingest", @"{""files"": [{""name"": ""delinea_export.csv"", ""source"": """"}], ""permissions"": [""perms.csv""]}"); }
        finally { Csv.FieldLimit = 64 * 1024 * 1024; }
        Assert.True(st == 400, Json.Dumps(r));
        Assert.Contains("not a readable CSV file", (string)r["error"]);
    }
}
