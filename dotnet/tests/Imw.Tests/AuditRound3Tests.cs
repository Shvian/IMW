using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Imw.Adapters;

namespace Imw.Tests;

// Port of tests/test_audit_round3.py

static class R3
{
    public const string CfgJson = @"{""default_platform"": ""WinServerLocal"", ""safe_defaults"": {""numberOfDaysRetention"": 7, ""description"": ""Rules""}}";
    public static readonly string AppJs = Path.Combine(TestBase.Root, "imw", "ui", "static", "app.js");

    public static SourceRecord Rec(string sid, params string[] folder)
    {
        var r = new SourceRecord("t", "f", sid, sid)
        {
            Name = sid, Folder = folder.ToList(), Type = "Windows", Address = "h1", Username = "u" + sid, Secret = "x",
        };
        r.Grants = new List<Grant> { new("CORP\\Ops", "View") };
        return r;
    }

    public static Dictionary<string, JObj> Ov(string json) =>
        TestBase.J(json).ToDictionary(kv => kv.Key, kv => (JObj)kv.Value, StringComparer.Ordinal);
}

public class MemberCheckMatchesServer
{
    [Fact]
    public void NoInvisibleCharactersInSource()
    {
        var unsafeText = new Regex(PyRe.Translate(Transform.UnsafeText));
        foreach (var path in Directory.GetFiles(Path.GetDirectoryName(R3.AppJs), "*.*"))
            Assert.False(unsafeText.IsMatch(File.ReadAllText(path).Replace("\n", "").Replace("\t", "")), path);
    }

    [Fact]
    public void NameChecksUseTheServerList()
    {
        var line = File.ReadAllLines(R3.AppJs).First(x => x.StartsWith("const INVISIBLE ="));
        var js = new Regex(Regex.Match(line, @"/(\[.*?\])/").Groups[1].Value);
        var server = new Regex(PyRe.Translate(Transform.UnsafeLine));
        for (int c = 0; c <= 0xFFFF; c++)
        {
            var s = ((char)c).ToString();
            Assert.True(js.IsMatch(s) == server.IsMatch(s), $"U+{c:X4}");
        }
    }
}

public class CleanSafeSettingsTests
{
    [Fact]
    public void CleanLine()
    {
        Assert.Equal("abc", Transform.CleanLine(" a\u200b\tb\r\nc\u2028\ufeff "));
        Assert.Equal(5L, Transform.CleanLineObj(5L));
    }

    [Fact]
    public void SafeSettingsStripControlCharacters()
    {
        var cfg = TestBase.Cfg(@"{""default_platform"": ""WinServerLocal"", ""safe_defaults"": {""description"": ""Line1\r\nLine2\u200b"", ""location"": ""\\Win\u0007"", ""managingCPM"": ""CPM\t1""}}");
        var plan = Transform.BuildPlan(new[] { R3.Rec("1", "Apps") }, cfg);
        var name = plan.Safes.Keys.First();
        var body = Transform.SafeSettings(name, plan.Safes[name], cfg);
        Assert.Equal(("Line1Line2", "\\Win", "CPM1"), ((string)body["description"], (string)body["location"], (string)body["managingCPM"]));
    }
}

public class MergedSafeSettings
{
    static (JObj, string, string) Names()
    {
        var cfg = TestBase.Cfg(R3.CfgJson);
        var plan = Transform.BuildPlan(new[] { R3.Rec("1", "Apps"), R3.Rec("2", "Web") }, cfg);
        var a = plan.Accounts.First(p => p.Rec.Folder.SequenceEqual(new[] { "Apps" })).Safe;
        var b = plan.Accounts.First(p => p.Rec.Folder.SequenceEqual(new[] { "Web" })).Safe;
        return (cfg, a, b);
    }

    [Fact]
    public void MergeTargetKeepsItsOwnSettings()
    {
        var (cfg, a, b) = Names();
        var ov = new Dictionary<string, JObj> { [a.ToLowerInvariant()] = Json.O(("key", a.ToLowerInvariant()), ("new_name", b), ("description", "From A")) };
        var plan = Transform.BuildPlan(new[] { R3.Rec("1", "Apps"), R3.Rec("2", "Web") }, cfg, safeOverrides: ov);
        Assert.Equal(new[] { b }, plan.Safes.Keys);
        Assert.Null(plan.Safes[b].Override);
        Assert.Equal("Rules", Transform.SafeSettings(b, plan.Safes[b], cfg)["description"]);
        ov[b.ToLowerInvariant()] = Json.O(("key", b.ToLowerInvariant()), ("description", "B's own"));
        plan = Transform.BuildPlan(new[] { R3.Rec("1", "Apps"), R3.Rec("2", "Web") }, cfg, safeOverrides: ov);
        Assert.Equal(b.ToLowerInvariant(), plan.Safes[b].Override["key"]);
        Assert.Equal("B's own", Transform.SafeSettings(b, plan.Safes[b], cfg)["description"]);
    }

    [Fact]
    public void RenameToANewNameKeepsTheSettings()
    {
        var (cfg, a, _) = Names();
        var ov = new Dictionary<string, JObj> { [a.ToLowerInvariant()] = Json.O(("key", a.ToLowerInvariant()), ("new_name", "MY-NEW"), ("description", "From A")) };
        var plan = Transform.BuildPlan(new[] { R3.Rec("1", "Apps"), R3.Rec("2", "Web") }, cfg, safeOverrides: ov);
        Assert.Equal("From A", Transform.SafeSettings("MY-NEW", plan.Safes["MY-NEW"], cfg)["description"]);
    }
}

public class MemberEditsFollowRenames : TestBase
{
    readonly Store st;
    readonly string a, b;

    public MemberEditsFollowRenames()
    {
        var db = T("m.db");
        var (rc, text) = RunCli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", S("delinea_export.csv"), "-p", S("delinea_permissions.csv"));
        Assert.True(rc == 0, text);
        (rc, text) = RunCli("map", "--db", db, "-c", S("config_delinea.json"));
        Assert.True(rc == 0, text);
        st = new Store(db);
        var names = st.Db.Query("SELECT safe_name FROM plan_safes WHERE accounts_to_upload > 0 ORDER BY safe_name LIMIT 2").Select(r => (string)r[0]).ToList();
        (a, b) = (names[0], names[1]);
    }

    public override void Dispose()
    {
        st.Close();
        base.Dispose();
    }

    List<string> Edits(string safe) =>
        st.Db.Query("SELECT member_name FROM member_edits WHERE lower(safe_name) = lower(?)", safe).Select(r => (string)r[0]).OrderBy(x => x, StringComparer.Ordinal).ToList();

    void Stamp(string safe, string member, string when)
    {
        st.Db.Execute("UPDATE member_edits SET changed_utc = ? WHERE safe_name = ? AND member_name = ?", when, safe, member);
        st.Db.Commit();
    }

    [Fact]
    public void MergeAndUndoKeepEachSafesOwnChanges()
    {
        st.SetMemberEdits(new() { a }, "pam-auditors", "add", role: "Read only");
        st.SetMemberEdits(new() { a }, "A-Only", "add", role: "Read only");
        st.SetMemberEdits(new() { b }, "PAM-Auditors", "add", role: "Full");
        st.SetMemberEdits(new() { b }, "B-Only", "add", role: "Read only");
        Stamp(a, "pam-auditors", "2026-01-01T00:00:00Z");
        Stamp(b, "PAM-Auditors", "2026-02-01T00:00:00Z");
        // A renamed into B: one change per member (ignoring case), the newer one wins
        st.SetSafeOverride(a, Json.O(("new_name", b)), oldName: a, newName: b);
        st.Map(st.StoredConfig());
        Assert.Equal(new[] { "A-Only", "B-Only", "PAM-Auditors" }, Edits(b));
        Assert.Empty(Edits(a));
        Assert.Equal("Full", st.Db.Scalar("SELECT role FROM member_edits WHERE member_name = 'PAM-Auditors'"));
        // Undo on A moves back only what came with A
        st.SetSafeOverride(a, new JObj(), undo: true, oldName: b, newName: a);
        st.Map(st.StoredConfig());
        Assert.Equal(new[] { "A-Only" }, Edits(a));
        Assert.Equal(new[] { "B-Only", "PAM-Auditors" }, Edits(b));
    }

    [Fact]
    public void CaseVariantCollisionLeavesOneRow()
    {
        st.SetMemberEdits(new() { a }, "pam-auditors", "add", role: "Full");
        st.SetMemberEdits(new() { b }, "PAM-Auditors", "add", role: "Read only");
        Stamp(a, "pam-auditors", "2026-03-01T00:00:00Z");
        Stamp(b, "PAM-Auditors", "2026-02-01T00:00:00Z");
        st.SetSafeOverride(a, Json.O(("new_name", b)), oldName: a, newName: b);
        var rows = st.Db.Query("SELECT member_name, role FROM member_edits WHERE lower(safe_name) = lower(?)", b);
        Assert.Equal(new[] { ("pam-auditors", "Full") }, rows.Select(r => ((string)r[0], (string)r[1])));
    }

    [Fact]
    public void PlainRenameAndUndoMoveEverything()
    {
        st.SetMemberEdits(new() { a }, "X1", "add", role: "Read only");
        st.SetSafeOverride(a, Json.O(("new_name", "MY-SAFE")), oldName: a, newName: "MY-SAFE");
        st.Map(st.StoredConfig());
        st.SetMemberEdits(new() { "MY-SAFE" }, "X2", "add", role: "Read only");      // made after the rename
        st.SetSafeOverride(a, new JObj(), undo: true, oldName: "MY-SAFE", newName: a);
        Assert.Equal(new[] { "X1", "X2" }, Edits(a));
    }

    [Fact]
    public void SettingsChangeKeepsTheMovedList()
    {
        st.SetMemberEdits(new() { a }, "A-Only", "add", role: "Read only");
        st.SetSafeOverride(a, Json.O(("new_name", b)), oldName: a, newName: b);
        st.Map(st.StoredConfig());
        st.SetSafeOverride(a, Json.O(("new_name", b), ("description", "x")), oldName: b, newName: b);
        Assert.Equal(new object[] { "A-Only" }, st.SafeOverrides()[a.ToLowerInvariant()].List("moved_edits"));
        st.SetSafeOverride(a, new JObj(), undo: true, oldName: b, newName: a);
        Assert.Equal(new[] { "A-Only" }, Edits(a));
    }
}

public class TypedNamesAreCleaned
{
    [Fact]
    public void SafeNames() => Assert.Equal("APPS", Transform.SanitizeSafeName("AP\u200bPS\u007f\u2060", TestBase.Cfg(R3.CfgJson)).Name);

    [Fact]
    public void AccountNamePlatformAndMemberEdits()
    {
        var cfg = TestBase.Cfg(R3.CfgJson);
        var r = R3.Rec("1", "Apps");
        var r2 = R3.Rec("2", "Apps");
        var rid = r.RecordId;
        var plan = Transform.BuildPlan(new[] { r, r2 }, cfg,
            overrides: new() { [rid] = new Dictionary<string, string> { ["Account_Name"] = "web\u200b01\u007f", ["Platform_ID"] = "Win\ufeffLocal" } },
            @explicit: true,
            memberEdits: new List<JObj> { Json.O(("safe_name", "APPS"), ("member_name", "PAM\u200b-Ops"), ("action", "add"), ("search_in", "corp\u2060"), ("role", "Read only"), ("reason", "")) },
            memberOverrides: new() { ["corp\\ops"] = Json.O(("member_name", "Ops\u200e"), ("search_in", "dir\u007f")) });
        var p = plan.Accounts.First(x => x.Rec.RecordId == rid);
        Assert.Equal(("web01", "WinLocal"), (p.AccountName, p.Platform));
        Assert.Contains("invisible or control characters removed from the account name", p.Warnings);
        var names = plan.Members.Values.Select(m => (m.MemberName, m.SearchIn)).ToHashSet();
        Assert.Contains(("PAM-Ops", "corp"), names);
        Assert.Contains(("Ops", "dir"), names);
    }
}

public class BrokenFilesGiveMessages : TestBase
{
    [Fact]
    public void BadXlsx()
    {
        var bad = T("bad.xlsx");
        File.WriteAllBytes(bad, Encoding.ASCII.GetBytes("not a zip at all"));
        Assert.Contains("not a readable Excel workbook", Assert.ThrowsAny<ValueError>(() => Xlsx.ReadRows(bad)).Message);
        Assert.Contains("not a readable Excel workbook", Assert.ThrowsAny<ValueError>(() => Xlsx.SheetNames(bad)).Message);
    }

    [Fact]
    public void XlsxWithMissingSheetRelationship()
    {
        var bad = T("norel.xlsx");
        using (var zin = ZipFile.OpenRead(S("accounts_by_group.xlsx")))
        using (var zout = ZipFile.Open(bad, ZipArchiveMode.Create))
            foreach (var item in zin.Entries)
            {
                using var s = item.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                var data = ms.ToArray();
                if (item.FullName == "xl/_rels/workbook.xml.rels")
                    data = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(data).Replace("Id=\"rId1\"", "Id=\"rIdGone\""));
                using var o = zout.CreateEntry(item.FullName).Open();
                o.Write(data);
            }
        Assert.Contains("the workbook does not list", Assert.ThrowsAny<ValueError>(() => Xlsx.ReadRows(bad)).Message);
    }

    [Fact]
    public void CsvErrorsBecomeValueErrors()
    {
        var nul = T("nul.csv");
        File.WriteAllBytes(nul, Encoding.ASCII.GetBytes("Secret Name,Username,Password\n\"a\u0000b\",u,\"unterminated\n"));
        var cfg = Cfg(R3.CfgJson);
        Csv.FieldLimit = 10;
        try
        {
            foreach (var reader in new Action[]
                     {
                         () => new DelineaAdapter().Read(nul, cfg),
                         () => new TableAdapter().Read(nul, cfg),
                         () => new KeePassAdapter().Read(nul, cfg),
                         () => _ = new Permissions(nul),
                         () => Transform.LoadOverrides(nul),
                     })
            {
                var exc = Record.Exception(reader);
                Assert.NotNull(exc);
                Assert.True(exc is ValueError or AdapterError, exc.GetType().Name);
                Assert.Contains("not a readable CSV file", exc.Message);
            }
        }
        finally { Csv.FieldLimit = 64 * 1024 * 1024; }
    }

    [Fact]
    public void LongFieldsAreFine()
    {
        var big = T("big.csv");
        var key = new string('A', 300_000);
        WriteText(big, $"Secret Name,Folder Path,Username,Password,Notes\nweb,\\IT,admin,pw,\"{key}\"\n");
        Assert.Equal(300_000, new DelineaAdapter().Read(big, Cfg(R3.CfgJson))[0].Extra["Notes"].Length);
    }

    [Fact]
    public void CliReportsInsteadOfCrashing()
    {
        var bad = T("bad.xlsx");
        File.WriteAllBytes(bad, Encoding.ASCII.GetBytes("PK broken"));
        Assert.Equal(2, RunCli("convert", "-i", bad, "-o", T("o"), "--force").Item1);
    }
}

public class SecretsStayOutOfReviewFiles : TestBase
{
    (string, string) ReviewText(string src, params string[] extra)
    {
        var cfg = T("cfg.json");
        WriteText(cfg, "{\"default_platform\": \"WinServerLocal\"}");
        var out_ = ConvertOne(src, cfg, extra);
        // SafeNamingConvention.csv is the naming rules in words, not record data.
        var text = string.Concat(Directory.GetFiles(Path.Combine(out_, "review"), "*.csv")
            .Where(f => Path.GetFileName(f) != "SafeNamingConvention.csv").Select(ReadText));
        return (text, out_);
    }

    [Fact]
    public void SecretLikeColumns()
    {
        var src = T("aws.csv");
        WriteText(src, "Secret Name,Folder Path,Username,Password,Secret Key,Client Secret,API Key,Token,Security Answer,Secret Template,Notes\n" +
                       "aws,\\Cloud,svc,pw1,SKVALUE1,CSVALUE2,AKVALUE3,TKVALUE4,ANSVALUE5,Amazon IAM Key,fine\n");
        var (text, _) = ReviewText(src);
        foreach (var v in new[] { "SKVALUE1", "CSVALUE2", "AKVALUE3", "TKVALUE4", "ANSVALUE5", "pw1" }) Assert.DoesNotContain(v, text);
        Assert.Contains("Amazon IAM Key", text);                    // Secret Template is not a secret
        Assert.Contains("secret field 'Secret Key' is not migrated", text);
    }

    [Fact]
    public void KeepassProtectedFields()
    {
        var src = T("kp.xml");
        WriteText(src, @"<?xml version=""1.0"" encoding=""utf-8""?><KeePassFile><Meta/><Root><Group><Name>Root</Name>
          <Entry><UUID>u1</UUID>
            <String><Key>Title</Key><Value>db</Value></String>
            <String><Key>UserName</Key><Value>sa</Value></String>
            <String><Key>Password</Key><Value ProtectInMemory=""True"">PWVALUE</Value></String>
            <String><Key>Vendor code</Key><Value ProtectInMemory=""True"">PROTVALUE1</Value></String>
            <String><Key>Recovery</Key><Value Protected=""True"">PROTVALUE2</Value></String>
            <String><Key>Port</Key><Value>1433</Value></String>
          </Entry></Group></Root></KeePassFile>");
        var (text, _) = ReviewText(src);
        foreach (var v in new[] { "PWVALUE", "PROTVALUE1", "PROTVALUE2" }) Assert.DoesNotContain(v, text);
        Assert.Contains("1433", text);
    }

    [Fact]
    public void ShiftedRowsAreErrorsWithoutSecretPieces()
    {
        var src = T("shift.csv");
        WriteText(src, "Secret Name,Folder Path,Username,Password,Notes,Machine\nweb,\\IT,admin,pa,ss,word,srv1\nok,\\IT,admin2,fine,n,srv2\n");
        var (text, out_) = ReviewText(src);
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        var bad = rows.First(r => r["Username"] == "admin");
        Assert.Equal("ERROR", bad["Status"]);
        Assert.Contains("more values than the header", bad["Notes"]);
        Assert.DoesNotContain(",ss,", text);
        Assert.DoesNotContain("word", text.Replace("password", "").Replace("Password", ""));
        var good = rows.First(r => r["Username"] == "admin2");
        Assert.NotEqual("ERROR", good["Status"]);
        Assert.DoesNotContain("srv1", rows.Select(r => r["Address"]));
        Assert.Equal(new[] { "admin2" }, ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).Select(a => a["userName"]));
    }

    [Fact]
    public void KeepassCsvAndTableCsvShifted()
    {
        var kp = T("kp.csv");
        WriteText(kp, "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\"Root/A\",\"t\",\"u\",\"p1\",\"p2\",\"h.example\",\"x\"\n");
        var recs = new KeePassAdapter().Read(kp, Cfg(R3.CfgJson));
        Assert.Contains(recs[0].Notes, n => n.Contains("more values than the header"));
        Assert.DoesNotContain("p2", recs[0].Extra.Select(kv => kv.Value).Append(recs[0].Address));
        var tb = T("t.csv");
        WriteText(tb, "Hostname,Login,Password,Notes\nh1,u1,p1,p2,note\n");
        recs = new TableAdapter().Read(tb, Cfg(R3.CfgJson));
        Assert.Contains(recs[0].Notes, n => n.Contains("more values than the header"));
        Assert.DoesNotContain("p2", recs[0].Extra.Select(kv => kv.Value));
    }
}

public class RenameJoinsSafeWhateverTheCase
{
    [Fact]
    public void Case()
    {
        var cfg = TestBase.Cfg(R3.CfgJson);
        SourceRecord[] Recs() => new[] { R3.Rec("1", "Apps"), R3.Rec("2", "Web") };
        var p = Transform.BuildPlan(Recs(), cfg, safeOverrides: R3.Ov(@"{""apps"": {""new_name"": ""web""}}"));
        Assert.Equal(new[] { "WEB" }, p.Safes.Keys);
        p = Transform.BuildPlan(Recs(), cfg, safeOverrides: R3.Ov(@"{""apps"": {""new_name"": ""new""}, ""web"": {""new_name"": ""NEW""}}"));
        Assert.Equal(1, p.Safes.Count);
    }
}
