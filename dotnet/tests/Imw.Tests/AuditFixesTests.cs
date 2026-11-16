using System.IO.Compression;
using System.Text;
using Imw.Adapters;
using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_audit_fixes.py (the 2026-11-13 security and logic audit)

static class AuditHelpers
{
    public static SourceRecord Rec(string sid, string name = "", string address = "", string username = "u", string[] folder = null) =>
        new("t", "f", sid, sid)
        {
            Name = name, Folder = (folder ?? new[] { "IT" }).ToList(), Type = "Windows", Address = address, Username = username, Secret = "x",
        };
}

public class XmlAndXlsx : TestBase
{
    static readonly byte[] Bomb = Encoding.ASCII.GetBytes(
        "<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\">" +
        "<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><KeePassFile>&b;</KeePassFile>");
    const string Ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    [Fact]
    public void DtdIsRefused()
    {
        Assert.Throws<UnsafeXmlError>(() => SafeXml.FromBytes(Bomb));
        var f = T("bomb.xml");
        File.WriteAllBytes(f, Bomb);
        Assert.Throws<AdapterError>(() => new KeePassAdapter().Read(f, Cfg()));
    }

    [Fact]
    public void NormalKeepassStillReads() => Assert.NotEmpty(new KeePassAdapter().Read(S("keepass_export.xml"), Cfg()));

    string Sheet(string sheetXml)
    {
        var path = T("t.xlsx");
        XlsxWriter.Write(path, new[] { ("S", new List<object[]> { new object[] { "Name", "Username" }, new object[] { "a", "b" } }) });
        var parts = new List<(string, byte[])>();
        using (var z = ZipFile.OpenRead(path))
            foreach (var e in z.Entries)
            {
                using var s = e.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                parts.Add((e.FullName, e.FullName == "xl/worksheets/sheet1.xml" ? Encoding.UTF8.GetBytes(sheetXml) : ms.ToArray()));
            }
        File.Delete(path);
        using (var z = ZipFile.Open(path, ZipArchiveMode.Create))
            foreach (var (n, data) in parts)
            {
                using var s = z.CreateEntry(n).Open();
                s.Write(data);
            }
        return path;
    }

    [Fact]
    public void FarAwayEmptyCellDoesNotAllocate()
    {
        var path = Sheet($"<worksheet xmlns=\"{Ns}\"><sheetData>" +
                         "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>Name</t></is></c><c r=\"XFD1\" s=\"3\"/></row>" +
                         "<row r=\"2\"><c r=\"A2\" t=\"inlineStr\"><is><t>web01</t></is></c></row>" +
                         "<row r=\"1048576\"><c r=\"XFD1048576\" s=\"3\"/></row></sheetData></worksheet>");
        var (_, rows) = Xlsx.ReadRows(path);
        Assert.Equal(new[] { new[] { "Name" }, new[] { "web01" } }, rows.Select(r => r.ToArray()));
    }

    [Fact]
    public void GapRowsKeepTheirNumbers()
    {
        var path = T("g.xlsx");
        XlsxWriter.Write(path, new[] { ("S", new List<object[]> { new object[] { "H" }, Array.Empty<object>(), Array.Empty<object>(), new object[] { "x" } }) });
        var (_, rows) = Xlsx.ReadRows(path);
        Assert.Equal(new[] { new[] { "H" }, Array.Empty<string>(), Array.Empty<string>(), new[] { "x" } }, rows.Select(r => r.ToArray()));
    }

    [Fact]
    public void XlsxDtdAndOversizePartRefused()
    {
        var path = Sheet($"<!DOCTYPE x [<!ENTITY e \"y\">]><worksheet xmlns=\"{Ns}\"><sheetData/></worksheet>");
        Assert.ThrowsAny<ValueError>(() => Xlsx.ReadRows(path));
        path = Sheet($"<worksheet xmlns=\"{Ns}\"><sheetData/></worksheet>");
        var old = Xlsx.MaxPartBytes;
        Xlsx.MaxPartBytes = 10;
        try { Assert.Contains("unpacks to", Assert.ThrowsAny<ValueError>(() => Xlsx.ReadRows(path)).Message); }
        finally { Xlsx.MaxPartBytes = old; }
    }
}

public class FormulaInjection : TestBase
{
    [Fact]
    public void EscapeRoundtrip()
    {
        foreach (var v in new[] { "=1+1", "+x", "-y", "@SUM(A1)", "\tz", "\rz", "'=a", "''b" })
            Assert.Equal(v, CsvSafe.Unescape((string)CsvSafe.Escape(v)));
        Assert.Equal("'=cmd|' /C calc'!A0", CsvSafe.Escape("=cmd|' /C calc'!A0"));
        Assert.Equal("plain", CsvSafe.Escape("plain"));
        Assert.Equal("'quoted", CsvSafe.Escape("'quoted"));
        Assert.Equal(5L, CsvSafe.Escape(5L));
    }

    [Fact]
    public void ReviewEscapedUploadNot()
    {
        var src = T("in.csv");
        WriteCsv(src, new[] { "Name", "Address", "Username", "Password", "Folder", "Comment" },
                 new[] { new object[] { "=HYPERLINK(\"http://x\")", "@host", "-admin", "-Secret=1", "IT", "+evil" } }, bom: false);
        var cfg = T("cfg.json");
        WriteText(cfg, "{\"default_platform\": \"WinServerLocal\"}");
        var out_ = ConvertOne(src, cfg, "--include-secrets");
        var review = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"))[0];
        Assert.StartsWith("'=", review["Account_Name"]);
        Assert.Equal("'@host", review["Address"]);
        Assert.Equal("'-admin", review["Username"]);
        Assert.Equal("'+evil", review["Source.Comment"]);
        var acct = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"))[0];
        Assert.Equal("-admin", acct["UserName"]);          // API data is left exactly as it is
        Assert.Equal("-Secret=1", acct["Secret"]);
        Assert.Equal("@host", acct["Address"]);
        // Feeding the review file back is not seen as a change.
        var row = Transform.LoadOverrides(Path.Combine(out_, "review", "Accounts_Review.csv")).Values.First();
        Assert.Equal("-admin", row["Username"]);
        Assert.StartsWith("=", row["Account_Name"]);
    }

    [Fact]
    public void QueryCsvEscaped()
    {
        var db = T("m.db");
        var src = T("in.csv");
        WriteText(src, "Name,Address,Username,Password\n=1+1,h,u,p\n");
        var (rc, text) = RunCli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", src);
        Assert.True(rc == 0, text);
        var out_ = T("q.csv");
        (rc, text) = RunCli("query", "--db", db, "SELECT name FROM records", "--csv", out_);
        Assert.True(rc == 0, text);
        Assert.Equal("'=1+1", ReadCsv(out_)[0]["name"]);
    }
}

public class LikeSearch
{
    [Fact]
    public void WildcardsAreLiteral()
    {
        var (where, pars) = UiApp.BuildWhere(TestBase.J(@"{""filters"": {""search"": ""svc_1%""}}"));
        using var db = Db.Open(":memory:");
        db.Execute("CREATE TABLE t (account_name, username, address, folder, record_id, target_safe)");
        foreach (var n in new[] { "svc_1%x", "svcA1x", "svc_12" }) db.Execute("INSERT INTO t VALUES (?,?,?,?,?,?)", n, "", "", "", n, "");
        where = where.Replace($"({UiApp.Views["all"].Sql})", "1=1");
        var got = db.QueryList($"SELECT account_name FROM t WHERE {where}", pars).Select(r => r[0]).ToList();
        Assert.Equal(new object[] { "svc_1%x" }, got);
    }
}

public class EndSessionAndDelete : TestBase
{
    readonly UiApp app;

    public EndSessionAndDelete()
    {
        app = new UiApp(T("ws"), "plain", new TestAuth("pw")) { Sid = "s", Unlocked = true };
    }

    [Fact]
    public void SecureDeleteInChunks()
    {
        var f = T("big.bin");
        File.WriteAllBytes(f, Enumerable.Repeat((byte)0xff, 2500).ToArray());
        UiApp.SecureDelete(f, chunk: 1000);
        Assert.False(File.Exists(f));
    }

    [Fact]
    public void LockedFileStillEndsSession()
    {
        File.WriteAllBytes(app.DbPath, new byte[10]);
        JObj r;
        using (new FileStream(app.DbPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))     // "in use"
            r = (JObj)app.ApiEnd(J(@"{""confirm"": ""DELETE DB"", ""delete_db"": true}"));
        Assert.False(app.Unlocked);
        Assert.Null(app.Sid);
        Assert.Equal(false, r["database_deleted"]);
        Assert.Equal(new object[] { "migration.db" }, r.List("not_deleted"));
    }
}

public class TlsKeyStaysInWorkspace : TestBase
{
    [Fact]
    public void NoKeyFileOutsideTheTlsFolder()
    {
        // The .NET version loads the key in memory: nothing but the certificate and the protected key is written.
        var ws = T("ws");
        Tls.ServerCertificate(ws);
        Assert.Equal(new[] { "tls" }, Directory.GetFileSystemEntries(ws).Select(Path.GetFileName));
        Assert.Equal(2, Directory.GetFileSystemEntries(Path.Combine(ws, "tls")).Length);
    }
}

public class DuplicateIdPermissions : TestBase
{
    [Fact]
    public void RecordGrantsKeptForDuplicateId()
    {
        var permsCsv = T("perms.csv");
        WriteText(permsCsv, "Folder Path,Secret Name,Secret ID,Group,Permission\n,,42,CORP\\Ops,Owner\n");
        var perms = new Permissions(permsCsv);
        var src = T("src.csv");
        WriteText(src, "x");
        Dictionary<string, SourceRecord> recs;
        using (var st = new Store(T("m.db"), create: true, protector: "plain"))
        {
            st.Ingest("t", src, new List<SourceRecord> { AuditHelpers.Rec("42", "a"), AuditHelpers.Rec("42", "b") }, perms);
            recs = st.LoadRecords().ToDictionary(r => r.Name);
        }
        Assert.Equal("42#2", recs["b"].SourceId);
        foreach (var r in recs.Values)
        {
            Assert.Equal(new[] { "CORP\\Ops" }, r.Grants.Select(g => g.Member));
            Assert.Equal("record", r.AccessSource);
        }
    }

    [Fact]
    public void BuildPlanDuplicateId()
    {
        var permsCsv = T("perms.csv");
        WriteText(permsCsv, "Folder Path,Secret Name,Secret ID,Group,Permission\n,,42,CORP\\Ops,Owner\n");
        var plan = Transform.BuildPlan(new[] { AuditHelpers.Rec("42", "a"), AuditHelpers.Rec("42", "b") }, Cfg(), new Permissions(permsCsv));
        Assert.All(plan.Accounts, p => Assert.Equal(new[] { "CORP\\Ops" }, p.Grants.Select(g => g.Member)));
        Assert.Equal(2, plan.Accounts.Count);
    }
}

public class DuplicateIdsNotSuffixedTwice : TestBase
{
    [Fact]
    public void BuildPlanTwiceIsStable()
    {
        var cfg = Cfg();
        var records = new[] { AuditHelpers.Rec("42", "a"), AuditHelpers.Rec("42", "b"), AuditHelpers.Rec("42#2", "c"), AuditHelpers.Rec("42", "d") };
        var ids = Transform.BuildPlan(records, cfg).Accounts.Select(p => p.Rec.RecordId).ToList();
        Assert.Equal(4, ids.Distinct().Count());
        Assert.Equal(new[] { "42", "42#3", "42#2", "42#4" }, ids.Select(i => i.Split(':').Last()));
        Assert.Equal(ids, Transform.BuildPlan(records, cfg).Accounts.Select(p => p.Rec.RecordId));
    }

    [Fact]
    public void StoreRecordsNotResuffixed()
    {
        var src = T("src.csv");
        WriteText(src, "x");
        List<SourceRecord> loaded;
        using (var st = new Store(T("m.db"), create: true, protector: "plain"))
        {
            st.Ingest("t", src, new List<SourceRecord> { AuditHelpers.Rec("42", "a"), AuditHelpers.Rec("42", "b") });
            loaded = st.LoadRecords();
        }
        var plan = Transform.BuildPlan(loaded, Cfg());
        Assert.Equal(new[] { "42", "42#2" }, plan.Accounts.Select(p => p.Rec.SourceId).OrderBy(x => x, StringComparer.Ordinal));
        Assert.Equal(1, plan.Accounts.SelectMany(p => p.Warnings).Count(w => w.Contains("suffixed in Record_ID")));
    }
}

public class ReviewRoundTrip : TestBase
{
    [Fact]
    public void ImportReviewIgnoresAddedApostrophes()
    {
        var src = T("in.csv");
        WriteText(src, "Name,Address,Username,Password\n=calc,@h,-adm,-pw\n");
        var cfg = T("cfg.json");
        WriteText(cfg, "{\"default_platform\": \"WinServerLocal\"}");
        var db = T("m.db");
        Assert.Equal(0, RunCli("ingest", "--db", db, "--insecure-plaintext-secrets", "-i", src).Item1);
        Assert.Equal(0, RunCli("map", "--db", db, "-c", cfg).Item1);
        var out_ = T("x");
        Assert.Equal(0, RunCli("extract", "--db", db, "-o", out_, "--include-secrets").Item1);
        var review = Path.Combine(out_, "review", "Accounts_Review.csv");
        Assert.Equal("'=calc", ReadCsv(review)[0]["Account_Name"]);
        Assert.Equal("-pw", ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"))[0]["Secret"]);
        using var st = new Store(db);
        Assert.Equal(0, st.ImportReview(review));          // nothing changed, nothing imported
    }
}

public class AccountNames
{
    [Fact]
    public void UrlStrippedBeforeName()
    {
        var cfg = TestBase.Cfg(@"{""account_name"": {""template"": ""{address}-{username}""}}");
        var records = new[] { AuditHelpers.Rec("1", address: "https://fw01.example.com/login", username: "admin") };
        var first = Transform.BuildPlan(records, cfg).Accounts[0].AccountName;
        Assert.Equal("fw01.example.com-admin", first);
        Assert.Equal(first, Transform.BuildPlan(records, cfg).Accounts[0].AccountName);
    }

    [Fact]
    public void SuffixSkipsExistingNames()
    {
        var cfg = TestBase.Cfg(@"{""default_platform"": ""WinServerLocal""}");
        var plan = Transform.BuildPlan(new[] { AuditHelpers.Rec("1", "admin"), AuditHelpers.Rec("2", "admin"), AuditHelpers.Rec("3", "admin_2"), AuditHelpers.Rec("4", "admin") }, cfg);
        var names = plan.Accounts.Select(p => p.AccountName).ToList();
        Assert.Single(plan.Accounts.Select(p => p.Safe).Distinct());
        Assert.Equal(new[] { "admin", "admin_3", "admin_2", "admin_4" }, names);
        Assert.Equal(4, names.Select(n => n.ToLowerInvariant()).Distinct().Count());
    }
}

public class GroupColumnCase
{
    [Fact]
    public void HeaderCaseDoesNotMatter()
    {
        var row = new StrDict();
        row["Name"] = "a";
        row["Username"] = "u";
        row["Group"] = "CORP\\Ops";
        row["ROLE"] = "Owner";
        var r = Rows.RecordFromRow(row, TestBase.Cfg(), "table", "f", "r2", 1, groupColumn: "group", permissionColumn: "role");
        Assert.Equal(new[] { ("CORP\\Ops", "Owner") }, r.Grants.Select(g => (g.Member, g.Permission)));
    }
}

public class ConfigVersionKept
{
    [Fact]
    public void DiffKeepsVersion()
    {
        var diff = Config.ConfigDiff(TestBase.Cfg(@"{""default_platform"": ""X""}"));
        Assert.Equal((long)Config.ConfigVersion, diff["config_version"]);
        Assert.True(Py.Eq(Json.O(("config_version", (long)Config.ConfigVersion)), Config.ConfigDiff(Config.DefaultConfig())));
        Assert.True(Py.Eq(diff, Config.UpgradeConfig(diff)));           // current version: nothing to do
    }
}

public class AccessDeniedMessage : TestBase
{
    public override void Dispose()
    {
        Owner.ListHook = null;
        Owner.PathOwnerHook = null;
        base.Dispose();
    }

    [Fact]
    public void OwnFolderIsNotBlamedOnAnotherUser()
    {
        var ws = T("ws");
        Directory.CreateDirectory(ws);
        Owner.ListHook = p => throw new UnauthorizedAccessException($"Access to the path '{Path.Combine(p, ".owner")}' is denied.");
        Owner.PathOwnerHook = _ => Owner.CurrentIdentity().Sid;
        var msg = Assert.Throws<OwnerError>(() => Owner.ClaimWorkspace(ws)).Message;
        Assert.DoesNotContain("belongs to another Windows user", msg);
        Assert.Contains(".owner", msg);
        Assert.Contains("is denied", msg);
    }

    [Fact]
    public void OtherOwnerStillNamed()
    {
        var ws = T("ws");
        Directory.CreateDirectory(ws);
        Owner.ListHook = _ => throw new UnauthorizedAccessException("denied");
        Owner.PathOwnerHook = _ => "S-1-5-21-9";
        Assert.Contains("belongs to another Windows user", Assert.Throws<OwnerError>(() => Owner.ClaimWorkspace(ws)).Message);
    }
}

public class WindowsAclCommands : TestBase
{
    [Fact]
    public void FilesInheritInsteadOfGettingFolderFlags()
    {
        var ws = T("ws");
        Directory.CreateDirectory(ws);
        File.WriteAllText(Path.Combine(ws, ".owner"), "{}");
        var calls = new List<string[]>();
        Owner.ForceWindows = true;
        Owner.RunHook = (exe, args) => { calls.Add(new[] { exe }.Concat(args).ToArray()); return (0, ""); };
        try { Owner.Restrict(ws, "S-1-5-21-1", recursive: true); }
        finally
        {
            Owner.ForceWindows = null;
            Owner.RunHook = null;
        }
        Assert.Equal(2, calls.Count);
        Assert.DoesNotContain("/T", calls[0]);                            // (OI)(CI) grant on the folder only
        Assert.Contains("*S-1-5-21-1:(OI)(CI)F", calls[0]);
        Assert.Equal(new[] { Path.Combine(ws, "*"), "/reset", "/T" }, calls[1].Skip(1).Take(3));
    }
}

public class WindowsOnly
{
    [Fact]
    public void DpapiRoundtrip()
    {
        if (!OperatingSystem.IsWindows()) return;
        var p = new DpapiProtector(Encoding.ASCII.GetBytes("salt"));
        Assert.Equal("s3cret-\u00fc", p.Unprotect(p.Protect("s3cret-\u00fc", "r1"), "r1"));
    }

    [Fact]
    public void PathOwner()
    {
        if (!OperatingSystem.IsWindows()) return;
        // An elevated session (a build server) makes new files owned by the Administrators group.
        Assert.Contains(Owner.PathOwnerSid(AppContext.BaseDirectory), new[] { Owner.CurrentIdentity().Sid, Owner.AdministratorsSid });
    }
}
