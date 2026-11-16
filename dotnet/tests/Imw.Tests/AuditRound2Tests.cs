using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Imw.Adapters;
using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_audit_round2.py

static class R2
{
    public const string Cfg = @"{""default_platform"": ""WinServerLocal""}";

    public static SourceRecord Rec(string sid, string[] folder = null, params (string, string)[] grants)
    {
        var r = new SourceRecord("t", "f", sid, sid)
        {
            Name = sid, Folder = (folder ?? new[] { "Apps" }).ToList(), Type = "Windows", Address = "h1", Username = "u" + sid, Secret = "x",
        };
        r.Grants = grants.Select(g => new Grant(g.Item1, g.Item2)).ToList();
        return r;
    }

    public static Dictionary<(string, string), MemberInfo> Members(Plan plan) =>
        plan.Members.ToDictionary(kv => (kv.Key.Safe, kv.Value.MemberName), kv => kv.Value);
}

public class MemberEditsAfterRename
{
    static Plan PlanWith(string edit)
    {
        var recs = new[] { R2.Rec("1", null, ("CORP\\Unix-Admins", "View")) };
        return Transform.BuildPlan(recs, TestBase.Cfg(R2.Cfg),
            memberOverrides: new() { ["corp\\unix-admins"] = TestBase.J(@"{""member_name"": ""Cloud-Unix-Admins"", ""member_type"": null, ""search_in"": null}") },
            memberEdits: new List<JObj> { TestBase.J(edit) });
    }

    [Fact]
    public void RemoveRenamedMember() =>
        Assert.Equal(0, PlanWith(@"{""safe_name"": ""APPS"", ""member_name"": ""Cloud-Unix-Admins"", ""action"": ""remove""}").Members.Count);

    [Fact]
    public void RoleChangeOnRenamedMemberDoesNotDuplicate()
    {
        var plan = PlanWith(@"{""safe_name"": ""APPS"", ""member_name"": ""Cloud-Unix-Admins"", ""action"": ""add"", ""role"": ""Full"", ""member_type"": """", ""search_in"": """"}");
        Assert.Equal(new[] { ("Cloud-Unix-Admins", "Full") }, plan.Members.Values.Select(m => (m.MemberName, m.Role)));
    }

    [Fact]
    public void EditSavedWithOldNameStillMatches()
    {
        foreach (var name in new[] { "Unix-Admins", "CORP\\\\Unix-Admins" })
            Assert.Equal(0, PlanWith($@"{{""safe_name"": ""APPS"", ""member_name"": ""{name}"", ""action"": ""remove""}}").Members.Count);
    }
}

public class MergedMembers : TestBase
{
    [Fact]
    public void TwoDomainsSameGroupOneRow()
    {
        var recs = new[] { R2.Rec("1", null, ("CORP\\SQL-Admins", "View")), R2.Rec("2", null, ("LEGACY\\SQL-Admins", "Owner"), ("CORP\\SQL-Admins", "View")) };
        var cfg = Cfg(R2.Cfg);
        var plan = Transform.BuildPlan(recs, cfg);
        var ms = R2.Members(plan);
        Assert.Equal(new[] { ("APPS", "SQL-Admins") }, ms.Keys);
        var m = ms[("APPS", "SQL-Admins")];
        Assert.Equal("CORP\\SQL-Admins | LEGACY\\SQL-Admins", m.SourceName);
        Assert.Equal("Full", m.Role);                               // strongest wins
        Assert.Equal(2, m.Accounts);                                // unique accounts, not grants
        Assert.Contains(m.Notes, n => n.StartsWith("merged source members"));
        Writers.WriteUpload(plan, cfg, Tmp, false);
        var rows = ReadCsv(T("upload", "SafeMembers.csv"));
        Assert.Equal(new[] { ("APPS", "SQL-Admins") }, rows.Select(r => (r["safeName"], r["memberName"])));
    }

    [Fact]
    public void RenameOntoExistingMemberMerges()
    {
        var recs = new[] { R2.Rec("1", null, ("CORP\\A", "View"), ("CORP\\B", "View")) };
        var plan = Transform.BuildPlan(recs, Cfg(R2.Cfg),
            memberOverrides: new() { ["corp\\b"] = J(@"{""member_name"": ""A"", ""member_type"": null, ""search_in"": null}") });
        Assert.Equal(new[] { ("APPS", "A") }, R2.Members(plan).Keys);
    }

    [Fact]
    public void DifferentDirectoriesAreFlagged()
    {
        var cfg = Cfg(@"{""default_platform"": ""WinServerLocal"", ""directory_map"": {""CORP"": ""corp.example.com"", ""LEGACY"": ""legacy.local""}}");
        var recs = new[] { R2.Rec("1", null, ("CORP\\SQL-Admins", "View"), ("LEGACY\\SQL-Admins", "View")) };
        var m = Transform.BuildPlan(recs, cfg).Members.Values.First();
        Assert.Contains(m.Notes, n => n.Contains("different directories"));
    }
}

public class ConfigUpgradeSteps
{
    [Fact]
    public void WorkbenchSavedConfigUpgradesToCurrentVersion()
    {
        var saved = Config.ConfigDiff(TestBase.Cfg(@"{""default_platform"": ""X""}"));
        Assert.False(saved.ContainsKey("field_aliases"));
        var up = Config.UpgradeConfig(saved);
        Assert.Equal((long)Config.ConfigVersion, up["config_version"]);
        Assert.Equal("X", up["default_platform"]);
    }

    [Fact]
    public void HandWrittenV1LeftAlone() =>
        Assert.True(Py.Eq(TestBase.J(@"{""default_platform"": ""X""}"), Config.UpgradeConfig(TestBase.J(@"{""default_platform"": ""X""}"))));

    [Fact]
    public void V1DumpUpgraded()
    {
        var up = Config.UpgradeConfig(TestBase.J(@"{""field_aliases"": {}, ""fallback_strategy"": ""folder_leaf""}"));
        Assert.Equal(("convention", (object)(long)Config.ConfigVersion), ((string)up["fallback_strategy"], up["config_version"]));
    }
}

public class StrayFarRightCell : TestBase
{
    const string Ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    string MakeXlsx(string sheet, string shared = null)
    {
        var path = T("s.xlsx");
        var parts = new Dictionary<string, string>
        {
            ["xl/workbook.xml"] = $"<workbook xmlns=\"{Ns}\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
                                  "<sheets><sheet name=\"S\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
            ["xl/_rels/workbook.xml.rels"] = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
                                             "<Relationship Id=\"rId1\" Target=\"worksheets/sheet1.xml\" Type=\"worksheet\"/></Relationships>",
            ["xl/worksheets/sheet1.xml"] = sheet,
        };
        if (shared != null) parts["xl/sharedStrings.xml"] = $"<sst xmlns=\"{Ns}\">{shared}</sst>";
        using var z = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (n, data) in parts)
        {
            using var s = z.CreateEntry(n).Open();
            s.Write(Encoding.UTF8.GetBytes(data));
        }
        return path;
    }

    [Fact]
    public void SpaceInXfdAddsNoColumns()
    {
        var path = MakeXlsx($"<worksheet xmlns=\"{Ns}\"><sheetData>" +
            "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>Name</t></is></c><c r=\"B1\" t=\"inlineStr\"><is><t>Username</t></is></c></row>" +
            "<row r=\"2\"><c r=\"A2\" t=\"inlineStr\"><is><t>web01</t></is></c><c r=\"B2\" t=\"inlineStr\"><is><t>admin</t></is></c>" +
            "<c r=\"XFD2\" t=\"inlineStr\"><is><t> </t></is></c></row></sheetData></worksheet>");
        var recs = new TableAdapter().Read(path, Cfg(R2.Cfg));
        Assert.Single(recs);
        Assert.DoesNotContain(recs[0].Extra.Keys, k => k.StartsWith("Extra_"));
    }

    [Fact]
    public void BlankExtraColumnsSkippedButValuesKept()
    {
        var row = new StrDict();
        row["Name"] = "a";
        row["Username"] = "u";
        row["Extra_1"] = "";
        row["Extra_2"] = "note";
        var r = Rows.RecordFromRow(row, Cfg(), "table", "f", "r2", 1);
        Assert.False(r.Extra.ContainsKey("Extra_1"));
        Assert.Equal("note", r.Extra["Extra_2"]);
    }

    [Fact]
    public void BadSharedStringIndexIsACleanError()
    {
        var path = MakeXlsx($"<worksheet xmlns=\"{Ns}\"><sheetData><row r=\"1\"><c r=\"A1\" t=\"s\"><v>7</v></c></row></sheetData></worksheet>",
                            "<si><t>x</t></si>");
        Assert.Contains("shared string", Assert.ThrowsAny<ValueError>(() => Xlsx.ReadRows(path)).Message);
    }
}

public class ReimportTrimsAfterUnescape : TestBase
{
    [Fact]
    public void LeadingTabIsTrimmed()
    {
        Assert.Equal("'\tadmin", CsvSafe.Escape("\tadmin"));
        var f = T("o.csv");
        WriteText(f, "Record_ID,Account_Name\nt:f:1,'\tadmin\n");
        Assert.Equal("admin", Transform.LoadOverrides(f)["t:f:1"]["Account_Name"]);
    }
}

public class XmlReadOnce : TestBase
{
    [Fact]
    public void ParseReadsTheFile()
    {
        var f = T("k.xml");
        File.WriteAllBytes(f, Encoding.ASCII.GetBytes("<KeePassFile><Root/></KeePassFile>"));
        Assert.Equal("KeePassFile", SafeXml.FromBytes(SafeXml.ReadCapped(f)).Name.LocalName);
    }

    [Fact]
    public void SizeCap()
    {
        var f = T("k.xml");
        File.WriteAllBytes(f, Encoding.ASCII.GetBytes("<KeePassFile>" + new string(' ', 100) + "</KeePassFile>"));
        Assert.Contains("larger than", Assert.ThrowsAny<ValueError>(() => SafeXml.ReadCapped(f, 50)).Message);
    }

    [Fact]
    public void BrokenKeepassXmlIsAnAdapterError()
    {
        var f = T("k.xml");
        File.WriteAllBytes(f, Encoding.ASCII.GetBytes("<KeePassFile><Root>"));
        Assert.Throws<AdapterError>(() => new KeePassAdapter().Read(f, Cfg()));
    }
}

public class FrontendCsp
{
    static string Res(string name) => Encoding.UTF8.GetString(UiHandler.Resource(name));

    [Fact]
    public void NoInlineScriptsOrHandlers()
    {
        var html = Res("static/index.html");
        Assert.Empty(Regex.Matches(html, @"<script(?![^>]*\bsrc=)"));
        foreach (var name in new[] { "static/index.html", "static/app.js", "static/theme.js" })
            Assert.Empty(Regex.Matches(Res(name), @"\son[a-z]+\s*=\s*[""']"));
        var src = File.ReadAllText(Path.Combine(TestBase.Root, "dotnet", "src", "Imw", "Ui", "Server.cs"));
        Assert.Contains("script-src 'self';", src);
        Assert.DoesNotContain("script-src 'self' 'unsafe-inline'", src);
    }

    [Fact]
    public void SecurityNoticeOnOverview()
    {
        var js = Res("static/app.js");
        Assert.Contains("const securityNotice", js);
        Assert.Contains("${securityNotice(true)}", js);             // welcome page: open
        Assert.Contains("${securityNotice(false)}", js);            // overview: folded
    }
}
