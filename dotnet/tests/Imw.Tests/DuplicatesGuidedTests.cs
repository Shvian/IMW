using Imw.Adapters;

namespace Imw.Tests;

// Port of tests/test_duplicates_otp.py and tests/test_guided_mappings.py

public class Duplicates
{
    static SourceRecord Rec(string sid, string folder = "\\Apps", string username = "admin", string address = "h1.corp.example.com",
                            string sourceFile = "f", string name = "") =>
        new("t", sourceFile, sid, "")
        {
            Name = name.Length > 0 ? name : sid, Folder = SourceRecord.SplitFolder(folder), Username = username,
            Type = "Windows Account", Address = address, Secret = "x",
        };

    static Dictionary<string, List<string>> DupNotes(Plan plan) =>
        plan.Accounts.ToDictionary(p => p.Rec.RecordId, p => p.Warnings.Where(w => w.StartsWith("possible duplicate", StringComparison.Ordinal)).ToList());

    [Fact]
    public void SameUsernameAndAddressAnyCaseAndSpaces()
    {
        var a = Rec("1", username: "Admin", address: "H1.corp.example.com ");
        var b = Rec("2", username: " admin", address: "h1.CORP.example.com");
        var c = Rec("3", username: "admin", address: "h2.corp.example.com");
        var notes = DupNotes(Transform.BuildPlan(new[] { a, b, c }, Config.Load()));
        Assert.Single(notes[a.RecordId]);
        Assert.Contains(b.RecordId, notes[a.RecordId][0]);
        Assert.Contains(a.RecordId, notes[b.RecordId][0]);
        Assert.Empty(notes[c.RecordId]);
        Assert.Equal("REVIEW", Transform.BuildPlan(new[] { a, b, c }, Config.Load()).Accounts[0].Status);
    }

    [Fact]
    public void AcrossFilesAndSafes()
    {
        var a = Rec("1", folder: "\\Prod\\Windows", sourceFile: "delinea_export");
        var b = Rec("1", folder: "\\Test\\Linux", sourceFile: "keepass_export");
        var plan = Transform.BuildPlan(new[] { a, b }, Config.Load());
        var notes = DupNotes(plan);
        Assert.Contains("file keepass_export", notes[a.RecordId][0]);
        var pb = plan.Accounts[1];
        if (Py.Lower(pb.Safe) != Py.Lower(plan.Accounts[0].Safe)) Assert.Contains("Safe " + pb.Safe, notes[a.RecordId][0]);
    }

    [Fact]
    public void NotMigratedCopyClearsTheFlag()
    {
        var (a, b) = (Rec("1"), Rec("2"));
        var plan = Transform.BuildPlan(new[] { a, b }, Config.Load(),
            overrides: new() { [b.RecordId] = new() { ["Migrate"] = "N" } }, @explicit: true);
        Assert.All(DupNotes(plan).Values, Assert.Empty);
        Assert.Equal(2, DupNotes(plan).Count);
    }

    [Fact]
    public void BlankUsernameOrAddressIsNotADuplicate()
    {
        var plan = Transform.BuildPlan(new[] { Rec("1", address: ""), Rec("2", address: "") }, Config.Load());
        Assert.All(DupNotes(plan).Values, Assert.Empty);
    }

    [Fact]
    public void ManyCopiesAreSummarised()
    {
        var recs = Enumerable.Range(0, 6).Select(i => Rec(i.ToString())).ToList();
        var note = DupNotes(Transform.BuildPlan(recs, Config.Load()))[recs[0].RecordId][0];
        Assert.Contains("and 2 more", note);
    }
}

public class OneTimePasswords : TestBase
{
    const string Seed = "JBSWY3DPEHPK3PXP";

    static string Dump(SourceRecord r) => string.Join("|", r.Extra.Select(kv => kv.Key + "=" + kv.Value)) + "|" + string.Join("|", r.Notes);

    [Fact]
    public void KeepassTotpFields()
    {
        var xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<KeePassFile><Root><Group><Name>Root</Name>
 <Entry><UUID>AAAA</UUID>
  <String><Key>Title</Key><Value>vpn</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw1</Value></String>
  <String><Key>TimeOtp-Secret-Base32</Key><Value Protected=""True"">{Seed}</Value></String>
  <String><Key>TimeOtp-Period</Key><Value>30</Value></String>
 </Entry>
 <Entry><UUID>BBBB</UUID>
  <String><Key>Title</Key><Value>git</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw2</Value></String>
  <String><Key>otp</Key><Value>otpauth://totp/x?secret={Seed}&amp;period=30</Value></String>
 </Entry>
 <Entry><UUID>CCCC</UUID>
  <String><Key>Title</Key><Value>plain</Value></String>
  <String><Key>UserName</Key><Value>jdoe</Value></String>
  <String><Key>Password</Key><Value>pw3</Value></String>
 </Entry>
</Group></Root></KeePassFile>";
        var path = T("kp.xml");
        WriteText(path, xml);
        var recs = Adapter.Get("keepass").Read(path, Config.Load()).ToDictionary(r => r.Name);
        foreach (var name in new[] { "vpn", "git" })
        {
            var r = recs[name];
            Assert.True(r.Notes.Count(n => n.StartsWith("one-time password (OTP)", StringComparison.Ordinal)) == 1, string.Join("; ", r.Notes));
            Assert.DoesNotContain(Seed, Dump(r));
            Assert.DoesNotContain(r.Notes, n => n.Contains("secret field"));     // one note, not two
            Assert.Equal(name == "vpn" ? "pw1" : "pw2", r.Secret);
        }
        Assert.DoesNotContain(recs["plain"].Notes, n => n.Contains("one-time"));
        var plan = Transform.BuildPlan(recs.Values, Config.Load());
        Assert.Equal("REVIEW", plan.Accounts.First(p => p.Rec.Name == "git").Status);
    }

    [Fact]
    public void TableOtpColumns()
    {
        var path = T("sheet.csv");
        WriteText(path, "Name,Username,Address,Password,TOTP,OTP Enabled,Login link\n" +
                        $"a,u1,h1,pw,{Seed},true,\n" +
                        "b,u2,h2,pw,,false,\n" +
                        $"c,u3,h3,pw,,,otpauth://totp/x?secret={Seed}\n");
        var recs = Adapter.Get("table").Read(path, Config.Load()).ToDictionary(r => r.Name);
        Assert.Contains(recs["a"].Notes, n => n.StartsWith("one-time password (OTP)", StringComparison.Ordinal));
        Assert.DoesNotContain(recs["b"].Notes, n => n.Contains("one-time"));
        Assert.Contains(recs["c"].Notes, n => n.Contains("'Login link'"));
        foreach (var r in recs.Values) Assert.DoesNotContain(Seed, Dump(r));
    }
}

public class FullMemberCheck
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

    static HashSet<string> Issues((string, string)[] grants, string cfg = "{}") =>
        Transform.BuildPlan(new[] { Rec("\\App", grants) }, TestBase.Cfg(cfg), @explicit: true).Safes.Values.First().Issues;

    [Fact]
    public void SafeWithoutFullMemberIsFlagged() =>
        Assert.Contains(Transform.NoFullMemberNote, Issues(new[] { ("CORP\\Ops", "View"), ("CORP\\Dev", "Edit") }));

    [Fact]
    public void SafeWithNoMembersIsFlagged() => Assert.Contains(Transform.NoFullMemberNote, Issues(Array.Empty<(string, string)>()));

    [Fact]
    public void FullMemberClearsIt() =>
        Assert.DoesNotContain(Transform.NoFullMemberNote, Issues(new[] { ("CORP\\Ops", "View"), ("CORP\\Admins", "Owner") }));

    [Fact]
    public void CustomRoleWithEveryFullPermissionCounts()
    {
        var full = Config.PermissionPresets["Full"];
        string Cfg(IEnumerable<string> perms) =>
            Json.Dumps(Json.O(("permission_map", Json.O(("Boss", "Everything"))),
                              ("custom_roles", Json.O(("Everything", perms.Cast<object>().ToList())))));
        Assert.DoesNotContain(Transform.NoFullMemberNote, Issues(new[] { ("CORP\\A", "Boss") }, Cfg(full.Append("requestsAuthorizationLevel2"))));
        Assert.Contains(Transform.NoFullMemberNote, Issues(new[] { ("CORP\\A", "Boss") }, Cfg(full.Skip(1))));
    }

    [Fact]
    public void MemberAddedByYouWithFullClearsIt()
    {
        var edits = new List<JObj> { TestBase.J("{\"safe_name\": \"App\", \"member_name\": \"PAM-Admins\", \"action\": \"add\", \"role\": \"Full\", \"member_type\": \"Group\", \"search_in\": \"\"}") };
        var plan = Transform.BuildPlan(new[] { Rec("\\App", ("CORP\\Ops", "View")) }, TestBase.Cfg(), @explicit: true, memberEdits: edits);
        var safe = plan.Safes.Keys.First();
        Assert.Contains(plan.Members.Values, m => m.Role == "Full");
        Assert.DoesNotContain(Transform.NoFullMemberNote, plan.Safes[safe].Issues);
    }
}

public class PlatformDefaults
{
    [Fact]
    public void NewTemplatesMapToKnownPlatforms()
    {
        var pmap = (JObj)Config.DefaultConfig().Get("platform_map");
        var codes = Naming.DefaultPlatformCodes.Select(c => c.Platform).ToHashSet();
        foreach (var t in new[] { "Windows Local Admin", "Active Directory Domain Admin", "Cisco Account (SSH)", "Palo Alto",
                                  "VMware ESXi", "PostgreSQL", "MySQL", "AWS IAM Key", "Azure AD Account" })
            Assert.True(codes.Contains((string)pmap.Get(t)), t);
    }

    [Fact]
    public void SavedV2PlatformMapGetsTheNewTypes()
    {
        var up = Config.UpgradeConfig(TestBase.J("{\"config_version\": 2, \"platform_map\": {\"Windows Account\": \"X\", \"cisco account (ssh)\": \"Mine\"}}"));
        Assert.Equal(Config.ConfigVersion.ToString(), Json.Dumps(up.Get("config_version")));
        var pm = (JObj)up.Get("platform_map");
        Assert.Equal("X", pm.Get("Windows Account"));
        Assert.Equal("Mine", pm.Get("cisco account (ssh)"));      // yours stays
        Assert.Null(pm.Get("Cisco Account (SSH)"));
        Assert.Equal("PostgreSQL", pm.Get("PostgreSQL"));
    }

    [Fact]
    public void PlatformRulesIgnoreCase()
    {
        var r = new SourceRecord("t", "f", "1", "")
        {
            Folder = SourceRecord.SplitFolder("\\LINUX\\Web"), Username = "root", Type = "Password", Address = "h", Secret = "x",
        };
        var cfg = TestBase.Cfg(@"{""platform_rules"": [{""field"": ""folder"", ""pattern"": ""\\\\linux\\\\"", ""platform"": ""UnixSSH""}]}");
        Assert.Equal("UnixSSH", Transform.ResolvePlatform(r, cfg).Item1);
    }
}

public class ColumnReport : TestBase
{
    [Fact]
    public void UnknownHeadersAreReported()
    {
        var f = T("inventory.csv");
        WriteText(f, "Title,SAMAccountName,TargetHost,Pwd\nWeb admin,svc_web,web01,x\n");
        var (headers, current) = new TableAdapter().ColumnReport(f, Cfg());
        Assert.Equal(new[] { "Title", "SAMAccountName", "TargetHost", "Pwd" }, headers);
        Assert.Equal(("Title", "", ""), ((string)current.Get("name"), (string)current.Get("username"), (string)current.Get("address")));
        var cfg = Cfg("{\"sources\": {\"table\": {\"columns\": {\"username\": \"SAMAccountName\", \"address\": \"TargetHost\"}}}}");
        var recs = new TableAdapter().Read(f, cfg);
        Assert.Equal(("svc_web", "web01"), (recs[0].Username, recs[0].Address));
    }
}
