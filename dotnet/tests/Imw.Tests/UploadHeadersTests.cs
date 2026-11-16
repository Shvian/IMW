namespace Imw.Tests;

// Port of tests/test_upload_headers.py: upload CSVs use the Privilege Cloud (ISPSS) sample layouts.

public class UploadHeaders : TestBase
{
    static string FirstLine(string path) => ReadText(path).Split('\n')[0].TrimEnd('\r');

    static string Pc(string name) => Path.Combine(Samples, "privilege_cloud", name);

    [Fact]
    public void HeadersMatchPrivilegeCloudSamples()
    {
        var out_ = ConvertOne(S("delinea_export.csv"), null, "-p", S("delinea_permissions.csv"));
        foreach (var (ours, theirs) in new[] { ("Safes.csv", "AddSafes.csv"), ("SafeMembers.csv", "AddSafeMembers.csv"),
                                               ("Accounts.csv", "AddAccounts.csv") })
            Assert.Equal(FirstLine(Pc(theirs)), FirstLine(Path.Combine(out_, "upload", ours)));
        var safes = ReadCsv(Path.Combine(out_, "upload", "Safes.csv"));
        Assert.NotEmpty(safes);
        Assert.All(safes, s => Assert.Equal("\\", s["Location"]));
        var members = ReadCsv(Path.Combine(out_, "upload", "SafeMembers.csv"));
        var flags = members.SelectMany(m => m.Where(kv => kv.Key != "SafeName" && kv.Key != "MemberName" && kv.Key != "MemberType")
            .Select(kv => kv.Value)).ToHashSet();
        Assert.Equal(new HashSet<string> { "True", "False" }, flags);
        Assert.All(members, m => Assert.Contains(m["MemberType"], new[] { "User", "Group", "Role" }));
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"));
        Assert.All(accounts, a => Assert.Equal("False", a["AutomaticManagement"]));
        Assert.Contains("\r\n", File.ReadAllText(Path.Combine(out_, "upload", "Accounts.csv")));
    }

    [Fact]
    public void ExtraColumnsOnlyWhenUsed()
    {
        var cfg = T("cfg.json");
        WriteText(cfg, @"{""safe_defaults"": {""olacEnabled"": true, ""location"": ""\\Migrated""},
            ""account_defaults"": {""automaticManagementEnabled"": true, ""manualManagementReason"": ""x""},
            ""account_property_map"": {""Notes"": ""Notes"", ""NoSuchColumn"": ""Unused""},
            ""directory_map"": {""*"": ""corp.example.com""}}");
        var out_ = ConvertOne(S("delinea_export.csv"), cfg, "-p", S("delinea_permissions.csv"));
        var safes = ReadCsv(Path.Combine(out_, "upload", "Safes.csv"));
        Assert.Equal("OlacEnabled", safes[0].Keys.Last());
        Assert.False(safes[0].ContainsKey("AutoPurgeEnabled"));
        Assert.All(safes, s => Assert.Equal("True", s["OlacEnabled"]));
        Assert.All(safes, s => Assert.Equal("\\Migrated", s["Location"]));
        var members = ReadCsv(Path.Combine(out_, "upload", "SafeMembers.csv"));
        Assert.Equal("SearchIn", members[0].Keys.Last());
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"));
        Assert.True(accounts[0].ContainsKey("platformAccountProperties.Notes"));
        Assert.False(accounts[0].ContainsKey("platformAccountProperties.Unused"));
        Assert.All(accounts, a => Assert.Equal("True", a["AutomaticManagement"]));
        Assert.All(accounts, a => Assert.Equal("", a["ManualManagementReason"]));
    }

    [Fact]
    public void SemicolonNotAllowedInAccountName()
    {
        var src = T("a.csv");
        WriteText(src, "Active Directory Account\nSecret ID,Secret Name,Folder Path,Domain,Username,Password\n" +
                       "1,app;db,\\IT,host1.example.com,admin,pw\n");
        var out_ = ConvertOne(src);
        Assert.Equal("app_db", ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"))[0]["Name"]);
    }
}
