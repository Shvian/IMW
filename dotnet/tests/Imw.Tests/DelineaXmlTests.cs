using System.Text;
using Imw.Adapters;
using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_delinea_xml.py: Delinea Secret Server XML exports, text encodings, and folder-permission reports.

static class DelineaXmlHelpers
{
    public static string Xml => TestBase.S("delinea_export.xml");                    // UTF-16 with BOM, folders and permissions
    public static string Converted => TestBase.S("delinea_keepass_converted.xml");   // Delinea's KeePass converter output
    public static readonly string[] XmlSecrets = { "FAKE-Wq7!rT2mZ9pLk4", "FAKE-b8@Hn3vQx6Ye1", "FAKEKEYb3Blbn", "FAKE-pass-phrase-77",
        "FAKE-Sq1&Prod", "FAKE-Vend0r-Phrase-3", "FAKE-memorable", "FAKE-\u00fcn\u00ef" };

    public static Dictionary<string, SourceRecord> Records(string path) =>
        Adapter.Detect(path).Read(path, Config.Load()).ToDictionary(r => r.Name);

    public static List<(string, string, string)> G(SourceRecord r) => r.Grants.Select(g => (g.Member, g.Permission, g.MemberType)).ToList();
}

public class XmlEncoding : TestBase
{
    [Fact]
    public void DeclaredUtf16ButUtf8Bytes()
    {
        // What Delinea's KeePass converter writes: encoding="utf-16" on plain UTF-8 bytes.
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-16\"?>", Encoding.ASCII.GetString(File.ReadAllBytes(DelineaXmlHelpers.Converted)));
        Assert.Equal("ImportFile", SafeXml.Tag(SafeXml.Parse(DelineaXmlHelpers.Converted)));
    }

    [Fact]
    public void Utf16WithAndWithoutBom()
    {
        var text = new UTF8Encoding(false).GetString(Encoding.Convert(Encoding.Unicode, Encoding.UTF8, File.ReadAllBytes(DelineaXmlHelpers.Xml)));
        text = text.TrimStart('\uFEFF');
        var variants = new[]
        {
            Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(text)).ToArray(),
            Encoding.Unicode.GetBytes(text),
            Encoding.BigEndianUnicode.GetBytes(text),
            Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(text)).ToArray(),
        };
        for (int i = 0; i < variants.Length; i++)
        {
            var p = T($"x{i}.xml");
            File.WriteAllBytes(p, variants[i]);
            Assert.True(Adapter.Detect(p).Name == "delinea", i.ToString());
            Assert.Contains("\u00dcn\u00efcode admin@srv099", DelineaXmlHelpers.Records(p).Keys);
        }
    }

    [Fact]
    public void DtdRefusedInUtf16()
    {
        var p = T("evil.xml");
        var s = "<?xml version=\"1.0\" encoding=\"utf-16\"?><!DOCTYPE x [<!ENTITY a \"aaaa\">]><ImportFile><Secrets/></ImportFile>";
        File.WriteAllBytes(p, Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(s)).ToArray());
        Assert.Throws<AdapterError>(() => Adapter.Get("delinea").Read(p, Config.Load()));
    }

    [Fact]
    public void KeepassXmlInUtf16()
    {
        var p = T("kp.xml");
        var s = File.ReadAllText(S("keepass_export.xml"), Encoding.UTF8);
        File.WriteAllBytes(p, Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(s)).ToArray());
        Assert.Equal("keepass", Adapter.Detect(p).Name);
        Assert.NotEmpty(Adapter.Detect(p).Read(p, Config.Load()));
    }

    [Fact]
    public void NotAnImportFile()
    {
        var p = T("other.xml");
        WriteText(p, "<Something/>");
        Assert.Throws<AdapterError>(() => Adapter.Get("delinea").Read(p, Config.Load()));
    }
}

public class DelineaXml : TestBase
{
    [Fact]
    public void ConvertedKeepassSample()
    {
        var recs = DelineaXmlHelpers.Records(DelineaXmlHelpers.Converted);
        Assert.Equal(2, recs.Count);
        var r = recs["Sample Entry #2"];
        Assert.Equal(("Michael321", "12345", "Kee Pass", 0), (r.Username, r.Secret, r.Type, r.Folder.Count));
        Assert.Null(r.Grants);              // empty <Permissions>: a permissions file can add them
        Assert.False(r.Extra.ContainsKey("Password"));
        var out_ = ConvertOne(DelineaXmlHelpers.Converted);
        var row = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"))[1];
        Assert.Equal("GenericWebApp", row["Platform_ID"]);
        Assert.Equal("keepass.info", row["Address"]);
    }

    [Fact]
    public void FoldersTemplatesAndPermissions()
    {
        var recs = DelineaXmlHelpers.Records(DelineaXmlHelpers.Xml);
        Assert.Equal(6, recs.Count);
        var inherit = recs["Administrator@srv001"];       // \Infrastructure\Windows has none: takes \Infrastructure's
        Assert.Equal("folder", inherit.AccessSource);
        Assert.Equal(new[] { ("CORP\\PAM-Infra-Admins", "Owner", "Group"), ("CORP\\Helpdesk", "List", "Group") }, DelineaXmlHelpers.G(inherit));
        var own = recs["svc_backup@srv002"];              // secret-level permissions replace the folder's
        Assert.Equal("record", own.AccessSource);
        Assert.Equal(new[] { ("CORP\\Backup-Operators", "Edit", "Group"), ("CORP\\adm_jdoe", "Owner", "User"), ("EMEA\\kmuller", "View", "User") },
                     DelineaXmlHelpers.G(own));
        Assert.Contains("1 secret dependency not migrated", own.Notes);
        var key = recs["deploy@web01"];
        Assert.Equal("key", key.SecretType);
        Assert.StartsWith("-----BEGIN OPENSSH", key.Secret);
        Assert.Equal(new[] { ("CORP\\PAM-Unix-Admins", "Owner", "Group"), ("CORP\\jsmith", "View", "User"), ("EMEA\\Linux-Ops-EU", "Edit", "Group") },
                     DelineaXmlHelpers.G(key));
        Assert.Null(recs["sa@sql-prod-01"].Grants);        // no permissions anywhere above it
        Assert.Equal("FAKE-Sq1&Prod<99>", recs["sa@sql-prod-01"].Secret);
        var portal = recs["Billing portal (Vendor 3)"];
        // Old true/false style; a <Name> listed under <Groups> is a group.
        Assert.Equal(new[] { ("CORP\\APP-Payments-Owners", "Owner", "Group"), ("CORP\\Security-Audit", "View", "Group"), ("APAC\\wtan", "Edit", "User") },
                     DelineaXmlHelpers.G(portal));
        // ispassword fields are secrets whatever their name; isfile fields are attachments.
        Assert.Equal("FAKE-Vend0r-Phrase-3", portal.Secret);
        foreach (var f in new[] { "Access Phrase", "Memorable Word", "Contract" }) Assert.False(portal.Extra.ContainsKey(f), f);
        Assert.Equal("https://billing.vendor3.example.com/login", portal.Address);
        Assert.Equal("Pat Example", portal.Extra["Account Manager"]);
        Assert.Contains(portal.Notes, n => n.Contains("Memorable Word"));
        Assert.Contains(portal.Notes, n => n.Contains("attachment field 'Contract'"));
        Assert.Null(recs["\u00dcn\u00efcode admin@srv099"].Grants);
    }

    [Fact]
    public void ConvertKeepsSecretsOutOfReview()
    {
        var cfg = T("cfg.json");
        WriteText(cfg, "{\"platform_rules\": [{\"field\": \"type\", \"pattern\": \"^Vendor Portal$\", \"platform\": \"GenericWebApp\"}], " +
                       "\"directory_map\": {\"CORP\": \"corp.example.com\", \"EMEA\": \"emea.corp.example.com\", " +
                       "\"APAC\": \"apac.corp.example.com\", \"*\": \"Vault\"}}");
        var out_ = ConvertOne(DelineaXmlHelpers.Xml, cfg, "--include-secrets");
        foreach (var f in Directory.EnumerateFiles(Path.Combine(out_, "review"), "*", SearchOption.AllDirectories))
        {
            var body = ReadText(f);
            foreach (var s in DelineaXmlHelpers.XmlSecrets) Assert.False(body.Contains(s, StringComparison.Ordinal), $"'{s}' leaked into {Path.GetFileName(f)}");
        }
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.Equal(6, accounts.Count);
        Assert.Contains("FAKE-Vend0r-Phrase-3", accounts.Values.Select(a => a["Secret"]));
        var members = ReadCsv(Path.Combine(out_, "upload", "SafeMembers.csv"));
        var got = members.Select(m => (m["SafeName"], m["MemberName"], m["MemberType"])).ToHashSet();
        var searchIn = members.GroupBy(m => (m["MemberName"], m["MemberType"])).ToDictionary(g => g.Key, g => g.Last()["SearchIn"]);
        Assert.Equal("emea.corp.example.com", searchIn[("kmuller", "User")]);
        Assert.Equal("emea.corp.example.com", searchIn[("Linux-Ops-EU", "Group")]);
        Assert.Equal("apac.corp.example.com", searchIn[("wtan", "User")]);
        Assert.Equal("corp.example.com", searchIn[("PAM-Infra-Admins", "Group")]);
        Assert.Subset(got, new HashSet<(string, string, string)>
        {
            ("INF-WIN", "PAM-Infra-Admins", "Group"), ("INF-WIN", "adm_jdoe", "User"), ("APP-PAY", "APP-Payments-Owners", "Group"),
        });
    }

    [Fact]
    public void PermissionsFileFillsGapsOnly()
    {
        var perms = T("perms.csv");
        WriteText(perms, "Folder Path,Group,Permission\n\\Databases,CORP\\PAM-DBA,Owner\n\\Infrastructure,CORP\\Someone-Else,Owner\n");
        var out_ = ConvertOne(DelineaXmlHelpers.Xml, null, "-p", perms);
        var text = ReadText(Path.Combine(out_, "review", "Accounts_Review.csv"));
        Assert.Contains("CORP\\PAM-DBA=Owner", text);          // \Databases had none in the XML
        Assert.DoesNotContain("Someone-Else", text);           // the XML's own permissions win
    }
}

public class DelineaReports : TestBase
{
    string Write(string name, string text)
    {
        var p = T(name);
        WriteText(p, text);
        return p;
    }

    [Fact]
    public void GroupReportSecretRoleWins()
    {
        var p = Write("groups.csv", "Folder Path,Group Name,Folder Permissions,Secret Permissions,Inherited\n" +
                                    "\\Databases,PAM-DBA,Owner,Owner,No\n" +
                                    "\\Databases\\SQL,PAM-DBA,Owner,Owner,Yes\n" +
                                    "\\Databases\\SQL,Helpdesk,View,List,No\n");
        Assert.True(UiApp.LooksLikePermissions(p));
        var perms = new Permissions(new[] { p });
        Assert.Equal(new[] { ("PAM-DBA", "Owner"), ("Helpdesk", "List") }, perms.ByFolder["databases\\sql"].Select(g => (g.Member, g.Permission)));
    }

    [Fact]
    public void UserReportWithDomain()
    {
        var p = Write("users.csv", "Folder,User Name,Domain,Permissions\n\\Infra,jsmith,CORP,\"View, Edit\"\n");
        Assert.True(UiApp.LooksLikePermissions(p));
        var g = new Permissions(new[] { p }).UsersByFolder["infra"][0];
        Assert.Equal(("CORP\\jsmith", "Edit", "User"), (g.Member, g.Permission, g.MemberType));
    }

    [Fact]
    public void UserAndGroupColumnsKeepTheGroup()
    {
        var p = Write("all.csv", "Folder Path,User,Group,Folder Permission\n\\Infra,jsmith,CORP\\Admins,Owner\n");
        var g = new Permissions(new[] { p }).ByFolder["infra"][0];
        Assert.Equal(("CORP\\Admins", "Group"), (g.Member, g.MemberType));
    }

    [Fact]
    public void StrongestPermission()
    {
        Assert.Equal("Owner", Permissions.StrongestPermission("View, Edit, Owner"));
        Assert.Equal("View", Permissions.StrongestPermission("List/View"));
        Assert.Equal("Edit", Permissions.StrongestPermission("Edit"));
    }
}

public class ConfigV4
{
    [Fact]
    public void SavedPlatformMapGetsKeePass()
    {
        var up = Config.UpgradeConfig(TestBase.J("{\"config_version\": 3, \"platform_map\": {\"Windows Account\": \"X\"}}"));
        Assert.Equal(Config.ConfigVersion.ToString(), Json.Dumps(up.Get("config_version")));
        Assert.Equal("GenericWebApp", ((JObj)up.Get("platform_map")).Get("Kee Pass"));
    }
}
