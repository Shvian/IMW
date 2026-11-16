using Imw.Adapters;

namespace Imw.Tests;

// Port of tests/test_imw.py

public class SafeNames : TestBase
{
    [Fact]
    public void Rules()
    {
        var cfg = Config.Load();
        Assert.Equal("Linux-Web- DMZ-Edge", Transform.SanitizeSafeName("Linux\\Web: DMZ/Edge", cfg).Name);
        var (name, valid, _) = Transform.SanitizeSafeName(new string('X', 40), cfg);
        Assert.Equal(28, name.Length);
        Assert.False(valid);
        Assert.True(Transform.SanitizeSafeName("OK-Name", cfg).Valid);
    }

    [Fact]
    public void CollisionSuffixFits()
    {
        var cfg = Config.Load();
        string a = new string('A', 30) + "1", b = new string('A', 30) + "2";
        var clean = new OrderedMap<string, string>(StringComparer.Ordinal);
        foreach (var p in new[] { a, b }) clean[p] = Transform.SanitizeSafeName(p, cfg).Name;
        var res = Transform.ResolveCollisions(clean, cfg);
        Assert.Equal(new string('A', 28), res[a].Item1);
        Assert.Equal(new string('A', 26) + "-2", res[b].Item1);
        Assert.Equal(28, res[b].Item1.Length);
    }

    [Fact]
    public void ChangedIgnoresToolSuffixes()
    {
        Assert.False(Transform.Changed("DB-Production-Privileged-A-2", "DB-Production-Privileged-Acc"));
        Assert.False(Transform.Changed("svc_2", "svc"));
        Assert.True(Transform.Changed("APP-2", "APP-Payments"));
        Assert.True(Transform.Changed("Other", "Name"));
        Assert.False(Transform.Changed("", "Name"));
    }
}

public class DelineaCsv : TestBase
{
    [Fact]
    public void Sample()
    {
        var out_ = ConvertOne(S("delinea_export.csv"), S("config_delinea.json"), "-p", S("delinea_permissions.csv"));
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        Assert.Equal(8, rows.Count);
        var byId = rows.ToDictionary(r => Id(r));
        Assert.Equal("DB-Production-Privileged-Acc", byId["101"]["Target_Safe"]);
        Assert.Equal("FALSE", byId["101"]["Valid_Safe_Name"]);
        Assert.Equal("key", byId["105"]["Secret_Type"]);
        Assert.Equal("APP-Storefront", byId["105"]["Target_Safe"]);    // min_permission from old config
        Assert.Equal("NET-Devices", byId["108"]["Target_Safe"]);
        Assert.Equal("fw01.example.com", byId["108"]["Address"]);
        Assert.Contains("Attachment", byId["103"]["Notes"]);
        Assert.False(rows[0].ContainsKey("Source.Attachment"));
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv"));
        Assert.All(accounts, a => Assert.Equal("", a["Secret"]));
        AssertNoSecrets(out_);
    }

    [Fact]
    public void IncludeSecrets()
    {
        var out_ = ConvertOne(S("delinea_export.csv"), null, "--include-secrets");
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.Equal("P@ssw0rd!1", accounts["svc_sql_prod"]["Secret"]);
        Assert.StartsWith("-----BEGIN OPENSSH", accounts["deploy key app01"]["Secret"]);
        AssertNoSecrets(Path.Combine(out_, "review"));
        var manifestText = File.ReadAllText(Path.Combine(out_, "manifest.json"));
        Assert.Equal(true, Json.ParseObj(manifestText)["includes_secrets"]);
        Assert.DoesNotContain("P@ssw0rd", manifestText);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(out_, "upload", "Accounts.csv")));
    }

    [Fact]
    public void Overrides()
    {
        var out_ = ConvertOne(S("delinea_export.csv"), S("config_delinea.json"), "-p", S("delinea_permissions.csv"));
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        foreach (var r in rows)
        {
            if (r["Record_ID"].EndsWith(":102")) r["Migrate"] = "N";
            if (r["Record_ID"].EndsWith(":107"))
            {
                r["Target_Safe"] = "FIN-Portals";
                r["Platform_ID"] = "VendorPortal";
            }
        }
        var edited = T("edited.csv");
        WriteDictCsv(edited, rows);
        var out2 = ConvertFiles(new[] { S("delinea_export.csv") }, S("config_delinea.json"),
                                new[] { "-p", S("delinea_permissions.csv"), "--overrides", edited }, "out2");
        var rows2 = ReadCsv(Path.Combine(out2, "review", "Accounts_Review.csv")).ToDictionary(r => Id(r));
        Assert.Equal("N", rows2["102"]["Migrate"]);
        Assert.Equal("FIN-Portals", rows2["107"]["Target_Safe"]);
        Assert.Equal("override", rows2["107"]["Safe_Mapping_Source"]);
        Assert.Equal("VendorPortal", rows2["107"]["Platform_ID"]);
        Assert.Equal("group_rule:CORP\\DBA-Team", rows2["101"]["Safe_Mapping_Source"]);
        var uploaded = ReadCsv(Path.Combine(out2, "upload", "Accounts.csv")).Select(a => a["Name"]).ToHashSet();
        Assert.DoesNotContain("svc_backup", uploaded);
        Assert.Contains("svc_sql_prod", uploaded);
        Assert.DoesNotContain("IT-Backup", ReadCsv(Path.Combine(out2, "upload", "Safes.csv")).Select(s => s["SafeName"]));
    }
}

public class KeePassTests : TestBase
{
    [Fact]
    public void Xml()
    {
        Assert.Equal("keepass", Adapter.Detect(S("keepass_export.xml")).Name);
        var cfg = Config.Load(S("config_generic.json"));
        var recs = Adapter.Get("keepass").Read(S("keepass_export.xml"), cfg);
        var names = recs.ToDictionary(r => r.Name);
        Assert.False(names.ContainsKey("deleted entry"));          // recycle bin skipped
        Assert.Equal(4, recs.Count);                                // history entries not duplicated
        var web = names["root@web02"];
        Assert.Equal(new[] { "Linux", "Web Servers: DMZ/Edge" }, web.Folder);
        // The adapter keeps the full URL; mapping turns it into the host when url_address_to_host is on.
        Assert.Equal("ssh://web02.example.com:22", web.Address);
        Assert.Equal("Kp!root-web02", web.Secret);
        Assert.Equal("22", web.Extra["Port"]);
        Assert.Contains(web.Notes, n => n.Contains("web02_notes.txt"));
        var key = names["deploy key build01"];
        Assert.Equal("key", key.SecretType);
        Assert.False(key.Extra.ContainsKey("SSH Private Key"));
    }

    [Fact]
    public void UrlAddressToHostSetting()
    {
        var cfg = Config.Load(S("config_generic.json"));
        string Address(bool on)
        {
            var c = cfg.Copy();
            c["url_address_to_host"] = on;
            var recs = Adapter.Get("keepass").Read(S("keepass_export.xml"), c);
            var plan = Transform.BuildPlan(recs, c);
            return plan.Accounts.First(p => p.Rec.Name == "root@web02").Rec.Address;
        }
        Assert.Equal("web02.example.com", Address(true));
        Assert.Equal("ssh://web02.example.com:22", Address(false));
    }

    [Fact]
    public void XmlEndToEnd()
    {
        var out_ = ConvertOne(S("keepass_export.xml"), S("config_generic.json"), "--include-secrets");
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv")).ToDictionary(r => r["Account_Name"]);
        Assert.Equal("ERROR", rows["switch core01"]["Status"]);     // no username
        Assert.Equal("UNIX-Servers", rows["root@web02"]["Target_Safe"]);
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.False(accounts.ContainsKey("switch core01"));
        Assert.Equal("22", accounts["root@web02"]["platformAccountProperties.Port"]);
        AssertNoSecrets(Path.Combine(out_, "review"));
    }

    [Fact]
    public void CsvExport()
    {
        Assert.Equal("keepass", Adapter.Detect(S("keepassxc_export.csv")).Name);
        var out_ = ConvertOne(S("keepassxc_export.csv"), S("config_generic.json"));
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        Assert.Equal(2, rows.Count);                                // recycle bin skipped
        Assert.Equal(new HashSet<string> { "Oracle", "MSSql" }, rows.Select(r => r["Platform_ID"]).ToHashSet());
        Assert.False(rows[0].ContainsKey("Source.TOTP"));
        AssertNoSecrets(out_);
    }

    [Fact]
    public void KdbxRefused()
    {
        var p = T("vault.kdbx");
        File.WriteAllBytes(p, new byte[] { 0x03, 0xd9, 0xa2, 0x9a });
        Assert.Throws<AdapterError>(() => Adapter.Get("keepass").Read(p, Config.Load()));
    }
}

public class TableTests : TestBase
{
    [Fact]
    public void CsvAccessColumn()
    {
        Assert.Equal("table", Adapter.Detect(S("accounts_inventory.csv")).Name);
        var out_ = ConvertOne(S("accounts_inventory.csv"), S("config_generic.json"), "--include-secrets");
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        var mf = rows.First(r => r["Username"] == "mfadmin");
        Assert.Equal("ERROR", mf["Status"]);
        var safes = rows.Where(r => r["Username"] == "sa").Select(r => r["Target_Safe"]).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "DB-SQL Production Reportin-2", "DB-SQL Production Reporting" }, safes);
        var members = ReadCsv(Path.Combine(out_, "upload", "SafeMembers.csv"));
        var helpdesk = members.First(m => m["MemberName"] == "Helpdesk");
        Assert.False(helpdesk.ContainsKey("role"));                  // the role is in the review file
        Assert.Equal("corp.example.com", helpdesk["SearchIn"]);      // set here, so the column is added
        Assert.Equal("True", helpdesk["retrieveAccounts"]);          // "Read" -> Read only preset
        Assert.Equal("True", helpdesk["listAccounts"]);
        Assert.Equal("False", helpdesk["deleteAccounts"]);
        Assert.Equal("False", helpdesk["manageSafe"]);
        Assert.DoesNotContain("mfadmin", ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).Select(a => a["UserName"]));
    }

    [Fact]
    public void XlsxGrantsPerRow()
    {
        var x = T("inv.xlsx");
        XlsxWriter.Write(x, XlsxWriter.Sample);
        Assert.Equal("table", Adapter.Detect(x).Name);
        var out_ = ConvertOne(x, S("config_excel.json"), "--include-secrets");
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        Assert.Equal(3, rows.Count);                                 // 2 grant rows merged
        var batch = rows[0];
        Assert.Equal("UNIX-Batch", batch["Target_Safe"]);
        Assert.Contains("CORP\\Helpdesk=List", batch["Access_Groups"]);
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.Equal("0042", accounts["leading zero id"]["UserName"]);
        Assert.Equal("=1+1", accounts["leading zero id"]["Secret"]);
        Assert.Equal("22", accounts["unix-batch01-root"]["platformAccountProperties.Port"]);
        Assert.Equal("APP-Payments-Prod", accounts["payments-api"]["SafeName"]);
    }

    [Fact]
    public void MultipleInputs()
    {
        var out_ = ConvertFiles(new[] { S("keepassxc_export.csv"), "table=" + S("accounts_inventory.csv") }, S("config_generic.json"));
        var sources = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv")).Select(r => r["Source"]).ToHashSet();
        Assert.Equal(new HashSet<string> { "keepass", "table" }, sources);
    }
}

public class CliTests : TestBase
{
    [Fact]
    public void RefusesNonEmptyOutput()
    {
        Directory.CreateDirectory(T("busy"));
        File.WriteAllText(T("busy", "x.txt"), "x");
        var (rc, _) = RunCli("convert", "-i", S("delinea_export.csv"), "-o", T("busy"));
        Assert.Equal(2, rc);
    }

    [Fact]
    public void InitConfigRoundTrip()
    {
        var p = T("cfg.json");
        var (rc, _) = RunCli("init-config", p);
        Assert.Equal(0, rc);
        var cfg = Config.Load(p);
        Assert.Equal(28L, cfg.Obj("safe_name")["max_length"]);
        Assert.Equal("-", cfg.Obj("safe_name")["replacement"]);
    }

    [Fact]
    public void PlanWithoutCli()
    {
        var cfg = Config.Load();
        var recs = Adapter.Get("delinea").Read(S("delinea_export.csv"), cfg);
        Assert.Equal(8, Transform.BuildPlan(recs, cfg).Accounts.Count);
    }
}
