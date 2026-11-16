using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Imw.Ui;

namespace Imw.Tests;

// Port of tests/test_store.py and tests/test_tls.py

public class StoreFlow : TestBase
{
    readonly string db;
    public StoreFlow() { db = T("m.db"); }

    void Ingest(params string[] extra)
    {
        var (rc, text) = RunCli(new[] { "ingest", "--db", db, "--insecure-plaintext-secrets", "-i", S("delinea_export.csv"),
                                        "-p", S("delinea_permissions.csv") }.Concat(extra).ToArray());
        Assert.True(rc == 0, text);
    }

    void Map()
    {
        var (rc, text) = RunCli("map", "--db", db, "-c", S("config_delinea.json"));
        Assert.True(rc == 0, text);
    }

    [Fact]
    public void FullFlowAndWave()
    {
        Ingest("-i", S("keepass_export.xml"));
        Map();
        Assert.Equal(0, RunCli("set", "--db", db, "--where", "target_safe = 'IT-Backup'", "--migrate", "N").Item1);
        Assert.Equal(0, RunCli("set", "--db", db, "-r", "delinea:delinea_export:107", "--safe", "FIN:Portals").Item1);
        var out_ = T("wave1");
        var (rc, text) = RunCli("extract", "--db", db, "-o", out_, "--where", "source = 'delinea'", "--include-secrets");
        Assert.True(rc == 0, text);
        var accounts = ReadCsv(Path.Combine(out_, "upload", "Accounts.csv")).ToDictionary(a => a["Name"]);
        Assert.False(accounts.ContainsKey("svc_backup"));                // 102, Migrate=N
        Assert.Equal("FIN-Portals", accounts["Vendor Portal"]["SafeName"]);        // edit, cleaned
        Assert.Equal("P@ssw0rd!1", accounts["svc_sql_prod"]["Secret"]);
        Assert.Equal(12, ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv")).Count);   // review covers everything
        AssertNoSecrets(Path.Combine(out_, "review"));
    }

    [Fact]
    public void QueryCannotReadSecretsOrWrite()
    {
        Ingest();
        Map();
        using var st = new Store(db);
        var (_, rows) = st.Query("SELECT secret_enc FROM records");
        Assert.All(rows, r => Assert.Null(r[0]));
        Assert.Throws<StoreError>(() => st.Query("DELETE FROM records"));
        Assert.Throws<StoreError>(() => st.Query($"ATTACH DATABASE '{T("x.db")}' AS x"));
        Assert.Equal("plain:P@ssw0rd!1", st.Db.Scalar("SELECT secret_enc FROM records WHERE record_id LIKE '%:101'"));
    }

    [Fact]
    public void ReingestReplacesAndKeepsEdits()
    {
        Ingest();
        Map();
        RunCli("set", "--db", db, "-r", "delinea:delinea_export:101", "--platform", "WinDomainCustom");
        Ingest();
        Map();
        using var st = new Store(db);
        Assert.Equal(8L, st.Db.Scalar("SELECT COUNT(*) FROM records"));
        var row = st.Db.One("SELECT platform_id, platform_source FROM plan_accounts WHERE record_id = 'delinea:delinea_export:101'");
        Assert.Equal(("WinDomainCustom", "override"), ((string)row[0], (string)row[1]));
    }

    [Fact]
    public void ImportReview()
    {
        Ingest();
        Map();
        var out_ = T("r");
        RunCli("extract", "--db", db, "-o", out_);
        var rows = ReadCsv(Path.Combine(out_, "review", "Accounts_Review.csv"));
        foreach (var r in rows) if (r["Record_ID"].EndsWith(":108")) r["Migrate"] = "N";
        var edited = T("edited.csv");
        WriteDictCsv(edited, rows);
        var (rc, text) = RunCli("set", "--db", db, "--from-review", edited);
        Assert.True(rc == 0, text);
        Assert.Contains("1 records", text);
        using var st = new Store(db);
        Assert.Equal(1L, st.Db.Scalar("SELECT COUNT(*) FROM edits"));
    }

    [Fact]
    public void NoSecretsMode()
    {
        Assert.Equal(0, RunCli("ingest", "--db", db, "--no-secrets", "-i", S("delinea_export.csv")).Item1);
        Map();
        Assert.Equal(2, RunCli("extract", "--db", db, "-o", T("o"), "--include-secrets").Item1);    // nothing to decrypt
        Assert.Equal(0, RunCli("extract", "--db", db, "-o", T("o")).Item1);
    }

    [Fact]
    public void DpapiRefusedOffWindows()
    {
        if (OperatingSystem.IsWindows()) return;                // checks the non-Windows refusal
        Assert.Equal(2, RunCli("ingest", "--db", db, "-i", S("delinea_export.csv")).Item1);
        Assert.Throws<ProtectError>(() => new DpapiProtector(Protectors.NewSalt()));
    }

    [Fact]
    public void DpapiRoundTrip()
    {
        if (!OperatingSystem.IsWindows()) return;               // Windows DPAPI
        var p = new DpapiProtector(Protectors.NewSalt());
        var blob = p.Protect("S3cret!", "rec1");
        Assert.StartsWith("dpapi:", blob);
        Assert.DoesNotContain("S3cret", blob);
        Assert.Equal("S3cret!", p.Unprotect(blob, "rec1"));
        Assert.Throws<ProtectError>(() => p.Unprotect(blob, "rec2"));                                // bound to the record id
        Assert.Throws<ProtectError>(() => new DpapiProtector(Protectors.NewSalt()).Unprotect(blob, "rec1"));   // bound to the database
    }
}

public class Certificate : TestBase
{
    public override void Dispose()
    {
        Tls.MachineNamesOverride = null;
        base.Dispose();
    }

    [Fact]
    public void MadeOnceThenReused()
    {
        var (cert, key, created) = Tls.EnsureCertificate(Tmp);
        Assert.True(created);
        Assert.Contains("BEGIN RSA PRIVATE KEY", key);
        var left = Tls.CertExpiry(File.ReadAllText(cert)) - DateTimeOffset.UtcNow;
        Assert.True(left > TimeSpan.FromDays(390) && left < TimeSpan.FromDays(398));
        var again = Tls.EnsureCertificate(Tmp);
        Assert.False(again.Item3);
        Assert.Equal(key, again.Item2);
        Assert.True(Tls.EnsureCertificate(Tmp, renew: true).Item3);
    }

    /// <summary>A TLS handshake to the certificate, as a browser does it: the name and the signature must check out.</summary>
    internal static SslProtocols Handshake(X509Certificate2 serverCert, string certPath, string host)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var conn = await listener.AcceptTcpClientAsync();
            using var s = new SslStream(conn.GetStream());
            await s.AuthenticateAsServerAsync(serverCert);
            _ = await s.ReadAsync(new byte[1]);   // waits for the client to finish; any byte count is fine
        });
        using var root = X509Certificate2.CreateFromPem(File.ReadAllText(certPath));
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        using var ssl = new SslStream(client.GetStream(), false, (_, cert, _, errors) =>
        {
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || cert == null) return false;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(new X509Certificate2(cert));
        });
        ssl.AuthenticateAsClient(host);
        ssl.Write(new byte[] { (byte)'x' });
        server.Wait(10000);
        listener.Stop();
        return ssl.SslProtocol;
    }

    [Fact]
    public void ClientsAcceptItFor127001AndLocalhost()
    {
        var (cert, certPath, _) = Tls.ServerCertificate(Tmp);
        Assert.Equal(2, Directory.GetFiles(Path.Combine(Tmp, "tls")).Length);    // no key file left behind
        Assert.Equal(95, Tls.Fingerprint(certPath).Length);
        foreach (var host in new[] { "127.0.0.1", "localhost" })
            Assert.Contains(Handshake(cert, certPath, host), new[] { SslProtocols.Tls12, SslProtocols.Tls13 });
    }

    [Fact]
    public void NamedAfterThisComputer()
    {
        var (cert, _, _) = Tls.EnsureCertificate(Tmp);
        var names = Tls.CertDnsNames(File.ReadAllText(cert));
        Assert.True(Tls.MachineNames().All(names.Contains));
        Assert.Contains("localhost", names);
        Tls.MachineNamesOverride = () => new List<string> { "jumphost01.corp.example.com", "jumphost01" };
        bool created;
        (cert, _, created) = Tls.EnsureCertificate(Tmp);             // renamed computer: new certificate
        Assert.True(created);
        Assert.Equal(new[] { "jumphost01.corp.example.com", "jumphost01" }, Tls.CertDnsNames(File.ReadAllText(cert)).Take(2));
        Assert.False(Tls.EnsureCertificate(Tmp).Item3);
        var (serverCert, certPath, _) = Tls.ServerCertificate(Tmp);
        Handshake(serverCert, certPath, "jumphost01.corp.example.com");
    }

    [Fact]
    public void DamagedKeyMakesANewPair()
    {
        var (cert, _, _) = Tls.EnsureCertificate(Tmp);
        var before = File.ReadAllText(cert);
        File.WriteAllText(Path.Combine(Tmp, "tls", OperatingSystem.IsWindows() ? Tls.KeyDpapi : Tls.KeyPem), "rubbish");
        var (_, certPath, created) = Tls.ServerCertificate(Tmp);
        Assert.True(created);
        Assert.NotEqual(before, File.ReadAllText(certPath));
    }

    [Fact]
    public void OpensslVerifiesSignature()
    {
        if (UiApp.Which("openssl") == null) return;              // openssl not installed
        var (cert, _, _) = Tls.EnsureCertificate(Tmp);
        var psi = new System.Diagnostics.ProcessStartInfo("openssl") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "verify", "-CAfile", cert, "-purpose", "sslserver", cert }) psi.ArgumentList.Add(a);
        using var p = System.Diagnostics.Process.Start(psi);
        var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, text);
    }

    [Fact]
    public void PythonMadeCertificateIsUsed()
    {
        // Same files as the Python version: a workspace made by either version keeps its certificate.
        var (cert, key, _) = Tls.EnsureCertificate(Tmp);
        var (_, certPath, created) = Tls.ServerCertificate(Tmp);
        Assert.False(created);
        Assert.Equal(cert, certPath);
        Assert.Contains("BEGIN RSA PRIVATE KEY", key);
    }
}
