using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Imw.Core;

namespace Imw.Ui;

public class TlsError : Exception
{
    public TlsError(string message) : base(message) { }
}

/// <summary>
/// HTTPS for the Workbench with a self-signed certificate, kept in
/// &lt;workspace&gt;/tls in the same files as the Python version, so either version can use it:
///
///   workbench.crt         the certificate (public, PEM). Trust it once with --trust-cert.
///   workbench.key.dpapi   the private key (PKCS#1 PEM), encrypted with Windows DPAPI for your user.
///                         On other systems (tests only) workbench.key.pem, readable by you only.
///
/// RSA 2048 / SHA-256, subject = this computer's name, SAN = full DNS name, host name, localhost,
/// 127.0.0.1 and ::1, valid 397 days, remade when the computer's name no longer matches.
/// </summary>
public static class Tls
{
    public const string CertName = "workbench.crt";
    public const string KeyDpapi = "workbench.key.dpapi";
    public const string KeyPem = "workbench.key.pem";
    public const int ValidDays = 397;      // browsers reject longer-lived server certificates
    public const int RenewDays = 30;       // make a new one when less than this is left
    public const string Organization = "Idira Migration Workbench";

    static readonly Regex DnsName = new(
        @"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$");

    /// <summary>Test hook: replaces machine_names().</summary>
    public static Func<List<string>> MachineNamesOverride;

    /// <summary>This computer's DNS names, most specific first: full DNS name, then host name.</summary>
    public static List<string> MachineNames()
    {
        if (MachineNamesOverride != null) return MachineNamesOverride();
        var names = new List<string>();
        string host = "", fqdn = "";
        try { host = Dns.GetHostName(); } catch (Exception) { }
        try { fqdn = Dns.GetHostEntry(host).HostName; } catch (Exception) { fqdn = host; }
        foreach (var raw in new[] { fqdn, host })
        {
            var n = Py.Lower(Py.RStrip(Py.Strip(raw ?? ""), "."));
            if (n.Length > 0 && DnsName.IsMatch(n) && !names.Contains(n) && n != "localhost" && !n.Replace(".", "").All(char.IsAsciiDigit))
                names.Add(n);
        }
        return names;
    }

    public static X509Certificate2 MakeCertificate(RSA key, DateTimeOffset? now = null, int days = ValidDays, List<string> names = null)
    {
        var t = (now ?? DateTimeOffset.UtcNow);
        t = new DateTimeOffset(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, TimeSpan.Zero);
        names ??= MachineNames();
        var subject = names.Count > 0 ? names[0] : "localhost";
        var dn = new X500DistinguishedNameBuilder();
        dn.AddCommonName(subject);
        dn.AddOrganizationName(Organization);
        var req = new CertificateRequest(dn.Build(), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names.Concat(new[] { "localhost" })) san.AddDnsName(n);
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var serial = RandomNumberGenerator.GetBytes(8);
        serial[0] = (byte)((serial[0] & 0x3F) | 0x40);      // 63 bits, top bit set: positive and full length
        return req.Create(dn.Build(), X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
                          t.AddMinutes(-5), t.AddDays(days), serial);
    }

    public static string Pem(string label, byte[] der)
    {
        var body = Convert.ToBase64String(der);
        var sb = new StringBuilder($"-----BEGIN {label}-----\n");
        for (int i = 0; i < body.Length; i += 64) sb.Append(body, i, Math.Min(64, body.Length - i)).Append('\n');
        return sb.Append($"-----END {label}-----\n").ToString();
    }

    public static List<string> CertDnsNames(string certPem)
    {
        using var cert = X509Certificate2.CreateFromPem(certPem);
        var ext = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        return ext == null ? new List<string>() : ext.EnumerateDnsNames().Select(n => n.ToLowerInvariant()).ToList();
    }

    public static DateTimeOffset CertExpiry(string certPem)
    {
        using var cert = X509Certificate2.CreateFromPem(certPem);
        return new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
    }

    // ---------------------------------------------------------------- key storage

    // The old name stays in this key: changing it would make existing certificates unreadable.
    static readonly byte[] DpapiSalt = Encoding.ASCII.GetBytes("pam2pc-workbench-tls");

    static void SaveKey(string folder, string keyPem)
    {
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(Path.Combine(folder, KeyDpapi), new DpapiProtector(DpapiSalt).Protect(keyPem, "workbench-key"), Encoding.ASCII);
            return;
        }
        var path = Path.Combine(folder, KeyPem);
        using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        var bytes = Encoding.UTF8.GetBytes(keyPem);
        fs.Write(bytes);
    }

    static string LoadKey(string folder)
    {
        if (OperatingSystem.IsWindows())
        {
            var p = Path.Combine(folder, KeyDpapi);
            return File.Exists(p) ? new DpapiProtector(DpapiSalt).Unprotect(File.ReadAllText(p, Encoding.ASCII), "workbench-key") : null;
        }
        var path = Path.Combine(folder, KeyPem);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    /// <summary>(cert path, key PEM, created). Makes a new pair when missing, unreadable, near expiry, or made
    /// for another computer name.</summary>
    public static (string, string, bool) EnsureCertificate(string workspace, bool renew = false)
    {
        var folder = Path.Combine(workspace, "tls");
        Directory.CreateDirectory(folder);
        var certPath = Path.Combine(folder, CertName);
        if (!renew && File.Exists(certPath))
        {
            try
            {
                var keyPem = LoadKey(folder);
                var pem = File.ReadAllText(certPath);
                var left = CertExpiry(pem) - DateTimeOffset.UtcNow;
                var named = MachineNames().All(CertDnsNames(pem).Contains);    // same computer name
                if (!string.IsNullOrEmpty(keyPem) && named && left > TimeSpan.FromDays(RenewDays)) return (certPath, keyPem, false);
            }
            catch (Exception) { }   // unreadable (other Windows user, damaged): make a new one
        }
        using var rsa = RSA.Create(2048);
        var key = rsa.ExportRSAPrivateKeyPem().Replace("\r\n", "\n") + "\n";
        using var cert = MakeCertificate(rsa);
        SaveKey(folder, key);
        File.WriteAllText(certPath, Pem("CERTIFICATE", cert.RawData), Encoding.ASCII);
        return (certPath, key, true);
    }

    /// <summary>The certificate with its private key, ready for the HTTPS server.</summary>
    static X509Certificate2 Load(string certPath, string keyPem)
    {
        using var pemCert = X509Certificate2.CreateFromPem(File.ReadAllText(certPath), keyPem);
        // Windows' TLS stack needs the key in a key container, not only in memory.
        var pfx = pemCert.Export(X509ContentType.Pkcs12);
        try
        {
            return X509CertificateLoader.LoadPkcs12(pfx, null,
                OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
        }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }

    /// <summary>The server certificate, plus (cert path, created).</summary>
    public static (X509Certificate2, string, bool) ServerCertificate(string workspace, bool renew = false)
    {
        var (certPath, keyPem, created) = EnsureCertificate(workspace, renew);
        try { return (Load(certPath, keyPem), certPath, created); }
        catch (Exception) when (!created)
        {
            (certPath, keyPem, created) = EnsureCertificate(workspace, renew: true);   // damaged pair
            return (Load(certPath, keyPem), certPath, created);
        }
    }

    public static string Fingerprint(string certPath)
    {
        using var cert = X509Certificate2.CreateFromPem(File.ReadAllText(certPath));
        var h = Convert.ToHexString(SHA256.HashData(cert.RawData));
        return string.Join(":", Enumerable.Range(0, h.Length / 2).Select(i => h.Substring(i * 2, 2)));
    }

    /// <summary>Adds the certificate to the current Windows user's Trusted Root store (Windows asks to confirm).</summary>
    public static void TrustCertificate(string certPath)
    {
        if (!OperatingSystem.IsWindows()) throw new TlsError("--trust-cert works on Windows only. Elsewhere, trust the file in your browser.");
        var psi = new ProcessStartInfo("certutil") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "-user", "-addstore", "Root", certPath }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new TlsError("could not run certutil");
        var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new TlsError($"certutil could not add the certificate: {Py.Strip(text)}");
    }
}
