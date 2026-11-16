using System.Security.Cryptography;
using System.Text;

namespace Imw.Core;

// Secret protection for values stored in the local database (port of imw/protect.py).
//
// dpapi    Windows DPAPI (CryptProtectData). A value can be decrypted only by the same Windows
//          account on the same machine (or the account's roaming profile in a domain). Each value
//          is bound to the database salt and its record id as extra entropy, so a blob copied into
//          another database or row will not decrypt. Blobs are the same as the Python version's.
// plain    NO protection. Only for tests and demos on non-Windows machines.

public class ProtectError : Exception
{
    public ProtectError(string message) : base(message) { }
}

public interface IProtector
{
    string Name { get; }
    string Protect(string plaintext, string recordId);
    string Unprotect(string stored, string recordId);
}

public sealed class DpapiProtector : IProtector
{
    readonly byte[] _salt;
    public string Name => "dpapi";

    public DpapiProtector(byte[] salt)
    {
        if (!OperatingSystem.IsWindows())
            throw new ProtectError("Windows DPAPI is only available on Windows. Run on the Windows " +
                                   "migration host, or use --no-secrets to stage metadata only.");
        _salt = salt;
    }

    byte[] Entropy(string recordId) => _salt.Concat(Encoding.UTF8.GetBytes(recordId)).ToArray();

    public static byte[] ProtectBytes(byte[] data, byte[] entropy)
    {
        if (!OperatingSystem.IsWindows()) throw new ProtectError("Windows DPAPI is only available on Windows.");
        try { return ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser); }
        catch (CryptographicException exc)
        {
            throw new ProtectError($"DPAPI call failed ({exc.Message}). A database can only be decrypted by the Windows account that created it.");
        }
    }

    public static byte[] UnprotectBytes(byte[] blob, byte[] entropy)
    {
        if (!OperatingSystem.IsWindows()) throw new ProtectError("Windows DPAPI is only available on Windows.");
        try { return ProtectedData.Unprotect(blob, entropy, DataProtectionScope.CurrentUser); }
        catch (CryptographicException exc)
        {
            throw new ProtectError($"DPAPI call failed ({exc.Message}). A database can only be decrypted by the Windows account that created it.");
        }
    }

    public string Protect(string plaintext, string recordId)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        try { return "dpapi:" + Convert.ToBase64String(ProtectBytes(data, Entropy(recordId))); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }

    public string Unprotect(string stored, string recordId)
    {
        if (!stored.StartsWith("dpapi:", StringComparison.Ordinal)) throw new ProtectError("value was not stored with DPAPI");
        var data = UnprotectBytes(Convert.FromBase64String(stored.Substring(6)), Entropy(recordId));
        try { return Encoding.UTF8.GetString(data); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
}

/// <summary>No protection at all. Tests and non-Windows demos only.</summary>
public sealed class PlainProtector : IProtector
{
    public string Name => "plain";
    public PlainProtector(byte[] salt) { }
    public string Protect(string plaintext, string recordId) => "plain:" + plaintext;

    public string Unprotect(string stored, string recordId)
    {
        if (!stored.StartsWith("plain:", StringComparison.Ordinal)) throw new ProtectError("value was not stored as plain text");
        return stored.Substring(6);
    }
}

public static class Protectors
{
    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(16);

    public static IProtector Get(string name, byte[] salt) => name switch
    {
        "dpapi" => new DpapiProtector(salt),
        "plain" => new PlainProtector(salt),
        _ => throw new ProtectError($"unknown protector '{name}'"),
    };
}
