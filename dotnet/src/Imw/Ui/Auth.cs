using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Imw.Core;

namespace Imw.Ui;

public class AuthError : Exception
{
    public AuthError(string message) : base(message) { }
}

/// <summary>
/// Sign-in for the Workbench: only the Windows user who started the tool can unlock it.
/// On Windows the password is checked by Windows itself (LogonUserW); nothing is stored. A password only
/// counts if Windows logs on that same account (same SID). Elsewhere there is no sign-in, except a test
/// password for automated tests (IMW_UI_TEST_PASSWORD), which must never be used with real data.
/// </summary>
public interface IAuthenticator
{
    string Kind { get; }
    string Display { get; }
    bool Check(string password);
}

public sealed class WindowsAuth : IAuthenticator
{
    readonly string _sid, _user, _domain;
    public string Kind => "windows";
    public string Display => $"{_domain}\\{_user}";

    public WindowsAuth()
    {
        var me = Owner.CurrentIdentity();
        (_sid, _user, _domain) = (me.Sid, me.User, string.IsNullOrEmpty(me.Domain) ? "." : me.Domain);
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUserW(string user, string domain, string password, int logonType, int provider, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    public bool Check(string password)
    {
        // Network logon first (no profile load); interactive if policy refuses that type.
        foreach (var logonType in new[] { 3, 2 })      // LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE
        {
            if (LogonUserW(_user, _domain, password, logonType, 0, out var token))
            {
                try { return Owner.TokenSid(token) == _sid; }
                finally { CloseHandle(token); }
            }
            if (Marshal.GetLastWin32Error() != 1385) return false;     // ERROR_LOGON_TYPE_NOT_GRANTED
        }
        return false;
    }
}

public sealed class TestAuth : IAuthenticator
{
    readonly string _password;
    readonly string _user;
    public string Kind => "test";
    public string Display => $"{_user} (test sign-in)";

    public TestAuth(string password)
    {
        _password = password;
        _user = Py.GetUser();
    }

    public bool Check(string password) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(password ?? ""), Encoding.UTF8.GetBytes(_password));
}

public static class Auth
{
    public static IAuthenticator Get(string testPassword = null)
    {
        testPassword = !string.IsNullOrEmpty(testPassword) ? testPassword : Environment.GetEnvironmentVariable("IMW_UI_TEST_PASSWORD");
        if (!string.IsNullOrEmpty(testPassword)) return new TestAuth(testPassword);
        if (OperatingSystem.IsWindows()) return new WindowsAuth();
        throw new AuthError("The Workbench sign-in uses your Windows password, so it needs Windows. For tests on " +
                            "other systems set IMW_UI_TEST_PASSWORD (never with real data).");
    }
}
