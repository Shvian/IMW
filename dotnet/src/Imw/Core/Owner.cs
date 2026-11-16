using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Imw.Core;

/// <summary>
/// Only the Windows user who created a workspace or database can use it (port of imw/owner.py).
///
/// 1. Folder and file permissions (NTFS ACLs): only the owner, and SYSTEM, can open them.
/// 2. An owner record: the workspace (.owner) and the database (meta table) record the owner's SID.
/// 3. The running Workbench only answers browser connections that come from a process of the same
///    Windows user (Windows reports which process owns each loopback TCP connection).
/// </summary>
public class OwnerError : Exception
{
    public OwnerError(string message) : base(message) { }
}

public sealed class Identity
{
    public string Sid, Domain, User, Display;
}

public static class Owner
{
    public const string OwnerFile = ".owner";
    public const string SystemSid = "S-1-5-18";
    public const string AdministratorsSid = "S-1-5-32-544";

    // Test hooks (the Python tests patch the same places with mock).
    internal static bool? ForceWindows;
    internal static Func<string, string[], (int, string)> RunHook;
    internal static Func<string, string> PathOwnerHook;
    internal static Action<string> ListHook;
    internal static Func<Identity> IdentityHook;

    public static readonly HashSet<string> WorkspaceEntries = new(StringComparer.Ordinal)
    {
        OwnerFile, "inbox", "output", "tls", "config.json", "migration.db", "migration.db-journal",
        "migration.db-wal", "migration.db-shm", "SAMPLE_DATA_README.txt",
    };

    [DllImport("libc", EntryPoint = "getuid")]
    static extern uint getuid();

    /// <summary>sid / domain / user / display of the user running this process (not from env vars).</summary>
    public static Identity CurrentIdentity()
    {
        if (IdentityHook != null) return IdentityHook();
        if (OperatingSystem.IsWindows())
        {
            using var me = WindowsIdentity.GetCurrent();
            var sid = me.User?.Value ?? throw new OwnerError("could not read this process's Windows account");
            string domain = "", user = "";
            try
            {
                var acct = ((NTAccount)me.User.Translate(typeof(NTAccount))).Value;
                int at = acct.IndexOf('\\');
                (domain, user) = at >= 0 ? (acct.Substring(0, at), acct.Substring(at + 1)) : ("", acct);
            }
            catch (IdentityNotMappedException) { }
            catch (SystemException) { }
            return new Identity
            {
                Sid = sid, Domain = domain.Length > 0 ? domain : ".", User = user.Length > 0 ? user : Py.GetUser(),
                Display = domain.Length > 0 ? $"{domain}\\{user}" : (user.Length > 0 ? user : sid),
            };
        }
        var uid = getuid();
        var name = Environment.UserName;
        return new Identity { Sid = $"uid:{uid}", Domain = ".", User = name, Display = name };
    }

    // ---------------------------------------------------------------- permissions

    static (int, string) Run(string exe, params string[] args)
    {
        if (RunHook != null) return RunHook(exe, args);
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new OwnerError($"could not run {exe}");
        var outText = p.StandardOutput.ReadToEndAsync();
        var errText = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, outText.Result + errText);
    }

    /// <summary>Only the owner (and SYSTEM) may open path. Returns a short description of what was set.</summary>
    public static string Restrict(string path, string sid = null, bool recursive = false)
    {
        if (ForceWindows ?? OperatingSystem.IsWindows())
        {
            sid ??= CurrentIdentity().Sid;
            bool isDir = Directory.Exists(path);
            var inherit = isDir ? "(OI)(CI)" : "";
            // The explicit grant goes on this folder (or file) only. Never combine an (OI)(CI) grant with /T.
            var cmds = new List<string[]>
            {
                new[] { path, "/inheritance:r", "/grant:r", $"*{sid}:{inherit}F", "/grant:r", $"*{SystemSid}:{inherit}F", "/C", "/Q" },
            };
            if (recursive && isDir && Directory.EnumerateFileSystemEntries(path).Any())
                // Everything inside inherits owner + SYSTEM from the folder.
                cmds.Add(new[] { Path.Combine(path, "*"), "/reset", "/T", "/C", "/Q" });
            foreach (var cmd in cmds)
            {
                var (rc, text) = Run("icacls", cmd);
                if (rc != 0) throw new OwnerError($"could not restrict access to {path}: {Py.Strip(text)}");
            }
            return "owner and SYSTEM only";
        }
        var targets = new List<string> { path };
        if (recursive && Directory.Exists(path))
            targets.AddRange(Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories));
        foreach (var t in targets)
        {
            try
            {
                var mode = Directory.Exists(t) ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                               : UnixFileMode.UserRead | UnixFileMode.UserWrite;
                File.SetUnixFileMode(t, mode);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        }
        return "owner only (mode 700/600)";
    }

    /// <summary>Owner of a file or folder as recorded by the file system (Windows SID, or uid:N elsewhere).</summary>
    public static string PathOwnerSid(string path)
    {
        if (PathOwnerHook != null) return PathOwnerHook(path);
        if (OperatingSystem.IsWindows())
        {
            try
            {
                FileSystemSecurity sec = Directory.Exists(path)
                    ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
                    : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
                return sec.GetOwner(typeof(SecurityIdentifier))?.Value ?? throw new OwnerError($"could not read the owner of {path}");
            }
            catch (Exception exc) when (exc is UnauthorizedAccessException or IOException or InvalidOperationException)
            {
                throw new OwnerError($"could not read the owner of {path} ({exc.Message})");
            }
        }
        var (rc, text) = Run("stat", OperatingSystem.IsMacOS() ? "-f" : "-c", "%u", path);
        if (rc != 0) throw new OwnerError($"could not read the owner of {path}");
        return "uid:" + Py.Strip(text);
    }

    static string AccessDenied(string ws, Identity me, Exception exc)
    {
        string folderOwner = null;
        try { folderOwner = PathOwnerSid(ws); } catch (Exception) { }
        if (folderOwner != null && folderOwner != me.Sid && folderOwner != AdministratorsSid)
            return $"{ws} belongs to another Windows user ({folderOwner}), so you can't open it. Use your " +
                   "own workspace folder (-w) or sign in to Windows as its owner.";
        var hint = "";
        if (OperatingSystem.IsWindows())
            hint = " Common causes on Windows: Controlled folder access (Windows Security > Virus & threat " +
                   "protection > Ransomware protection) blocking the Workbench in Documents or Desktop; antivirus; " +
                   "OneDrive sync; or files in the folder left with other permissions. Check with: icacls " +
                   $"\"{ws}\" /T. Or start with a workspace outside Documents, e.g. -w C:\\Workbench\\ws.";
        return $"Windows refused access to {exc.Message}, although you ({me.Display}) " +
               $"{(folderOwner == me.Sid ? "own" : "may own")} the workspace folder {ws}.{hint}";
    }

    static (JObj, HashSet<string>) ReadWorkspace(string ws, string marker)
    {
        Directory.CreateDirectory(ws);
        ListHook?.Invoke(ws);
        JObj existing = File.Exists(marker) ? Json.ParseObj(PyFile.ReadText(marker)) : null;
        var entries = Directory.EnumerateFileSystemEntries(ws).Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        return (existing, entries);
    }

    /// <summary>Make sure ws belongs to the current user: record it on first use, refuse anyone else,
    /// and (re)apply owner-only permissions to the whole folder.</summary>
    public static Identity ClaimWorkspace(string ws)
    {
        var me = CurrentIdentity();
        var marker = Path.Combine(ws, OwnerFile);
        JObj existing;
        HashSet<string> entries;
        try
        {
            try { (existing, entries) = ReadWorkspace(ws, marker); }
            catch (UnauthorizedAccessException exc)
            {
                // Earlier versions could leave files in the owner's own workspace with an empty permission
                // list. The folder's owner may always reset them, so repair and retry once.
                if (!OperatingSystem.IsWindows() || PathOwnerSid(ws) != me.Sid) throw;
                Log.Warning($"access denied in your own workspace ({exc.Message}); resetting its permissions");
                Restrict(ws, me.Sid, recursive: true);
                (existing, entries) = ReadWorkspace(ws, marker);
            }
        }
        catch (UnauthorizedAccessException exc)
        {
            throw new OwnerError(AccessDenied(ws, me, exc));
        }
        catch (ValueError)
        {
            throw new OwnerError($"{marker} is damaged. Only the workspace owner can repair it.");
        }
        if (existing != null && existing.Count > 0 && !Py.Eq(existing.Get("sid"), me.Sid))
            throw new OwnerError($"This workspace belongs to {Py.Str(Py.Or(existing.Get("name"), existing.Get("sid")))}. " +
                                 $"You are signed in to Windows as {me.Display}, so it stays closed. " +
                                 "Use your own workspace folder (-w), or sign in as its owner.");
        if (existing == null || existing.Count == 0)
        {
            var other = Py.Sorted(entries.Where(e => !WorkspaceEntries.Contains(e)));
            if (other.Count > 0)
                throw new OwnerError($"{ws} already holds other files ({string.Join(", ", other.Take(5))}). The Workbench locks its " +
                                     "workspace folder to you alone, so pick an empty or new folder with -w.");
            if (entries.Count > 0)
            {
                // A workspace from before owners were recorded: only the folder's owner may claim it.
                var folderOwner = PathOwnerSid(ws);
                if (folderOwner != me.Sid && folderOwner != AdministratorsSid)
                    throw new OwnerError($"{ws} was created by another Windows user ({folderOwner}). " +
                                         "Only that user can open it; use your own workspace folder (-w).");
            }
            PyFile.WriteText(marker, Json.Dumps(Json.O(("sid", me.Sid), ("name", me.Display))));
        }
        Restrict(ws, me.Sid, recursive: true);
        return me;
    }

    // ---------------------------------------------------------------- who is connecting

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr mem);

    /// <summary>SID of a Windows access token handle (for a logon token from LogonUserW).</summary>
    public static string TokenSid(IntPtr token)
    {
        GetTokenInformation(token, 1, IntPtr.Zero, 0, out int size);           // TokenUser
        var buf = Marshal.AllocHGlobal(Math.Max(size, 1));
        try
        {
            if (!GetTokenInformation(token, 1, buf, size, out size))
                throw new OwnerError($"GetTokenInformation failed ({Marshal.GetLastWin32Error()})");
            var psid = Marshal.ReadIntPtr(buf);                                  // TOKEN_USER.User.Sid
            if (!ConvertSidToStringSidW(psid, out var str))
                throw new OwnerError($"ConvertSidToStringSidW failed ({Marshal.GetLastWin32Error()})");
            try { return Marshal.PtrToStringUni(str); }
            finally { LocalFree(str); }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static uint? PeerPid(string clientIp, int clientPort, int serverPort)
    {
        const int TcpTableOwnerPidConnections = 4, AfInet = 2;
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidConnections, 0);
        IntPtr buf = IntPtr.Zero;
        try
        {
            bool ok = false;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                size += 4096;
                buf = Marshal.AllocHGlobal(size);
                var rc = GetExtendedTcpTable(buf, ref size, false, AfInet, TcpTableOwnerPidConnections, 0);
                if (rc == 0) { ok = true; break; }
                if (rc != 122) throw new OwnerError($"GetExtendedTcpTable failed ({rc})");   // ERROR_INSUFFICIENT_BUFFER
            }
            if (!ok) throw new OwnerError("GetExtendedTcpTable kept growing");
            int count = Marshal.ReadInt32(buf, 0);
            const int Established = 5;
            for (int i = 0; i < count; i++)
            {
                int off = 4 + i * 24;
                uint state = (uint)Marshal.ReadInt32(buf, off);
                uint laddr = (uint)Marshal.ReadInt32(buf, off + 4);
                uint lport = (uint)Marshal.ReadInt32(buf, off + 8);
                uint rport = (uint)Marshal.ReadInt32(buf, off + 16);
                uint pid = (uint)Marshal.ReadInt32(buf, off + 20);
                if (state != Established) continue;     // TIME_WAIT and other closed rows report pid 0
                int lp = ((int)(lport & 0xFF) << 8) | (int)((lport >> 8) & 0xFF);
                int rp = ((int)(rport & 0xFF) << 8) | (int)((rport >> 8) & 0xFF);
                var ip = new IPAddress(BitConverter.GetBytes(laddr)).ToString();
                if (lp == clientPort && rp == serverPort && ip == clientIp) return pid;
            }
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>True when the process on the other end of this loopback connection runs as ownerSid.
    /// Anything that can't be confirmed counts as false.</summary>
    public static bool PeerIsOwner(string clientIp, int clientPort, int serverPort, string ownerSid)
    {
        if (!OperatingSystem.IsWindows()) return true;   // tests and demos only; the Workbench needs Windows for real use
        var pid = PeerPid(clientIp, clientPort, serverPort);
        if (pid == null) return false;
        if (pid == (uint)Environment.ProcessId) return true;
        var handle = OpenProcess(0x1000, false, pid.Value);                    // PROCESS_QUERY_LIMITED_INFORMATION
        if (handle == IntPtr.Zero) return false;                                // another user's process: not ours
        try
        {
            if (!OpenProcessToken(handle, 0x0008, out var token)) return false;  // TOKEN_QUERY
            try { return TokenSid(token) == ownerSid; }
            catch (OwnerError) { return false; }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(handle); }
    }
}
