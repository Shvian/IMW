"""Only the Windows user who created a workspace or database can use it.

Three locks, each enough on its own for most cases:

1. Folder and file permissions (NTFS ACLs). The workspace folder (inbox, database, config,
   outputs) and any database file are set so that only the owner, and SYSTEM, can open them:
   inherited permissions are removed, so Users, Authenticated Users and even Administrators
   have no access unless they take ownership first (which Windows logs and which needs
   admin rights). This is what stops another person who is signed in to the same machine.
2. An owner record. The workspace (.owner) and the database (meta table) record the owner's
   Windows SID. The Workbench refuses to open either for another SID, with a clear message.
3. The running Workbench only answers browser connections that come from a process of the
   same Windows user (Windows reports which process owns each loopback TCP connection).
   127.0.0.1 is shared by every session on a machine, so without this another signed-in
   user could reach the Workbench while it runs.

Secrets are also DPAPI-encrypted for the owner (protect.py), so even a copied database
does not give away a password.
"""

import getpass
import logging
import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("imw.owner")
OWNER_FILE = ".owner"
SYSTEM_SID = "S-1-5-18"


class OwnerError(Exception):
    pass


# ---------------------------------------------------------------- who am I

def _win_token_sid(token):
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    size = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))      # TokenUser
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
        raise OwnerError(f"GetTokenInformation failed ({ctypes.get_last_error()})")
    psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]              # TOKEN_USER.User.Sid
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out)):
        raise OwnerError(f"ConvertSidToStringSidW failed ({ctypes.get_last_error()})")
    try:
        sid = out.value
    finally:
        kernel32.LocalFree(out)
    return sid, psid, buf


def _win_account_name(psid):
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
    n, d, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
    if advapi32.LookupAccountSidW(None, ctypes.c_void_p(psid), name, ctypes.byref(n), domain,
                                  ctypes.byref(d), ctypes.byref(use)):
        return domain.value, name.value
    return "", ""


def _win_process_token(process_handle):
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process_handle, 0x0008, ctypes.byref(token)):   # TOKEN_QUERY
        return None
    return token


def current_identity():
    """{"sid", "domain", "user", "display"} of the user running this process (not from env vars)."""
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        token = _win_process_token(ctypes.c_void_p(kernel32.GetCurrentProcess()))
        if token is None:
            raise OwnerError("could not read this process's Windows account")
        try:
            sid, psid, _buf = _win_token_sid(token)
            domain, user = _win_account_name(psid)
        finally:
            kernel32.CloseHandle(token)
        return {"sid": sid, "domain": domain or ".", "user": user or getpass.getuser(),
                "display": f"{domain}\\{user}" if domain else (user or sid)}
    import pwd
    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    return {"sid": f"uid:{uid}", "domain": ".", "user": user, "display": user}


def token_sid(token):
    """SID of a Windows access token handle (for a logon token from LogonUserW)."""
    return _win_token_sid(token)[0]


# ---------------------------------------------------------------- permissions

def restrict(path, sid=None, recursive=False):
    """Only the owner (and SYSTEM) may open path. Returns a short description of what was set."""
    path = Path(path)
    if sys.platform == "win32":
        sid = sid or current_identity()["sid"]
        is_dir = path.is_dir()
        inherit = "(OI)(CI)" if is_dir else ""
        # The explicit grant goes on this folder (or file) only. Never combine an (OI)(CI) grant
        # with /T: icacls drops those ACEs on files and, with inheritance removed, leaves every
        # file with an EMPTY permission list that nobody can open.
        cmds = [["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:{inherit}F",
                 "/grant:r", f"*{SYSTEM_SID}:{inherit}F", "/C", "/Q"]]
        if recursive and is_dir and any(path.iterdir()):
            # Everything inside inherits owner + SYSTEM from the folder (also repairs files
            # that an earlier version left with an empty permission list).
            cmds.append(["icacls", str(path / "*"), "/reset", "/T", "/C", "/Q"])
        for cmd in cmds:
            done = subprocess.run(cmd, capture_output=True, text=True)
            if done.returncode != 0:
                raise OwnerError(f"could not restrict access to {path}: {(done.stdout + done.stderr).strip()}")
        return "owner and SYSTEM only"
    mode_dir, mode_file = 0o700, 0o600
    targets = [path]
    if recursive and path.is_dir():
        targets += list(path.rglob("*"))
    for t in targets:
        try:
            os.chmod(t, mode_dir if t.is_dir() else mode_file)
        except OSError:
            pass
    return "owner only (mode 700/600)"


# ---------------------------------------------------------------- workspace owner

WORKSPACE_ENTRIES = {OWNER_FILE, "inbox", "output", "tls", "config.json", "migration.db", "migration.db-journal",
                     "migration.db-wal", "migration.db-shm"}
ADMINISTRATORS_SID = "S-1-5-32-544"


def path_owner_sid(path):
    """Owner of a file or folder as recorded by the file system (Windows SID, or uid:N elsewhere)."""
    if sys.platform != "win32":
        return f"uid:{os.stat(path).st_uid}"
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,                     # name, SE_FILE_OBJECT, info
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),    # owner, group
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),    # dacl, sacl
        ctypes.POINTER(ctypes.c_void_p)]                                     # security descriptor
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    p_owner, p_sd = ctypes.c_void_p(), ctypes.c_void_p()
    rc = advapi32.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(p_owner), None, None, None, ctypes.byref(p_sd))
    if rc != 0:
        raise OwnerError(f"could not read the owner of {path} (Windows error {rc})")
    try:
        out = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(p_owner, ctypes.byref(out)):
            raise OwnerError("ConvertSidToStringSidW failed")
        sid = out.value
        kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
        return sid
    finally:
        kernel32.LocalFree(p_sd)


def _access_denied(ws, me, exc):
    """Explain an 'access denied' honestly: only blame another user when the folder really
    belongs to one; otherwise show what Windows refused and the usual causes."""
    what = f"{exc.filename} ({exc.strerror or exc})" if getattr(exc, "filename", None) else str(exc)
    try:
        folder_owner = path_owner_sid(ws)
    except Exception:  # noqa: BLE001
        folder_owner = None
    if folder_owner and folder_owner not in (me["sid"], ADMINISTRATORS_SID):
        return (f"{ws} belongs to another Windows user ({folder_owner}), so you can't open it. Use your "
                "own workspace folder (-w) or sign in to Windows as its owner.")
    hint = ""
    if sys.platform == "win32":
        hint = (" Common causes on Windows: Controlled folder access (Windows Security > Virus & threat "
                "protection > Ransomware protection) blocking Python in Documents or Desktop; antivirus; "
                "OneDrive sync; or files in the folder left with other permissions. Check with: icacls "
                f"\"{ws}\" /T. Or start with a workspace outside Documents, e.g. -w C:\\Workbench\\ws.")
    return (f"Windows refused access to {what}, although you ({me['display']}) "
            f"{'own' if folder_owner == me['sid'] else 'may own'} the workspace folder {ws}.{hint}")


def claim_workspace(ws):
    """Make sure ws belongs to the current user: record it on first use, refuse anyone else,
    and (re)apply owner-only permissions to the whole folder."""
    ws = Path(ws)
    me = current_identity()
    marker = ws / OWNER_FILE
    try:
        try:
            ws.mkdir(parents=True, exist_ok=True)
            existing = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else None
            entries = {p.name for p in ws.iterdir()}
        except PermissionError as exc:
            # Earlier versions could leave files in the owner's own workspace with an empty
            # permission list. The folder's owner may always reset them, so repair and retry once.
            if sys.platform != "win32" or path_owner_sid(ws) != me["sid"]:
                raise
            log.warning("access denied in your own workspace (%s); resetting its permissions", exc)
            restrict(ws, me["sid"], recursive=True)
            existing = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else None
            entries = {p.name for p in ws.iterdir()}
    except PermissionError as exc:
        raise OwnerError(_access_denied(ws, me, exc)) from None
    except ValueError:
        raise OwnerError(f"{marker} is damaged. Only the workspace owner can repair it.")
    if existing and existing.get("sid") != me["sid"]:
        raise OwnerError(f"This workspace belongs to {existing.get('name') or existing.get('sid')}. "
                         f"You are signed in to Windows as {me['display']}, so it stays closed. "
                         "Use your own workspace folder (-w), or sign in as its owner.")
    if not existing:
        other = sorted(entries - WORKSPACE_ENTRIES)
        if other:
            raise OwnerError(f"{ws} already holds other files ({', '.join(other[:5])}). The Workbench locks its "
                             "workspace folder to you alone, so pick an empty or new folder with -w.")
        if entries:   # a workspace from before owners were recorded: only the folder's owner may claim it
            folder_owner = path_owner_sid(ws)
            if folder_owner not in (me["sid"], ADMINISTRATORS_SID):
                raise OwnerError(f"{ws} was created by another Windows user ({folder_owner}). "
                                 "Only that user can open it; use your own workspace folder (-w).")
        marker.write_text(json.dumps({"sid": me["sid"], "name": me["display"]}), encoding="utf-8")
    restrict(ws, me["sid"], recursive=True)
    return me


# ---------------------------------------------------------------- who is connecting

def _win_peer_pid(client_ip, client_port, server_port):
    import ctypes
    from ctypes import wintypes
    iphlpapi = ctypes.WinDLL("iphlpapi")
    iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                             wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
    size = wintypes.DWORD(0)
    TCP_TABLE_OWNER_PID_CONNECTIONS, AF_INET = 4, 2
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
    for _ in range(5):
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wintypes.DWORD(len(buf))
        rc = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        if rc == 0:
            break
        if rc != 122:   # ERROR_INSUFFICIENT_BUFFER: the table grew, try again
            raise OwnerError(f"GetExtendedTcpTable failed ({rc})")
    else:
        raise OwnerError("GetExtendedTcpTable kept growing")
    raw = buf.raw
    count = struct.unpack_from("<I", raw, 0)[0]
    MIB_TCP_STATE_ESTAB = 5
    for i in range(count):
        state, laddr, lport, raddr, rport, pid = struct.unpack_from("<6I", raw, 4 + i * 24)
        if state != MIB_TCP_STATE_ESTAB:      # TIME_WAIT and other closed rows report pid 0
            continue
        if (socket.ntohs(lport & 0xFFFF) == client_port and socket.ntohs(rport & 0xFFFF) == server_port
                and socket.inet_ntoa(struct.pack("<I", laddr)) == client_ip):
            return pid
    return None


def peer_is_owner(client_address, server_port, owner_sid):
    """True when the process on the other end of this loopback connection runs as owner_sid.
    Anything that can't be confirmed counts as False."""
    if sys.platform != "win32":
        return True       # tests and demos only; the Workbench needs Windows for real use
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    pid = _win_peer_pid(client_address[0], client_address[1], server_port)
    if pid is None:
        return False
    if pid == os.getpid():
        return True
    handle = kernel32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False       # a standard user can't open another user's process: not ours
    try:
        token = _win_process_token(ctypes.c_void_p(handle))
        if token is None:
            return False
        try:
            return token_sid(token) == owner_sid
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
