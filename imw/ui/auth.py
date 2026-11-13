"""Sign-in for the Workbench: only the Windows user who started the tool can unlock it.

On Windows the password is checked by Windows itself (LogonUserW); nothing is stored. The
account is read from this process's own token (not from environment variables, which anyone
can change), and a password only counts if Windows logs on that same account (same SID).
Elsewhere there is no sign-in, except a test password for automated tests
(IMW_UI_TEST_PASSWORD), which must never be used with real data.
"""

import getpass
import os
import sys


class AuthError(Exception):
    pass


class WindowsAuth:
    kind = "windows"

    def __init__(self):
        from ..owner import current_identity
        me = current_identity()
        self.sid, self.user, self.domain = me["sid"], me["user"], me["domain"] or "."

    @property
    def display(self):
        return f"{self.domain}\\{self.user}"

    def check(self, password):
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        logon = advapi32.LogonUserW
        logon.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                          wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        logon.restype = wintypes.BOOL
        # Network logon first (no profile load); interactive if policy refuses that type.
        for logon_type in (3, 2):   # LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE
            token = wintypes.HANDLE()
            if logon(self.user, self.domain, password, logon_type, 0, ctypes.byref(token)):
                try:
                    from ..owner import token_sid
                    return token_sid(token) == self.sid
                finally:
                    kernel32.CloseHandle(token)
            if ctypes.get_last_error() != 1385:   # ERROR_LOGON_TYPE_NOT_GRANTED
                return False
        return False


class TestAuth:
    kind = "test"

    def __init__(self, password):
        self.password = password
        self.user = getpass.getuser()

    @property
    def display(self):
        return f"{self.user} (test sign-in)"

    def check(self, password):
        import hmac
        return hmac.compare_digest(password.encode(), self.password.encode())


def get_authenticator(test_password=None):
    test_password = test_password or os.environ.get("IMW_UI_TEST_PASSWORD")
    if test_password:
        return TestAuth(test_password)
    if sys.platform == "win32":
        return WindowsAuth()
    raise AuthError("The Workbench sign-in uses your Windows password, so it needs Windows. For tests on "
                    "other systems set IMW_UI_TEST_PASSWORD (never with real data).")
