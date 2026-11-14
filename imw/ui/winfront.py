"""Bring a just-opened Explorer window to the front (Windows only, best effort).

Windows' foreground lock stops a background program (the Workbench server runs in a
console window, not the browser) from giving focus to the window it opens, so Explorer
appears behind the browser. This finds the Explorer window showing the folder and raises
it, using the two standard ways round the lock: a harmless synthetic key press (the process
that sent the last input may set the foreground window) and attaching to the input of the
current foreground window while calling SetForegroundWindow.
"""

import sys
import threading
import time
from pathlib import Path

EXPLORER_CLASS = "CabinetWClass"
SW_RESTORE = 9
VK_F24 = 0x87               # a key no keyboard has, so the press does nothing else
KEYEVENTF_KEYUP = 0x0002


def _find_explorer(user32, names):
    import ctypes
    from ctypes import wintypes
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        cls = ctypes.create_unicode_buffer(64)
        user32.GetClassNameW(hwnd, cls, 64)
        if cls.value != EXPLORER_CLASS:
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, title, n + 1)
        # Explorer titles a window with the folder name, or the full path when "Display the
        # full path in the title bar" is on. Windows 11 adds " - File Explorer" (in the user's
        # language), and " and 2 more tabs" when the window has tabs.
        t = title.value.strip().lower()
        if any(t == n or t.startswith(n + " - ") or t.startswith(n + " and ") for n in names):
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


def _raise(user32, kernel32, hwnd):
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, SW_RESTORE)
    user32.keybd_event(VK_F24, 0, 0, 0)
    user32.keybd_event(VK_F24, 0, KEYEVENTF_KEYUP, 0)
    fg = user32.GetForegroundWindow()
    here = kernel32.GetCurrentThreadId()
    there = user32.GetWindowThreadProcessId(fg, None) if fg else 0
    attached = bool(there and there != here and user32.AttachThreadInput(here, there, True))
    try:
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(here, there, False)
    if user32.GetForegroundWindow() != hwnd:
        # Last resort: what Alt+Tab uses; not limited by the foreground lock.
        user32.SwitchToThisWindow(hwnd, True)


def bring_to_front(path, timeout=4.0):
    """Wait (in a background thread) for the Explorer window of path, then raise it."""
    if sys.platform != "win32":
        return

    def run():
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.WinDLL("user32")
            kernel32 = ctypes.WinDLL("kernel32")
            # Window handles are pointer-sized: declare them so 64-bit Python does not cut them.
            H, BOOL, DWORD = wintypes.HWND, wintypes.BOOL, wintypes.DWORD
            for name, args, res in (("IsWindowVisible", [H], BOOL), ("IsIconic", [H], BOOL),
                                    ("ShowWindow", [H, ctypes.c_int], BOOL),
                                    ("GetClassNameW", [H, wintypes.LPWSTR, ctypes.c_int], ctypes.c_int),
                                    ("GetWindowTextLengthW", [H], ctypes.c_int),
                                    ("GetWindowTextW", [H, wintypes.LPWSTR, ctypes.c_int], ctypes.c_int),
                                    ("GetForegroundWindow", [], H),
                                    ("GetWindowThreadProcessId", [H, ctypes.c_void_p], DWORD),
                                    ("AttachThreadInput", [DWORD, DWORD, BOOL], BOOL),
                                    ("BringWindowToTop", [H], BOOL), ("SetForegroundWindow", [H], BOOL),
                                    ("SwitchToThisWindow", [H, BOOL], None)):
                fn = getattr(user32, name)
                fn.argtypes, fn.restype = args, res
            kernel32.GetCurrentThreadId.restype = DWORD
            p = Path(path)
            names = {str(p).lower(), p.name.lower()}
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                hwnd = _find_explorer(user32, names)
                if hwnd:
                    _raise(user32, kernel32, hwnd)
                    return
                time.sleep(0.15)
        except Exception:      # noqa: BLE001 - cosmetic; the folder is open either way
            pass

    threading.Thread(target=run, name="imw-raise-explorer", daemon=True).start()
