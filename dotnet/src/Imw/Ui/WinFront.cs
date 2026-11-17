using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Imw.Ui;

/// <summary>
/// Bring a just-opened Explorer window to the front (Windows only, best effort).
/// Windows' foreground lock stops a background program from giving focus to the window it opens, so
/// Explorer would appear behind the browser. This finds the Explorer window showing the folder and raises it.
/// </summary>
public static class WinFront
{
    const string ExplorerClass = "CabinetWClass";
    const int SwRestore = 9;
    const byte VkF24 = 0x87;              // a key no keyboard has, so the press does nothing else
    const int KeyeventfKeyup = 0x0002;

    delegate bool EnumProc(IntPtr hwnd, IntPtr lparam);

    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc fn, IntPtr lparam);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int cmd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder buf, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextLengthW(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hwnd, StringBuilder buf, int max);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr pid);
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] static extern void SwitchToThisWindow(IntPtr hwnd, bool altTab);
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, int flags, IntPtr extra);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();

    static IntPtr FindExplorer(HashSet<string> names)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, _) =>
        {
            if (!IsWindowVisible(hwnd)) return true;
            var cls = new StringBuilder(64);
            GetClassNameW(hwnd, cls, 64);
            if (cls.ToString() != ExplorerClass) return true;
            int n = GetWindowTextLengthW(hwnd);
            var title = new StringBuilder(n + 1);
            GetWindowTextW(hwnd, title, n + 1);
            // Explorer titles a window with the folder name, or the full path; Windows 11 adds " - File Explorer"
            // (in the user's language), and " and 2 more tabs" when the window has tabs.
            var t = title.ToString().Trim().ToLowerInvariant();
            if (names.Any(x => t == x || t.StartsWith(x + " - ") || t.StartsWith(x + " and ")))
            {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static void Raise(IntPtr hwnd)
    {
        if (IsIconic(hwnd)) ShowWindow(hwnd, SwRestore);
        keybd_event(VkF24, 0, 0, IntPtr.Zero);
        keybd_event(VkF24, 0, KeyeventfKeyup, IntPtr.Zero);
        var fg = GetForegroundWindow();
        var here = GetCurrentThreadId();
        var there = fg != IntPtr.Zero ? GetWindowThreadProcessId(fg, IntPtr.Zero) : 0;
        bool attached = there != 0 && there != here && AttachThreadInput(here, there, true);
        try
        {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        finally
        {
            if (attached) AttachThreadInput(here, there, false);
        }
        if (GetForegroundWindow() != hwnd) SwitchToThisWindow(hwnd, true);   // what Alt+Tab uses
    }

    /// <summary>Wait (in a background thread) for the Explorer window of path, then raise it.</summary>
    public static void BringToFront(string path, double timeout = 4.0)
    {
        if (!OperatingSystem.IsWindows()) return;
        var t = new Thread(() =>
        {
            try
            {
                var names = new HashSet<string> { path.ToLowerInvariant(), Path.GetFileName(path.TrimEnd('\\', '/')).ToLowerInvariant() };
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed.TotalSeconds < timeout)
                {
                    var hwnd = FindExplorer(names);
                    if (hwnd != IntPtr.Zero)
                    {
                        Raise(hwnd);
                        return;
                    }
                    Thread.Sleep(150);
                }
            }
            catch (Exception) { }      // cosmetic; the folder is open either way
        }) { IsBackground = true, Name = "imw-raise-explorer" };
        t.Start();
    }
}
