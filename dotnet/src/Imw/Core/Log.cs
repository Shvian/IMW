namespace Imw.Core;

/// <summary>Python logging with basicConfig(format="%(levelname)s %(message)s") on stderr.</summary>
public static class Log
{
    public static bool Verbose;
    public static bool Quiet;
    public static TextWriter Out = Console.Error;
    static readonly object Lock = new();

    static void Write(string level, string msg)
    {
        if (Quiet) return;
        lock (Lock) Out.WriteLine($"{level} {msg}");
    }

    public static void Debug(string msg) { if (Verbose) Write("DEBUG", msg); }
    public static void Info(string msg) => Write("INFO", msg);
    public static void Warning(string msg) => Write("WARNING", msg);
    public static void Error(string msg) => Write("ERROR", msg);
}
