using System.Text;

namespace Imw;

static class Program
{
    static int Main(string[] argv)
    {
        try
        {
            Console.OutputEncoding = new UTF8Encoding(false);
        }
        catch (IOException) { }
        if (argv.Length > 0) return Cli.Run(argv);
        // Double-clicked (no arguments): start the Workbench on the "imw_workspace" folder next to
        // IMW.exe, and keep the window open on an error so its message can be read.
        Directory.SetCurrentDirectory(AppContext.BaseDirectory);
        var code = Cli.Run(new[] { "ui" });
        if (code != 0 && !Console.IsInputRedirected)
        {
            Console.Error.WriteLine("\nPress Enter to close this window.");
            Console.ReadLine();
        }
        return code;
    }
}
