using System.Text;

namespace Imw.Core;

/// <summary>Text files as Python's Path.write_text / read_text handle them.</summary>
public static class PyFile
{
    /// <summary>Path.write_text(text, encoding="utf-8"): "\n" becomes the platform's line ending (CRLF on Windows).</summary>
    public static void WriteText(string path, string text, string encoding = "utf-8")
    {
        if (Environment.NewLine != "\n") text = text.Replace("\n", Environment.NewLine);
        File.WriteAllText(path, text, encoding == "ascii" ? Encoding.ASCII : new UTF8Encoding(false));
    }

    /// <summary>Path.read_text(): universal newlines, so CRLF and CR read as "\n".</summary>
    public static string ReadText(string path, string encoding = "utf-8")
    {
        var text = Csv.ReadText(path, encoding);
        return text.Replace("\r\n", "\n").Replace('\r', '\n');
    }
}
