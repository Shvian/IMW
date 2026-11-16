using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Imw.Core;

public class UnsafeXmlError : ValueError
{
    public UnsafeXmlError(string message) : base(message) { }
}

public class XmlParseError : ValueError
{
    public XmlParseError(string message) : base(message) { }
}

/// <summary>
/// XML parsing that refuses document type declarations. Source exports (KeePass XML, the parts
/// inside an .xlsx) never need a DTD. A DTD is what entity-expansion attacks ("billion laughs",
/// external entities) rely on, so any document that declares one is rejected.
/// </summary>
public static class SafeXml
{
    public const long MaxFileBytes = 512L * 1024 * 1024;
    const string Refused = "the XML declares a DTD or entities, which the Workbench does not accept";

    /// <summary>Parse text into an element tree; a DTD is refused, never processed.</summary>
    public static XElement FromString(string text)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            CheckCharacters = true,
        };
        try
        {
            using var sr = new StringReader(text);
            using var reader = XmlReader.Create(sr, settings);
            return XElement.Load(reader, LoadOptions.PreserveWhitespace);
        }
        catch (XmlException exc)
        {
            if (exc.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase)) throw new UnsafeXmlError(Refused);
            throw new XmlParseError(Simplify(exc));
        }
    }

    static string Simplify(XmlException exc)
    {
        var m = exc.Message;
        return exc.LineNumber > 0 ? $"{m.Split(" Line ")[0].TrimEnd('.')}: line {exc.LineNumber}, column {Math.Max(0, exc.LinePosition - 1)}" : m;
    }

    public static XElement FromBytes(byte[] data) => FromString(Decode(data));

    public static string ReadHeadText(string path, int size = 8192)
    {
        byte[] data;
        try
        {
            using var fh = File.OpenRead(path);
            data = new byte[Math.Min(size, fh.Length)];
            int n = 0;
            while (n < data.Length)
            {
                int r = fh.Read(data, n, data.Length - n);
                if (r == 0) break;
                n += r;
            }
            if (n < data.Length) Array.Resize(ref data, n);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return "";
        }
        bool utf16 = (data.Length >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)))
                     || (data.Length > 1 && (data[0] == 0 || data[1] == 0));
        if (utf16) Array.Resize(ref data, data.Length - data.Length % 2);
        try { return Decode(data); }
        catch (ValueError) { return Encoding.UTF8.GetString(data); }
    }

    public static byte[] ReadCapped(string path, long? limit = null)
    {
        long cap = limit ?? MaxFileBytes;
        using var fh = File.OpenRead(path);
        if (fh.Length > cap) throw new ValueError($"{path}: larger than {cap / (1024 * 1024)} MB; split the export");
        var ms = new MemoryStream();
        fh.CopyTo(ms);
        if (ms.Length > cap) throw new ValueError($"{path}: larger than {cap / (1024 * 1024)} MB; split the export");
        return ms.ToArray();
    }

    static readonly Regex Declared = new(@"^<\?xml[^>]*?encoding\s*=\s*[""']([A-Za-z0-9._-]+)[""']", RegexOptions.CultureInvariant);

    /// <summary>
    /// Bytes of an XML file -> text, whatever the file says about itself: byte order mark first,
    /// then the zero-byte pattern of UTF-16, then UTF-8, then the declared encoding, then Windows-1252.
    /// </summary>
    public static string Decode(byte[] data)
    {
        static string Strict(Encoding e, byte[] d, int skip)
        {
            try { return e.GetString(d, skip, d.Length - skip); }
            catch (DecoderFallbackException exc) { throw new ValueError($"cannot decode ({exc.Message})"); }
        }
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            return Strict(new UTF8Encoding(false, true), data, 3);
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return Strict(new UnicodeEncoding(false, false, true), data, 2);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) return Strict(new UnicodeEncoding(true, false, true), data, 2);
        if (data.Length >= 2 && data[1] == 0 && data[0] != 0) return Strict(new UnicodeEncoding(false, false, true), data, 0);
        if (data.Length >= 2 && data[0] == 0 && data[1] != 0) return Strict(new UnicodeEncoding(true, false, true), data, 0);
        try { return new UTF8Encoding(false, true).GetString(data); }
        catch (DecoderFallbackException) { }
        var head = Encoding.Latin1.GetString(data, 0, Math.Min(data.Length, 200));
        var m = Declared.Match(head);
        if (m.Success && !m.Groups[1].Value.ToLowerInvariant().StartsWith("utf-16"))
        {
            try
            {
                _ = Csv.Decode(Array.Empty<byte>(), "utf-8");     // registers the code pages
                var enc = Encoding.GetEncoding(m.Groups[1].Value, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                return enc.GetString(data);
            }
            catch (Exception exc) when (exc is ArgumentException or DecoderFallbackException) { }
        }
        _ = Csv.Decode(Array.Empty<byte>(), "utf-8");
        return Encoding.GetEncoding(1252).GetString(data);
    }

    /// <summary>Read the file once and parse it.</summary>
    public static XElement Parse(string path)
    {
        var data = ReadCapped(path);
        string text;
        try { text = Decode(data); }
        catch (ValueError exc) { throw new XmlParseError($"{path}: cannot read the text encoding ({exc.Message})"); }
        try { return FromString(text); }
        catch (UnsafeXmlError) { throw; }
        catch (XmlParseError exc) { throw new XmlParseError($"{path}: {exc.Message}"); }
    }

    // ------------------------------------------------------------------ ElementTree helpers

    /// <summary>ElementTree's element.text: the text before the first child element (null when none).</summary>
    public static string Text(XElement e)
    {
        if (e == null) return null;
        StringBuilder sb = null;
        foreach (var n in e.Nodes())
        {
            if (n is XElement) break;
            if (n is XText t) (sb ??= new StringBuilder()).Append(t.Value);
        }
        return sb?.ToString();
    }

    /// <summary>ElementTree's tag: {namespace}local, or local without a namespace.</summary>
    public static string Tag(XElement e) =>
        e.Name.NamespaceName.Length > 0 ? "{" + e.Name.NamespaceName + "}" + e.Name.LocalName : e.Name.LocalName;

    /// <summary>element.find(path) for a simple a/b/c path of tags without namespace.</summary>
    public static XElement Find(XElement e, string path)
    {
        var cur = e;
        foreach (var part in path.Split('/'))
        {
            cur = cur?.Elements().FirstOrDefault(c => Tag(c) == part);
            if (cur == null) return null;
        }
        return cur;
    }

    public static IEnumerable<XElement> FindAll(XElement e, string tag) => e.Elements().Where(c => Tag(c) == tag);

    /// <summary>element.findtext(path): the text ("" when empty), or null when there is no such element.</summary>
    public static string FindText(XElement e, string path)
    {
        var f = Find(e, path);
        return f == null ? null : Text(f) ?? "";
    }

    public static string Attr(XElement e, string name) => e.Attribute(name)?.Value;
}
