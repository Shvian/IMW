using System.Text.RegularExpressions;
using Imw.Core;

namespace Imw.Adapters;

public class AdapterError : Exception
{
    public AdapterError(string message) : base(message) { }
}

/// <summary>Turns one exported file into SourceRecord objects.</summary>
public abstract class Adapter
{
    public abstract string Name { get; }
    public abstract string Description { get; }

    /// <summary>0..100: how likely this adapter understands the file.</summary>
    public abstract int Sniff(string path);

    public abstract List<SourceRecord> Read(string path, JObj cfg, string encoding = "utf-8-sig");

    // ------------------------------------------------------------------ registry

    public static readonly Dictionary<string, Func<Adapter>> All = new()
    {
        ["delinea"] = () => new DelineaAdapter(),
        ["keepass"] = () => new KeePassAdapter(),
        ["table"] = () => new TableAdapter(),
    };

    public static IEnumerable<string> Names => All.Keys;

    public static Adapter Get(string name)
    {
        if (name != null && All.TryGetValue(name.ToLowerInvariant(), out var make)) return make();
        throw new AdapterError($"unknown source '{name}'; choose one of: {string.Join(", ", All.Keys)}");
    }

    /// <summary>The adapter whose Sniff() scores highest for this file.</summary>
    public static Adapter Detect(string path)
    {
        Adapter best = null;
        int bestScore = 0;
        foreach (var make in All.Values)
        {
            var a = make();
            var score = a.Sniff(path);
            if (score > bestScore) { best = a; bestScore = score; }
        }
        return best ?? throw new AdapterError($"cannot tell what kind of export {path} is; pass --source");
    }

    // ------------------------------------------------------------------ helpers

    public static string ReadHead(string path, int size = 65536, string encoding = "utf-8-sig")
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            // errors="replace": undecodable bytes become U+FFFD
            string text;
            var name = (encoding ?? "").ToLowerInvariant();
            if (name.StartsWith("utf-8") || name.StartsWith("utf8"))
            {
                int skip = name.EndsWith("sig") && bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
                text = new System.Text.UTF8Encoding(false, false).GetString(bytes, skip, bytes.Length - skip);
            }
            else
            {
                try { text = Csv.Decode(bytes, encoding); }
                catch (ValueError) { text = System.Text.Encoding.UTF8.GetString(bytes); }
            }
            return text.Length > size ? text.Substring(0, size) : text;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return "";
        }
    }

    public static string FileStem(string path) =>
        Regex.Replace(Path.GetFileNameWithoutExtension(path), "[^A-Za-z0-9_.-]", "_");

    /// <summary>column name lower-cased and trimmed -> column name (the last one wins, like a dict).</summary>
    public static Dictionary<string, string> ColumnLookup(IEnumerable<string> columns)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var c in columns) d[Py.Lower(Py.Strip(c))] = c;
        return d;
    }

    public static string FindColumn(Dictionary<string, string> lookup, IEnumerable<string> aliases)
    {
        foreach (var alias in aliases)
            if (lookup.TryGetValue(Py.Lower(Py.Strip(alias)), out var col) && col != null) return col;
        return null;
    }

    /// <summary>(column, value) for the first alias that is present and non-empty.</summary>
    public static (string, string) FirstValue(StrDict row, Dictionary<string, string> lookup, IEnumerable<string> aliases)
    {
        string first = null;
        foreach (var alias in aliases)
        {
            if (!lookup.TryGetValue(Py.Lower(Py.Strip(alias)), out var col) || col == null) continue;
            if (string.IsNullOrEmpty(first)) first = col;      // first = first or col
            var val = row.Get(col);
            if (val != null && Py.Strip(val).Length > 0) return (col, val);
        }
        return (first, "");
    }

    public static bool MatchesAny(string name, IEnumerable<string> patterns) =>
        patterns.Any(p => PyRe.Search(p, name, ignoreCase: true) != null);

    // Column names that hold secrets, always on (config secret_column_patterns adds to them).
    public static readonly string[] BuiltinSecretColumns =
    {
        @"pass ?word", @"passwd", @"\bpwd\b", @"^pass$", @"passphrase", @"pass ?code",
        @"private ?key", @"ssh ?key", @"\bsecret\b(?! ?(name|id|template|folder|policy|type)\b)",
        @"api ?key", @"\btoken\b", @"\bpin\b", @"\btotp\b", @"\botp\b", @"\bseed\b",
        @"recovery ?(code|key)", @"backup ?code", @"security ?(answer|code)", @"\bcvv\b", @"\bcvc\b",
        @"card ?number", @"connection ?string", @"combination", @"alarm ?code", @"(license|product) ?key",
    };

    /// <summary>True when a column (or KeePass field) name says it holds a secret value.</summary>
    public static bool IsSecretColumn(string name, JObj cfg) =>
        MatchesAny(name ?? "", BuiltinSecretColumns) ||
        MatchesAny(name ?? "", (cfg?.List("secret_column_patterns") ?? new List<object>()).Select(x => Py.Str(x)));

    // Fields that hold (or set up) a one-time password.
    static readonly string[] OtpFieldPatterns = { @"\b[th]?otp\b", @"timeotp", @"hmacotp", @"\btotp", @"one[ -]?time[ -]?pass" };
    public const string OtpNoteText = "one-time password (OTP) in the source";
    static readonly HashSet<string> Off = new() { "", "0", "false", "no", "n", "none", "off", "disabled", "null" };

    public static bool IsOtpValue(string value) => Py.Lower(Py.Strip(value ?? "")).StartsWith("otpauth://", StringComparison.Ordinal);

    /// <summary>Names of the fields in (name, value) pairs that show a one-time password is set up.</summary>
    public static List<string> OtpFields(IEnumerable<KeyValuePair<string, string>> items) =>
        items.Where(kv => !Off.Contains(Py.Lower(Py.Strip(kv.Value ?? "")))
                          && (MatchesAny(kv.Key ?? "", OtpFieldPatterns) || IsOtpValue(kv.Value)))
             .Select(kv => kv.Key).ToList();

    /// <summary>The account note for a record with a one-time password. The seed is never kept.</summary>
    public static string OtpNote(IEnumerable<string> fields)
    {
        var names = string.Join(", ", fields.Select(f => $"'{f}'"));
        return $"{OtpNoteText} ({names}): it is not migrated and is left out of the review files; " +
               "set up MFA for this account again after migration";
    }

    /// <summary>Keep the host part of a URL as the address (https://h.example/x -> h.example).</summary>
    public static string AddressFromUrl(string value)
    {
        var m = PyRe.MatchStart(@"^[a-z][a-z0-9+.-]*://([^/?#]+)", Py.Strip(value), ignoreCase: true);
        if (m == null) return Py.Strip(value);
        var hostPart = m.Groups[1].Value;
        var host = hostPart.Substring(hostPart.LastIndexOf('@') + 1);
        if (host.StartsWith('['))
        {
            var inner = host.Substring(1);
            int close = inner.IndexOf(']');
            return close >= 0 ? inner.Substring(0, close) : inner;
        }
        return host.Count(c => c == ':') == 1 ? host.Substring(0, host.LastIndexOf(':')) : host;
    }
}
