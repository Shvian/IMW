namespace Imw.Core;

/// <summary>
/// Keep spreadsheet programs from running cell values as formulas (CSV/formula injection).
///
/// Review files are meant to be opened in Excel. A source value that starts with = + - @ or a
/// tab / carriage return could be read as a formula (or DDE command), so such values are
/// written with a leading apostrophe, which Excel shows as plain text. When a review file
/// comes back (--overrides, --from-review) the apostrophe is taken off again.
///
/// Upload files (upload/*.csv) are API input and are NOT escaped: changing a value there
/// would change the account (a password may well start with '-').
/// </summary>
public static class CsvSafe
{
    static readonly string[] Triggers = { "=", "+", "-", "@", "\t", "\r" };

    static bool StartsWithTrigger(string s, bool orQuote) =>
        Triggers.Any(t => s.StartsWith(t, StringComparison.Ordinal)) || (orQuote && s.StartsWith('\''));

    public static object Escape(object value)
    {
        if (value is not string s || s.Length == 0) return value;
        if (StartsWithTrigger(s, false) || (s.StartsWith('\'') && StartsWithTrigger(s.Substring(1), true)))
            return "'" + s;
        return s;
    }

    public static string Unescape(string value)
    {
        if (value != null && value.StartsWith('\'') && StartsWithTrigger(value.Substring(1), true))
            return value.Substring(1);
        return value;
    }

    public static List<object> Row(IEnumerable<object> values) => values.Select(Escape).ToList();

    /// <summary>csv.writer that escapes every value it writes.</summary>
    public sealed class SafeWriter
    {
        readonly Csv.Writer _w;
        public SafeWriter(Csv.Writer w) { _w = w; }
        public void WriteRow(IEnumerable<object> values) => _w.WriteRow(Row(values));
        public void WriteRows(IEnumerable<IEnumerable<object>> rows) { foreach (var r in rows) WriteRow(r); }
    }

    /// <summary>Read a CSV file as Python's csvsafe.reading() would: CSV errors name the file.</summary>
    public static T Reading<T>(string path, Func<T> fn)
    {
        try { return fn(); }
        catch (CsvError exc) { throw new ValueError($"{path}: not a readable CSV file ({exc.Message})"); }
    }
}
