using System.Text;

namespace Imw.Core;

/// <summary>A bad file: Python raises ValueError (or csv.Error) for these and the tools show the message.</summary>
public class ValueError : Exception
{
    public ValueError(string message) : base(message) { }
}

public class CsvError : ValueError
{
    public CsvError(string message) : base(message) { }
}

/// <summary>A CSV dialect, as Python's csv module describes one.</summary>
public sealed record Dialect(char Delimiter = ',', char? QuoteChar = '"', bool DoubleQuote = true,
                             bool SkipInitialSpace = false, bool Strict = false)
{
    public static readonly Dialect Excel = new();
    public static readonly Dialect ExcelTab = new('\t');
}

/// <summary>
/// Python's csv module: the reader state machine (with its line counting and its handling of
/// stray quotes), the writer's quoting, DictReader and the Sniffer, so files read and write
/// exactly as they did in the Python version.
/// </summary>
public static class Csv
{
    public const int FieldLimit = 64 * 1024 * 1024;

    static Csv()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    // ------------------------------------------------------------------ text files

    /// <summary>open(path, encoding=...).read(): text decoded strictly, like Python.</summary>
    public static string ReadText(string path, string encoding = "utf-8-sig")
    {
        var bytes = File.ReadAllBytes(path);
        return Decode(bytes, encoding);
    }

    public static string Decode(byte[] bytes, string encoding = "utf-8-sig")
    {
        var name = (encoding ?? "utf-8-sig").Trim().ToLowerInvariant().Replace('_', '-');
        int skip = 0;
        Encoding enc;
        switch (name)
        {
            case "utf-8-sig": case "utf8-sig":
                enc = new UTF8Encoding(false, true);
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) skip = 3;
                break;
            case "utf-8": case "utf8":
                enc = new UTF8Encoding(false, true);
                break;
            case "latin-1": case "latin1": case "iso-8859-1": case "iso8859-1":
                enc = Encoding.Latin1;
                break;
            case "utf-16": case "utf16":
                if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) { enc = new UnicodeEncoding(false, false, true); skip = 2; }
                else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) { enc = new UnicodeEncoding(true, false, true); skip = 2; }
                else enc = new UnicodeEncoding(false, false, true);
                break;
            default:
                try
                {
                    enc = Encoding.GetEncoding(name.StartsWith("cp") && int.TryParse(name.AsSpan(2), out var cp) ? $"windows-{cp}" : name,
                        EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                }
                catch (ArgumentException)
                {
                    throw new ValueError($"unknown encoding: {encoding}");
                }
                break;
        }
        try
        {
            return enc.GetString(bytes, skip, bytes.Length - skip);
        }
        catch (DecoderFallbackException exc)
        {
            var pos = exc.Index >= 0 ? exc.Index : 0;
            var b = exc.BytesUnknown is { Length: > 0 } u ? u[0] : (byte)0;
            throw new ValueError($"'{(name.StartsWith("utf-8") ? "utf-8" : name)}' codec can't decode byte 0x{b:x2} in position {pos}: invalid start byte");
        }
    }

    /// <summary>Lines as Python's file iterator gives them with newline="": split after \r\n, \r or \n, endings kept.</summary>
    public static IEnumerable<string> Lines(string text)
    {
        int start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\n' || c == '\r')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                yield return text.Substring(start, i + 1 - start);
                start = i + 1;
            }
        }
        if (start < text.Length) yield return text.Substring(start);
    }

    // ------------------------------------------------------------------ reader

    enum St { StartRecord, StartField, EscapedChar, InField, InQuotedField, EscapeInQuotedField, QuoteInQuotedField, EatCrnl }

    /// <summary>csv.reader: yields (line_num after the row, fields).</summary>
    public sealed class Reader
    {
        readonly IEnumerator<string> _lines;
        readonly Dialect _d;
        public int LineNum { get; private set; }

        public Reader(string text, Dialect dialect = null)
        {
            _lines = Lines(text).GetEnumerator();
            _d = dialect ?? Dialect.Excel;
        }

        public IEnumerable<List<string>> Rows()
        {
            while (true)
            {
                var row = Next();
                if (row == null) yield break;
                yield return row;
            }
        }

        List<string> _fields;
        StringBuilder _field;
        St _state;

        void Save()
        {
            _fields.Add(_field.ToString());
            _field.Clear();
        }

        void Add(char c)
        {
            if (_field.Length >= FieldLimit) throw new CsvError($"field larger than field limit ({FieldLimit})");
            _field.Append(c);
        }

        const int EOL = -2;

        void Process(int c)
        {
            var d = _d;
            bool nl = c == '\n' || c == '\r';
            bool isQuote = d.QuoteChar != null && c == d.QuoteChar;
            switch (_state)
            {
                case St.StartRecord:
                    if (c == EOL) break;
                    if (nl) { _state = St.EatCrnl; break; }
                    _state = St.StartField;
                    goto case St.StartField;
                case St.StartField:
                    if (nl || c == EOL) { Save(); _state = c == EOL ? St.StartRecord : St.EatCrnl; }
                    else if (isQuote) _state = St.InQuotedField;
                    else if (c == ' ' && d.SkipInitialSpace) { }
                    else if (c == d.Delimiter) Save();
                    else { Add((char)c); _state = St.InField; }
                    break;
                case St.InField:
                    if (nl || c == EOL) { Save(); _state = c == EOL ? St.StartRecord : St.EatCrnl; }
                    else if (c == d.Delimiter) { Save(); _state = St.StartField; }
                    else Add((char)c);
                    break;
                case St.InQuotedField:
                    if (c == EOL) { }
                    else if (isQuote) _state = d.DoubleQuote ? St.QuoteInQuotedField : St.InField;
                    else Add((char)c);
                    break;
                case St.QuoteInQuotedField:
                    if (isQuote) { Add((char)c); _state = St.InQuotedField; }
                    else if (c == d.Delimiter) { Save(); _state = St.StartField; }
                    else if (nl || c == EOL) { Save(); _state = c == EOL ? St.StartRecord : St.EatCrnl; }
                    else if (!d.Strict) { Add((char)c); _state = St.InField; }
                    else throw new CsvError($"'{d.Delimiter}' expected after '{d.QuoteChar}'");
                    break;
                case St.EatCrnl:
                    if (nl) { }
                    else if (c == EOL) _state = St.StartRecord;
                    else throw new CsvError("new-line character seen in unquoted field - do you need to open the file with newline=''?");
                    break;
            }
        }

        /// <summary>The next row, or null at the end.</summary>
        public List<string> Next()
        {
            _fields = new List<string>();
            _field = new StringBuilder();
            _state = St.StartRecord;
            do
            {
                if (!_lines.MoveNext())
                {
                    if (_field.Length != 0 || _state == St.InQuotedField)
                    {
                        if (_d.Strict) throw new CsvError("unexpected end of data");
                        Save();
                        break;
                    }
                    return null;
                }
                LineNum++;
                foreach (var ch in _lines.Current) Process(ch);
                Process(EOL);
            } while (_state != St.StartRecord);
            var f = _fields;
            _fields = null;
            return f;
        }
    }

    /// <summary>csv.DictReader over text: the first row names the columns.</summary>
    public sealed class DictReader
    {
        readonly Reader _r;
        public List<string> FieldNames { get; }
        public string RestKey { get; init; }
        public int LineNum => _r.LineNum;

        public DictReader(string text, Dialect dialect = null, string restKey = null)
        {
            _r = new Reader(text, dialect);
            RestKey = restKey;
            FieldNames = _r.Next() ?? new List<string>();
        }

        /// <summary>Rows as ordered dictionaries; the value of the rest key (if any) is a List&lt;string&gt;.</summary>
        public IEnumerable<OrderedRow> Rows()
        {
            while (true)
            {
                var row = _r.Next();
                if (row == null) yield break;
                while (row != null && row.Count == 0) row = _r.Next();
                if (row == null) yield break;
                var d = new OrderedRow();
                for (int i = 0; i < FieldNames.Count && i < row.Count; i++) d[FieldNames[i]] = row[i];
                if (row.Count > FieldNames.Count) d.Rest = row.Skip(FieldNames.Count).ToList();
                else for (int i = row.Count; i < FieldNames.Count; i++) d[FieldNames[i]] = null;
                yield return d;
            }
        }
    }

    /// <summary>One DictReader row: column -> value (null for a missing value), in column order.</summary>
    public sealed class OrderedRow : IEnumerable<KeyValuePair<string, string>>
    {
        readonly List<string> _keys = new();
        readonly Dictionary<string, string> _map = new(StringComparer.Ordinal);
        public List<string> Rest;

        public string this[string key]
        {
            get => _map.TryGetValue(key, out var v) ? v : null;
            set { if (!_map.ContainsKey(key)) _keys.Add(key); _map[key] = value; }
        }

        public bool Has(string key) => _map.ContainsKey(key);
        public IReadOnlyList<string> Keys => _keys;

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            foreach (var k in _keys) yield return new(k, _map[k]);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    // ------------------------------------------------------------------ writer

    public enum Quoting { Minimal, All }

    /// <summary>csv.writer: \r\n line endings, quotes doubled.</summary>
    public sealed class Writer
    {
        readonly TextWriter _w;
        readonly Quoting _q;
        readonly char _delim;

        public Writer(TextWriter w, Quoting quoting = Quoting.Minimal, char delimiter = ',')
        {
            _w = w;
            _q = quoting;
            _delim = delimiter;
        }

        public void WriteRow(IEnumerable<object> values)
        {
            var fields = values.ToList();
            var sb = new StringBuilder();
            for (int i = 0; i < fields.Count; i++)
            {
                if (i > 0) sb.Append(_delim);
                var v = fields[i];
                var s = v == null ? "" : Py.Str(v);
                bool quote = _q == Quoting.All;
                if (!quote)
                {
                    foreach (var c in s)
                        if (c == _delim || c == '"' || c == '\r' || c == '\n') { quote = true; break; }
                    if (s.Length == 0 && fields.Count == 1) quote = true;
                }
                if (quote) sb.Append('"').Append(s.Replace("\"", "\"\"")).Append('"');
                else sb.Append(s);
            }
            sb.Append("\r\n");
            _w.Write(sb.ToString());
        }

        public void WriteRows(IEnumerable<IEnumerable<object>> rows)
        {
            foreach (var r in rows) WriteRow(r);
        }
    }

    /// <summary>open(path, "w", newline="", encoding="utf-8-sig"): UTF-8 with a byte order mark.</summary>
    public static StreamWriter OpenWrite(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
        return new StreamWriter(path, false, new UTF8Encoding(true));
    }

    // ------------------------------------------------------------------ sniffer

    /// <summary>csv.Sniffer().sniff(sample, delimiters); throws CsvError when no delimiter is found.</summary>
    public static Dialect Sniff(string sample, string delimiters = null)
    {
        sample = sample.Replace("\r\n", "\n").Replace('\r', '\n');
        var (quotechar, doublequote, delimiter, skipinitialspace) = GuessQuoteAndDelimiter(sample, delimiters);
        if (string.IsNullOrEmpty(delimiter))
            (delimiter, skipinitialspace) = GuessDelimiter(sample, delimiters);
        if (string.IsNullOrEmpty(delimiter)) throw new CsvError("Could not determine delimiter");
        return new Dialect(delimiter[0], string.IsNullOrEmpty(quotechar) ? '"' : quotechar[0], doublequote, skipinitialspace);
    }

    const string Body = @"(?>(?:\k<quote>{2}|(?!\k<quote>).)*)";

    static (string, bool, string, bool) GuessQuoteAndDelimiter(string data, string delimiters)
    {
        var patterns = new[]
        {
            @"(?<delim>[^\w\n""'])(?<space> ?)(?<quote>[""'])" + Body + @"\k<quote>\k<delim>",
            @"(?:^|\n)(?<quote>[""'])" + Body + @"\k<quote>(?<delim>[^\w\n""'])(?<space> ?)",
            @"(?<delim>[^\w\n""'])(?<space> ?)(?<quote>[""'])" + Body + @"\k<quote>(?:$|\n)",
            @"(?:^|\n)(?<quote>[""'])" + Body + @"\k<quote>(?:$|\n)",
        };
        var opts = System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.Multiline;
        List<System.Text.RegularExpressions.Match> matches = null;
        System.Text.RegularExpressions.Regex rx = null;
        foreach (var p in patterns)
        {
            rx = new System.Text.RegularExpressions.Regex(p, opts);
            matches = rx.Matches(data).ToList();
            if (matches.Count > 0) break;
        }
        if (matches == null || matches.Count == 0) return ("", false, null, false);
        var quotes = new JObj();
        var delims = new JObj();
        int spaces = 0;
        bool hasDelim = rx.GetGroupNames().Contains("delim");
        bool hasSpace = rx.GetGroupNames().Contains("space");
        foreach (var m in matches)
        {
            var key = m.Groups["quote"].Value;
            if (key.Length > 0) quotes[key] = (long)quotes.Get(key, 0L) + 1;
            if (!hasDelim) continue;
            key = m.Groups["delim"].Value;
            if (key.Length > 0 && (delimiters == null || delimiters.Contains(key)))
                delims[key] = (long)delims.Get(key, 0L) + 1;
            if (!hasSpace) continue;
            if (m.Groups["space"].Value.Length > 0) spaces++;
        }
        string quotechar = MaxKey(quotes);
        string delim;
        bool skip;
        if (delims.Count > 0)
        {
            delim = MaxKey(delims);
            skip = (long)delims[delim] == spaces;
            if (delim == "\n") delim = "";
        }
        else
        {
            delim = "";
            skip = false;
        }
        bool doublequote = false;
        if (delim.Length > 0)
        {
            var q = System.Text.RegularExpressions.Regex.Escape(quotechar);
            var space = delim != " " ? "(?> *)" : "";
            var dq = new System.Text.RegularExpressions.Regex(
                $"(?:(?<={System.Text.RegularExpressions.Regex.Escape(delim)})|^){space}{q}((?>(?:{q}{q}|(?>[^{q}]+))*)){q}(?:{System.Text.RegularExpressions.Regex.Escape(delim)}|$)",
                System.Text.RegularExpressions.RegexOptions.Multiline);
            var two = quotechar + quotechar;
            doublequote = dq.Matches(data).Any(m => m.Groups[1].Value.Contains(two));
        }
        return (quotechar, doublequote, delim, skip);
    }

    static string MaxKey(JObj counts)
    {
        string best = null;
        long bestN = long.MinValue;
        foreach (var kv in counts)
            if ((long)kv.Value > bestN) { best = kv.Key; bestN = (long)kv.Value; }
        return best;
    }

    static int Count(string s, string sub)
    {
        if (sub.Length == 0) return s.Length + 1;
        int n = 0, i = 0;
        while ((i = s.IndexOf(sub, i, StringComparison.Ordinal)) >= 0) { n++; i += sub.Length; }
        return n;
    }

    static (string, bool) GuessDelimiter(string sample, string delimiters)
    {
        var data = sample.Split('\n').Where(l => l.Length > 0).ToList();
        int chunkLength = Math.Min(10, data.Count);
        int iteration = 0;
        // char -> (frequency -> rows), both in first-seen order
        var charFrequency = new Dictionary<char, List<(int freq, int rows)>>();
        var charOrder = new List<char>();
        var modes = new Dictionary<char, (int, int)>();
        var modeOrder = new List<char>();
        var delims = new Dictionary<char, (int, int)>();
        var delimOrder = new List<char>();
        int start = 0, end = chunkLength;
        while (start < data.Count)
        {
            iteration++;
            foreach (var line in data.Skip(start).Take(end - start))
            {
                for (int ci = 0; ci < 127; ci++)
                {
                    char ch = (char)ci;
                    if (!charFrequency.TryGetValue(ch, out var meta))
                    {
                        meta = new List<(int, int)>();
                        charFrequency[ch] = meta;
                        charOrder.Add(ch);
                    }
                    int freq = 0;
                    foreach (var c in line) if (c == ch) freq++;
                    int at = meta.FindIndex(x => x.freq == freq);
                    if (at < 0) meta.Add((freq, 1));
                    else meta[at] = (freq, meta[at].rows + 1);
                }
            }
            foreach (var ch in charOrder)
            {
                var items = charFrequency[ch].ToList();
                if (items.Count == 1 && items[0].freq == 0) continue;
                (int, int) mode;
                if (items.Count > 1)
                {
                    var best = items[0];
                    foreach (var it in items) if (it.rows > best.rows) best = it;
                    int idx = items.IndexOf(best);
                    items.RemoveAt(idx);
                    mode = (best.freq, best.rows - items.Sum(x => x.rows));
                }
                else mode = items[0];
                if (!modes.ContainsKey(ch)) modeOrder.Add(ch);
                modes[ch] = mode;
            }
            double total = Math.Min(chunkLength * iteration, data.Count);
            double consistency = 1.0, threshold = 0.9;
            while (delims.Count == 0 && consistency >= threshold)
            {
                foreach (var k in modeOrder)
                {
                    var v = modes[k];
                    if (v.Item1 > 0 && v.Item2 > 0 && v.Item2 / total >= consistency
                        && (delimiters == null || delimiters.IndexOf(k) >= 0))
                    {
                        if (!delims.ContainsKey(k)) delimOrder.Add(k);
                        delims[k] = v;
                    }
                }
                consistency -= 0.01;
            }
            if (delims.Count == 1)
            {
                var delim = delimOrder[0];
                return (delim.ToString(), Count(data[0], delim.ToString()) == Count(data[0], delim + " "));
            }
            start = end;
            end += chunkLength;
        }
        if (delims.Count == 0) return ("", false);
        if (delims.Count > 1)
        {
            foreach (var d in new[] { ',', '\t', ';', ' ', ':' })
                if (delims.ContainsKey(d))
                    return (d.ToString(), Count(data[0], d.ToString()) == Count(data[0], d + " "));
        }
        var sorted = delimOrder.Select(k => (v: delims[k], k)).ToList();
        sorted.Sort((a, b) =>
        {
            int c = a.v.Item1.CompareTo(b.v.Item1);
            if (c == 0) c = a.v.Item2.CompareTo(b.v.Item2);
            if (c == 0) c = a.k.CompareTo(b.k);
            return c;
        });
        var last = sorted[^1].k;
        return (last.ToString(), Count(data[0], last.ToString()) == Count(data[0], last + " "));
    }
}
