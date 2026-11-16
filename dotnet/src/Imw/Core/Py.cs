using System.Globalization;
using System.Text;

namespace Imw.Core;

/// <summary>
/// Python string and value semantics the port has to keep, so the .NET version gives the same
/// output as the Python version: whitespace and character classes, case mapping, code-point
/// lengths and slices, ordering by code point, str() / repr() of values and truthiness.
/// </summary>
public static class Py
{
    // ------------------------------------------------------------------ character classes

    /// <summary>Python str.isspace() for one character.</summary>
    public static bool IsSpace(char c) => c switch
    {
        ' ' or '\t' or '\n' or '\x0b' or '\x0c' or '\r' or '\x1c' or '\x1d' or '\x1e' or '\x1f'
            or '\x85' or '\xa0' or '\u1680' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' => true,
        _ => c >= '\u2000' && c <= '\u200a',
    };

    public static string Strip(string s) => s == null ? null : StripChars(s, null, true, true);
    public static string LStrip(string s) => StripChars(s, null, true, false);
    public static string RStrip(string s) => StripChars(s, null, false, true);
    public static string Strip(string s, string chars) => StripChars(s, chars, true, true);
    public static string LStrip(string s, string chars) => StripChars(s, chars, true, false);
    public static string RStrip(string s, string chars) => StripChars(s, chars, false, true);

    static string StripChars(string s, string chars, bool left, bool right)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";
        bool Drop(char c) => chars == null ? IsSpace(c) : chars.IndexOf(c) >= 0;
        int a = 0, b = s.Length;
        if (left) while (a < b && Drop(s[a])) a++;
        if (right) while (b > a && Drop(s[b - 1])) b--;
        return s.Substring(a, b - a);
    }

    /// <summary>Python str.split() with no arguments: runs of whitespace, no empty parts.</summary>
    public static List<string> SplitWs(string s)
    {
        var out_ = new List<string>();
        var sb = new StringBuilder();
        foreach (var c in s ?? "")
        {
            if (IsSpace(c)) { if (sb.Length > 0) { out_.Add(sb.ToString()); sb.Clear(); } }
            else sb.Append(c);
        }
        if (sb.Length > 0) out_.Add(sb.ToString());
        return out_;
    }

    static IEnumerable<int> CodePoints(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                yield return char.ConvertToUtf32(s[i], s[i + 1]);
                i++;
            }
            else yield return s[i];
        }
    }

    static UnicodeCategory Cat(int cp) => cp <= 0xFFFF
        ? CharUnicodeInfo.GetUnicodeCategory((char)cp)
        : CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(cp), 0);

    static bool IsAlphaCp(int cp) => Cat(cp) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
        or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter;

    static bool IsDigitCp(int cp)
    {
        var c = Cat(cp);
        if (c == UnicodeCategory.DecimalDigitNumber) return true;
        if (c != UnicodeCategory.OtherNumber) return false;
        var s = cp <= 0xFFFF ? ((char)cp).ToString() : char.ConvertFromUtf32(cp);
        return CharUnicodeInfo.GetDigitValue(s, 0) >= 0;
    }

    static bool IsNumericCp(int cp) => Cat(cp) is UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber
        or UnicodeCategory.OtherNumber;

    public static bool IsDigit(string s) => !string.IsNullOrEmpty(s) && CodePoints(s).All(IsDigitCp);
    public static bool IsAlnum(string s) => !string.IsNullOrEmpty(s) && CodePoints(s).All(cp => IsAlphaCp(cp) || IsNumericCp(cp));
    public static bool IsAlnum(char c) => IsAlphaCp(c) || IsNumericCp(c);
    public static bool IsDigitChar(char c) => IsDigitCp(c);

    /// <summary>Python str.isupper(): at least one cased character and no lowercase one.</summary>
    public static bool IsUpper(string s)
    {
        bool cased = false;
        foreach (var cp in CodePoints(s ?? ""))
        {
            var c = Cat(cp);
            if (c is UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter) return false;
            if (c == UnicodeCategory.UppercaseLetter) cased = true;
        }
        return cased;
    }

    // ------------------------------------------------------------------ case

    /// <summary>Python str.lower() (full case mapping for the one special case Python has).</summary>
    public static string Lower(string s)
    {
        if (s == null) return null;
        return s.IndexOf('\u0130') < 0 ? s.ToLowerInvariant() : LowerSpecial(s);
    }

    static string LowerSpecial(string s)
    {
        var sb = new StringBuilder(s.Length + 4);
        foreach (var c in s)
            sb.Append(c == '\u0130' ? "i\u0307" : char.ToLowerInvariant(c).ToString());
        return sb.ToString();
    }

    static readonly Dictionary<char, string> UpperSpecial = new()
    {
        ['\u00df'] = "SS", ['\ufb00'] = "FF", ['\ufb01'] = "FI", ['\ufb02'] = "FL", ['\ufb03'] = "FFI",
        ['\ufb04'] = "FFL", ['\ufb05'] = "ST", ['\ufb06'] = "ST", ['\u0149'] = "\u02bcN",
    };

    /// <summary>Python str.upper() (full case mapping for the common special cases such as \u00df -> SS).</summary>
    public static string Upper(string s)
    {
        if (s == null) return null;
        bool special = false;
        foreach (var c in s) if (UpperSpecial.ContainsKey(c)) { special = true; break; }
        if (!special) return s.ToUpperInvariant();
        var sb = new StringBuilder(s.Length + 4);
        foreach (var c in s)
            sb.Append(UpperSpecial.TryGetValue(c, out var u) ? u : char.ToUpperInvariant(c).ToString());
        return sb.ToString();
    }

    // ------------------------------------------------------------------ code points

    /// <summary>len(s) in Python: code points, not UTF-16 units.</summary>
    public static int Len(string s)
    {
        if (s == null) return 0;
        int n = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
            n++;
        }
        return n;
    }

    static int Offset(string s, int cps)
    {
        int i = 0, n = 0;
        while (i < s.Length && n < cps)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i += 2;
            else i++;
            n++;
        }
        return i;
    }

    /// <summary>s[:n] in Python (n may be negative, counted from the end).</summary>
    public static string Head(string s, int n)
    {
        if (s == null) return "";
        if (n < 0) n = Math.Max(0, Len(s) + n);
        return s.Substring(0, Offset(s, n));
    }

    /// <summary>s[n:] in Python.</summary>
    public static string Tail(string s, int n)
    {
        if (s == null) return "";
        if (n < 0) n = Math.Max(0, Len(s) + n);
        return s.Substring(Offset(s, n));
    }

    // ------------------------------------------------------------------ ordering

    /// <summary>Python string comparison: by code point.</summary>
    public static int Cmp(string a, string b)
    {
        a ??= ""; b ??= "";
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            int ca = a[i], cb = b[j];
            if (char.IsHighSurrogate(a[i]) && i + 1 < a.Length && char.IsLowSurrogate(a[i + 1])) { ca = char.ConvertToUtf32(a[i], a[i + 1]); i++; }
            if (char.IsHighSurrogate(b[j]) && j + 1 < b.Length && char.IsLowSurrogate(b[j + 1])) { cb = char.ConvertToUtf32(b[j], b[j + 1]); j++; }
            if (ca != cb) return ca < cb ? -1 : 1;
            i++; j++;
        }
        return (a.Length - i).CompareTo(b.Length - j) switch { < 0 => -1, > 0 => 1, _ => 0 };
    }

    public static readonly IComparer<string> Ordinal = Comparer<string>.Create(Cmp);

    /// <summary>sorted(strings): code-point order, stable.</summary>
    public static List<string> Sorted(IEnumerable<string> items) => items.OrderBy(x => x, Ordinal).ToList();

    /// <summary>A stable sort, like Python's list.sort / sorted.</summary>
    public static List<T> Sorted<T>(IEnumerable<T> items, Comparison<T> cmp)
        => items.OrderBy(x => x, Comparer<T>.Create(cmp)).ToList();

    public static void SortInPlace<T>(List<T> items, Comparison<T> cmp)
    {
        var sorted = Sorted(items, cmp);
        items.Clear();
        items.AddRange(sorted);
    }

    // ------------------------------------------------------------------ values

    /// <summary>Python truthiness of a JSON-like value.</summary>
    public static bool Truthy(object v) => v switch
    {
        null => false,
        bool b => b,
        long l => l != 0,
        int i => i != 0,
        double d => d != 0,
        string s => s.Length > 0,
        System.Collections.ICollection c => c.Count > 0,
        JObj o => o.Count > 0,
        _ => true,
    };

    /// <summary>a or b, Python style.</summary>
    public static object Or(object a, object b) => Truthy(a) ? a : b;

    /// <summary>Python str(v) of a JSON-like value.</summary>
    public static string Str(object v) => v switch
    {
        null => "None",
        string s => s,
        bool b => b ? "True" : "False",
        long l => l.ToString(CultureInfo.InvariantCulture),
        int i => i.ToString(CultureInfo.InvariantCulture),
        double d => FloatRepr(d),
        _ => Repr(v),
    };

    /// <summary>Python repr(v) of a JSON-like value.</summary>
    public static string Repr(object v)
    {
        switch (v)
        {
            case string s: return ReprStr(s);
            case null: case bool: case long: case int: case double: return Str(v);
            case JObj o:
                return "{" + string.Join(", ", o.Select(kv => ReprStr(kv.Key) + ": " + Repr(kv.Value))) + "}";
            case System.Collections.IEnumerable e:
                var parts = new List<string>();
                foreach (var x in e) parts.Add(Repr(x));
                return "[" + string.Join(", ", parts) + "]";
            default: return v.ToString();
        }
    }

    static bool Printable(int cp)
    {
        if (cp == ' ') return true;
        var c = Cat(cp);
        return c is not (UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
            or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator or UnicodeCategory.SpaceSeparator);
    }

    /// <summary>Python repr() of a string, quotes included.</summary>
    public static string ReprStr(string s)
    {
        s ??= "";
        char q = s.Contains('\'') && !s.Contains('"') ? '"' : '\'';
        var sb = new StringBuilder();
        sb.Append(q);
        for (int i = 0; i < s.Length; i++)
        {
            int cp = s[i];
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                cp = char.ConvertToUtf32(s[i], s[i + 1]);
                i++;
            }
            if (cp == q || cp == '\\') { sb.Append('\\').Append((char)cp); continue; }
            if (cp == '\t') { sb.Append("\\t"); continue; }
            if (cp == '\n') { sb.Append("\\n"); continue; }
            if (cp == '\r') { sb.Append("\\r"); continue; }
            if (cp < ' ' || cp == 0x7f) { sb.Append("\\x").Append(cp.ToString("x2")); continue; }
            if (cp < 0x7f) { sb.Append((char)cp); continue; }
            if (Printable(cp)) { sb.Append(char.ConvertFromUtf32(cp)); continue; }
            if (cp <= 0xff) sb.Append("\\x").Append(cp.ToString("x2"));
            else if (cp <= 0xffff) sb.Append("\\u").Append(cp.ToString("x4"));
            else sb.Append("\\U").Append(cp.ToString("x8"));
        }
        sb.Append(q);
        return sb.ToString();
    }

    /// <summary>Python repr(float): shortest round-trip digits, fixed between 1e-4 and 1e16.</summary>
    public static string FloatRepr(double d)
    {
        if (double.IsNaN(d)) return "nan";
        if (double.IsPositiveInfinity(d)) return "inf";
        if (double.IsNegativeInfinity(d)) return "-inf";
        if (d == 0) return 1 / d < 0 ? "-0.0" : "0.0";
        var r = d.ToString("E16", CultureInfo.InvariantCulture);
        // Shortest digits that round-trip.
        string digits = null; int exp = 0;
        for (int prec = 1; prec <= 17; prec++)
        {
            var t = d.ToString("E" + (prec - 1), CultureInfo.InvariantCulture);
            if (double.Parse(t, CultureInfo.InvariantCulture) == d) { r = t; break; }
        }
        bool neg = r.StartsWith('-');
        if (neg) r = r.Substring(1);
        var parts = r.Split('E');
        digits = parts[0].Replace(".", "").TrimEnd('0');
        if (digits.Length == 0) digits = "0";
        exp = int.Parse(parts[1], CultureInfo.InvariantCulture);
        string body;
        if (exp >= -5 && exp < 16)
        {
            if (exp >= 0)
            {
                var ip = digits.Length > exp + 1 ? digits.Substring(0, exp + 1) : digits.PadRight(exp + 1, '0');
                var fp = digits.Length > exp + 1 ? digits.Substring(exp + 1) : "0";
                body = ip + "." + fp;
            }
            else
            {
                if (exp < -4) goto sci;
                body = "0." + new string('0', -exp - 1) + digits;
            }
            return (neg ? "-" : "") + body;
        }
    sci:
        var mant = digits.Length > 1 ? digits[0] + "." + digits.Substring(1) : digits;
        body = mant + "e" + (exp < 0 ? "-" : "+") + Math.Abs(exp).ToString("00", CultureInfo.InvariantCulture);
        return (neg ? "-" : "") + body;
    }

    /// <summary>Python's int(str(x).strip()) style conversion for config numbers; null when not a number.</summary>
    public static long? ToLong(object v) => v switch
    {
        long l => l,
        int i => i,
        bool b => b ? 1 : 0,
        double d when d == Math.Floor(d) => (long)d,
        string s when long.TryParse(Strip(s), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) => n,
        _ => null,
    };

    /// <summary>Python ==: numbers by value (True == 1), dicts without order, lists in order.</summary>
    public static bool Eq(object a, object b)
    {
        if (a == null || b == null) return a == null && b == null;
        if (IsNumber(a) && IsNumber(b)) return ToDouble(a) == ToDouble(b);
        if (a is string sa) return b is string sb && sa == sb;
        if (a is JObj oa)
        {
            if (b is not JObj ob || oa.Count != ob.Count) return false;
            foreach (var kv in oa)
                if (!ob.ContainsKey(kv.Key) || !Eq(kv.Value, ob[kv.Key])) return false;
            return true;
        }
        if (a is System.Collections.IList la)
        {
            if (b is not System.Collections.IList lb || la.Count != lb.Count) return false;
            for (int i = 0; i < la.Count; i++) if (!Eq(la[i], lb[i])) return false;
            return true;
        }
        return a.Equals(b);
    }

    static bool IsNumber(object v) => v is long or int or double or bool;
    static double ToDouble(object v) => v switch { long l => l, int i => i, double d => d, bool b => b ? 1 : 0, _ => 0 };

    // ------------------------------------------------------------------ environment

    /// <summary>getpass.getuser(): LOGNAME, USER, LNAME, USERNAME, then the account name.</summary>
    public static string GetUser()
    {
        foreach (var name in new[] { "LOGNAME", "USER", "LNAME", "USERNAME" })
        {
            var v = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrEmpty(v)) return v;
        }
        return Environment.UserName;
    }

    /// <summary>platform.node(): the host name.</summary>
    public static string Node()
    {
        try { return System.Net.Dns.GetHostName(); }
        catch { return Environment.MachineName; }
    }

    /// <summary>datetime.now(timezone.utc).isoformat(timespec="seconds").</summary>
    public static string NowUtcIso() => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + "+00:00";

    public static string Join(string sep, IEnumerable<string> items) => string.Join(sep, items);
}
