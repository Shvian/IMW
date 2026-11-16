using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace Imw.Core;

public class PyReError : Exception
{
    public PyReError(string message) : base(message) { }
}

/// <summary>
/// Python's re module on top of .NET Regex. Patterns typed in the settings were written for
/// Python, so the few Python-only spellings are translated first: (?P&lt;name&gt;...), (?P=name),
/// \Z (end of text) and \U00XXXXXX. Everything else means the same in both.
/// </summary>
public static class PyRe
{
    static readonly ConcurrentDictionary<(string, RegexOptions, int), Regex> Cache = new();

    /// <summary>Python pattern -> .NET pattern.</summary>
    public static string Translate(string pattern)
    {
        pattern ??= "";
        var sb = new StringBuilder(pattern.Length + 8);
        bool inClass = false;
        for (int i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                char n = pattern[i + 1];
                if (!inClass && n == 'Z') { sb.Append("\\z"); i++; continue; }
                if (n == 'U' && i + 10 <= pattern.Length)
                {
                    var hex = pattern.Substring(i + 2, 8);
                    if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var cp))
                    {
                        sb.Append(Regex.Escape(char.ConvertFromUtf32(cp)));
                        i += 9;
                        continue;
                    }
                }
                sb.Append(c).Append(n);
                i++;
                continue;
            }
            if (inClass)
            {
                if (c == ']') inClass = false;
                // .NET reads "-[" inside a class as class subtraction; Python reads both literally.
                if (c == '-' && i + 1 < pattern.Length && pattern[i + 1] == '[') { sb.Append("\\-"); continue; }
                if (c == '[') { sb.Append("\\["); continue; }
                sb.Append(c);
                continue;
            }
            if (c == '[')
            {
                inClass = true;
                sb.Append(c);
                // A ] right after [ or [^ is a literal in both, copy it so it does not close the class.
                if (i + 1 < pattern.Length && pattern[i + 1] == '^') { sb.Append('^'); i++; }
                if (i + 1 < pattern.Length && pattern[i + 1] == ']') { sb.Append("\\]"); i++; }
                continue;
            }
            if (c == '(' && i + 2 < pattern.Length && pattern[i + 1] == '?' && pattern[i + 2] == 'P')
            {
                if (i + 3 < pattern.Length && pattern[i + 3] == '<') { sb.Append("(?<"); i += 3; continue; }
                if (i + 3 < pattern.Length && pattern[i + 3] == '=')
                {
                    int close = pattern.IndexOf(')', i);
                    if (close > 0)
                    {
                        sb.Append("\\k<").Append(pattern, i + 4, close - i - 4).Append('>');
                        i = close;
                        continue;
                    }
                }
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>re.compile(pattern, flags). kind: 0 = search, 1 = match at start, 2 = full match.</summary>
    public static Regex Compile(string pattern, bool ignoreCase = false, int kind = 0, RegexOptions extra = RegexOptions.None)
    {
        var opts = RegexOptions.CultureInvariant | extra | (ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None);
        return Cache.GetOrAdd((pattern ?? "", opts, kind), key =>
        {
            var p = Translate(key.Item1);
            if (key.Item3 == 1) p = "\\G(?:" + p + ")";
            else if (key.Item3 == 2) p = "\\A(?:" + p + ")\\z";
            try { return new Regex(p, key.Item2); }
            catch (ArgumentException exc) { throw new PyReError(Reason(exc)); }
        });
    }

    static string Reason(ArgumentException exc)
    {
        var m = exc.Message;
        int at = m.IndexOf(" - ", StringComparison.Ordinal);
        return at >= 0 ? m.Substring(at + 3).TrimEnd('.') : m;
    }

    /// <summary>Raise PyReError when pattern is not a valid regular expression.</summary>
    public static void Check(string pattern) => Compile(pattern);

    public static bool IsValid(string pattern)
    {
        try { Compile(pattern); return true; }
        catch (PyReError) { return false; }
    }

    /// <summary>re.search: the first match anywhere, or null.</summary>
    public static Match Search(string pattern, string s, bool ignoreCase = false)
    {
        var m = Compile(pattern, ignoreCase).Match(s ?? "");
        return m.Success ? m : null;
    }

    /// <summary>re.match: a match at the start, or null.</summary>
    public static Match MatchStart(string pattern, string s, bool ignoreCase = false)
    {
        var m = Compile(pattern, ignoreCase, 1).Match(s ?? "", 0);
        return m.Success ? m : null;
    }

    /// <summary>re.fullmatch</summary>
    public static Match FullMatch(string pattern, string s, bool ignoreCase = false)
    {
        var m = Compile(pattern, ignoreCase, 2).Match(s ?? "");
        return m.Success ? m : null;
    }

    /// <summary>re.split for patterns without groups.</summary>
    public static string[] Split(string pattern, string s) => Compile(pattern).Split(s ?? "");

    /// <summary>re.findall for a pattern without groups: every whole match.</summary>
    public static List<string> FindAll(string pattern, string s) =>
        Compile(pattern).Matches(s ?? "").Select(m => m.Value).ToList();

    /// <summary>The groups of a match as Python's m.groups(): null for a group that did not take part.</summary>
    public static List<string> Groups(Match m)
    {
        var out_ = new List<string>();
        for (int i = 1; i < m.Groups.Count; i++)
            out_.Add(m.Groups[i].Success ? m.Groups[i].Value : null);
        return out_;
    }

    /// <summary>re.sub(pattern, repl, s) with a Python replacement template (\1, \g&lt;name&gt;, \n...).</summary>
    public static string Sub(string pattern, string repl, string s, bool ignoreCase = false)
    {
        var rx = Compile(pattern, ignoreCase);
        var parts = ParseTemplate(repl ?? "", rx);
        return rx.Replace(s ?? "", m =>
        {
            var sb = new StringBuilder();
            foreach (var (lit, grp) in parts)
            {
                if (lit != null) sb.Append(lit);
                else
                {
                    var g = grp is int gi ? m.Groups[gi] : m.Groups[(string)grp];
                    if (g.Success) sb.Append(g.Value);
                }
            }
            return sb.ToString();
        });
    }

    /// <summary>re.sub with a function.</summary>
    public static string Sub(string pattern, MatchEvaluator fn, string s, bool ignoreCase = false)
        => Compile(pattern, ignoreCase).Replace(s ?? "", fn);

    static List<(string, object)> ParseTemplate(string t, Regex rx)
    {
        var parts = new List<(string, object)>();
        var lit = new StringBuilder();
        void Flush() { if (lit.Length > 0) { parts.Add((lit.ToString(), null)); lit.Clear(); } }
        for (int i = 0; i < t.Length; i++)
        {
            char c = t[i];
            if (c != '\\' || i + 1 >= t.Length) { lit.Append(c); continue; }
            char n = t[++i];
            if (char.IsAsciiDigit(n))
            {
                int j = i;
                while (j < t.Length && j < i + 2 && char.IsAsciiDigit(t[j])) j++;
                int num = int.Parse(t.AsSpan(i, j - i));
                if (num >= rx.GetGroupNumbers().Length) throw new PyReError($"invalid group reference {num}");
                Flush();
                parts.Add((null, num));
                i = j - 1;
                continue;
            }
            if (n == 'g' && i + 1 < t.Length && t[i + 1] == '<')
            {
                int close = t.IndexOf('>', i);
                if (close < 0) throw new PyReError("missing >, unterminated name");
                var name = t.Substring(i + 2, close - i - 2);
                Flush();
                parts.Add((null, int.TryParse(name, out var gn) ? gn : name));
                i = close;
                continue;
            }
            switch (n)
            {
                case 'n': lit.Append('\n'); break;
                case 't': lit.Append('\t'); break;
                case 'r': lit.Append('\r'); break;
                case 'f': lit.Append('\f'); break;
                case 'v': lit.Append('\v'); break;
                case 'a': lit.Append('\a'); break;
                case 'b': lit.Append('\b'); break;
                case '\\': lit.Append('\\'); break;
                default:
                    if (char.IsAsciiLetter(n)) throw new PyReError($"bad escape \\{n}");
                    lit.Append('\\').Append(n);
                    break;
            }
        }
        Flush();
        return parts;
    }

    const string Special = "()[]{}?*+-|^$\\.&~# \t\n\r\v\f";

    /// <summary>re.escape (Python 3.7+): only the characters that mean something in a pattern.</summary>
    public static string Escape(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s ?? "")
        {
            if (Special.IndexOf(c) >= 0) sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }
}
