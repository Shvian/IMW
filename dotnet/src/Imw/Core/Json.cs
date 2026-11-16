using System.Collections;
using System.Globalization;
using System.Text;

namespace Imw.Core;

/// <summary>
/// An insertion-ordered JSON object, like a Python dict: the settings file, API bodies and
/// results are all built from JObj, List&lt;object&gt;, string, long, double, bool and null.
/// </summary>
public sealed class JObj : IEnumerable<KeyValuePair<string, object>>
{
    readonly List<string> _keys = new();
    readonly Dictionary<string, object> _map = new(StringComparer.Ordinal);

    public JObj() { }

    public JObj(IEnumerable<KeyValuePair<string, object>> items)
    {
        foreach (var kv in items) this[kv.Key] = kv.Value;
    }

    public object this[string key]
    {
        get => _map.TryGetValue(key, out var v) ? v : null;
        set
        {
            if (!_map.ContainsKey(key)) _keys.Add(key);
            _map[key] = value;
        }
    }

    public int Count => _keys.Count;
    public IReadOnlyList<string> Keys => _keys;
    public IEnumerable<object> Values => _keys.Select(k => _map[k]);
    public bool ContainsKey(string key) => _map.ContainsKey(key);
    public bool TryGetValue(string key, out object value) => _map.TryGetValue(key, out value);

    /// <summary>dict.get(key, default)</summary>
    public object Get(string key, object dflt = null) => _map.TryGetValue(key, out var v) ? v : dflt;

    public bool Remove(string key)
    {
        if (!_map.Remove(key)) return false;
        _keys.Remove(key);
        return true;
    }

    /// <summary>dict.pop(key, default)</summary>
    public object Pop(string key, object dflt = null)
    {
        if (!_map.TryGetValue(key, out var v)) return dflt;
        Remove(key);
        return v;
    }

    /// <summary>dict.setdefault(key, value)</summary>
    public object SetDefault(string key, object value)
    {
        if (_map.TryGetValue(key, out var v)) return v;
        this[key] = value;
        return value;
    }

    /// <summary>dict.update(other)</summary>
    public void Update(JObj other)
    {
        foreach (var kv in other) this[kv.Key] = kv.Value;
    }

    public JObj Copy() => new(this);

    public IEnumerator<KeyValuePair<string, object>> GetEnumerator()
    {
        foreach (var k in _keys.ToList()) yield return new KeyValuePair<string, object>(k, _map[k]);
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    // Typed reads used all over the rules code.
    public JObj Obj(string key) => Get(key) as JObj;
    public List<object> List(string key) => Get(key) as List<object>;
    public string S(string key) => Get(key) as string;
}

public class JsonError : ValueError
{
    public JsonError(string message) : base(message) { }
}

/// <summary>JSON read and written exactly as Python's json module does.</summary>
public static class Json
{
    // ------------------------------------------------------------------ parse

    public static object Parse(string text)
    {
        var p = new Parser(text ?? "");
        p.Ws();
        var v = p.Value();
        p.Ws();
        if (p.Pos < p.Text.Length) throw new JsonError($"Extra data: line 1 column {p.Pos + 1} (char {p.Pos})");
        return v;
    }

    public static JObj ParseObj(string text) => Parse(text) as JObj ?? throw new JsonError("expected a JSON object");

    sealed class Parser
    {
        public readonly string Text;
        public int Pos;
        public Parser(string t) { Text = t; }

        public void Ws()
        {
            while (Pos < Text.Length && (Text[Pos] == ' ' || Text[Pos] == '\t' || Text[Pos] == '\n' || Text[Pos] == '\r')) Pos++;
        }

        JsonError Err(string what) => new($"{what}: char {Pos}");

        public object Value()
        {
            if (Pos >= Text.Length) throw Err("Expecting value");
            char c = Text[Pos];
            switch (c)
            {
                case '{': return Object();
                case '[': return Array();
                case '"': return Str();
                case 't': return Word("true", true);
                case 'f': return Word("false", false);
                case 'n': return Word("null", null);
                case 'N': return Word("NaN", double.NaN);
                case 'I': return Word("Infinity", double.PositiveInfinity);
                default:
                    if (c == '-' && Pos + 1 < Text.Length && Text[Pos + 1] == 'I') { Pos++; Word("Infinity", null); return double.NegativeInfinity; }
                    if (c == '-' || (c >= '0' && c <= '9')) return Number();
                    throw Err("Expecting value");
            }
        }

        object Word(string w, object v)
        {
            if (string.CompareOrdinal(Text, Pos, w, 0, w.Length) != 0) throw Err("Expecting value");
            Pos += w.Length;
            return v;
        }

        object Number()
        {
            int start = Pos;
            if (Text[Pos] == '-') Pos++;
            if (Pos < Text.Length && Text[Pos] == '0') Pos++;
            else
            {
                if (Pos >= Text.Length || !char.IsAsciiDigit(Text[Pos])) throw Err("Expecting value");
                while (Pos < Text.Length && char.IsAsciiDigit(Text[Pos])) Pos++;
            }
            bool isFloat = false;
            if (Pos + 1 < Text.Length && Text[Pos] == '.' && char.IsAsciiDigit(Text[Pos + 1]))
            {
                isFloat = true;
                Pos++;
                while (Pos < Text.Length && char.IsAsciiDigit(Text[Pos])) Pos++;
            }
            if (Pos < Text.Length && (Text[Pos] == 'e' || Text[Pos] == 'E'))
            {
                int save = Pos;
                Pos++;
                if (Pos < Text.Length && (Text[Pos] == '+' || Text[Pos] == '-')) Pos++;
                if (Pos < Text.Length && char.IsAsciiDigit(Text[Pos]))
                {
                    isFloat = true;
                    while (Pos < Text.Length && char.IsAsciiDigit(Text[Pos])) Pos++;
                }
                else Pos = save;
            }
            var s = Text.Substring(start, Pos - start);
            if (!isFloat && long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l)) return l;
            return double.Parse(s, NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        string Str()
        {
            Pos++;
            var sb = new StringBuilder();
            while (true)
            {
                if (Pos >= Text.Length) throw Err("Unterminated string starting at");
                char c = Text[Pos++];
                if (c == '"') return sb.ToString();
                if (c == '\\')
                {
                    if (Pos >= Text.Length) throw Err("Unterminated string starting at");
                    char e = Text[Pos++];
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (Pos + 4 > Text.Length) throw Err("Invalid \\uXXXX escape");
                            sb.Append((char)int.Parse(Text.AsSpan(Pos, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                            Pos += 4;
                            break;
                        default: throw Err("Invalid \\escape");
                    }
                }
                else if (c < ' ') throw Err("Invalid control character at");
                else sb.Append(c);
            }
        }

        List<object> Array()
        {
            Pos++;
            var list = new List<object>();
            Ws();
            if (Pos < Text.Length && Text[Pos] == ']') { Pos++; return list; }
            while (true)
            {
                Ws();
                list.Add(Value());
                Ws();
                if (Pos < Text.Length && Text[Pos] == ',') { Pos++; continue; }
                if (Pos < Text.Length && Text[Pos] == ']') { Pos++; return list; }
                throw Err("Expecting ',' delimiter");
            }
        }

        JObj Object()
        {
            Pos++;
            var obj = new JObj();
            Ws();
            if (Pos < Text.Length && Text[Pos] == '}') { Pos++; return obj; }
            while (true)
            {
                Ws();
                if (Pos >= Text.Length || Text[Pos] != '"') throw Err("Expecting property name enclosed in double quotes");
                var key = Str();
                Ws();
                if (Pos >= Text.Length || Text[Pos] != ':') throw Err("Expecting ':' delimiter");
                Pos++;
                Ws();
                obj[key] = Value();
                Ws();
                if (Pos < Text.Length && Text[Pos] == ',') { Pos++; continue; }
                if (Pos < Text.Length && Text[Pos] == '}') { Pos++; return obj; }
                throw Err("Expecting ',' delimiter");
            }
        }
    }

    // ------------------------------------------------------------------ write

    /// <summary>json.dumps(v) (indent: null for one line with ", " and ": ").</summary>
    public static string Dumps(object v, int? indent = null)
    {
        var sb = new StringBuilder();
        Write(sb, v, indent, 0);
        return sb.ToString();
    }

    static void Write(StringBuilder sb, object v, int? indent, int level)
    {
        switch (v)
        {
            case null: sb.Append("null"); return;
            case bool b: sb.Append(b ? "true" : "false"); return;
            case string s: Quote(sb, s); return;
            case long or int: sb.Append(Convert.ToInt64(v).ToString(CultureInfo.InvariantCulture)); return;
            case double d:
                sb.Append(double.IsNaN(d) ? "NaN" : double.IsPositiveInfinity(d) ? "Infinity"
                    : double.IsNegativeInfinity(d) ? "-Infinity" : Py.FloatRepr(d));
                return;
            case JObj o:
                if (o.Count == 0) { sb.Append("{}"); return; }
                sb.Append('{');
                bool first = true;
                foreach (var kv in o)
                {
                    if (!first) sb.Append(indent == null ? ", " : ",");
                    first = false;
                    Newline(sb, indent, level + 1);
                    Quote(sb, kv.Key);
                    sb.Append(": ");
                    Write(sb, kv.Value, indent, level + 1);
                }
                Newline(sb, indent, level);
                sb.Append('}');
                return;
            case IEnumerable e:
                var items = e.Cast<object>().ToList();
                if (items.Count == 0) { sb.Append("[]"); return; }
                sb.Append('[');
                for (int i = 0; i < items.Count; i++)
                {
                    if (i > 0) sb.Append(indent == null ? ", " : ",");
                    Newline(sb, indent, level + 1);
                    Write(sb, items[i], indent, level + 1);
                }
                Newline(sb, indent, level);
                sb.Append(']');
                return;
            default:
                Quote(sb, v.ToString());       // json.dumps(default=str)
                return;
        }
    }

    static void Newline(StringBuilder sb, int? indent, int level)
    {
        if (indent == null) return;
        sb.Append('\n').Append(' ', indent.Value * level);
    }

    /// <summary>A JSON string with ensure_ascii, as Python writes it.</summary>
    public static void Quote(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < ' ' || c > '~') sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>copy.deepcopy of a JSON-like value.</summary>
    public static object DeepCopy(object v) => v switch
    {
        JObj o => new JObj(o.Select(kv => new KeyValuePair<string, object>(kv.Key, DeepCopy(kv.Value)))),
        List<object> l => l.Select(DeepCopy).ToList(),
        _ => v,
    };

    public static JObj DeepCopy(JObj o) => (JObj)DeepCopy((object)o);

    /// <summary>A JSON list of strings.</summary>
    public static List<object> L(params object[] items) => items.ToList();

    public static JObj O(params (string, object)[] items)
    {
        var o = new JObj();
        foreach (var (k, v) in items) o[k] = v;
        return o;
    }
}
