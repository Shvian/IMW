using System.Text.RegularExpressions;
using Imw.Core;

namespace Imw.Adapters;

/// <summary>Turn one tabular row (column -> value) into a SourceRecord. Shared by the Delinea
/// adapter and the generic CSV/Excel adapter.</summary>
public static class Rows
{
    static readonly Regex AccessSplit = new("[;\n]+", RegexOptions.CultureInvariant);
    static readonly Regex ExtraCol = new(@"^Extra_\d+$", RegexOptions.CultureInvariant);

    public static bool IsExtraCol(string c) => ExtraCol.IsMatch(c);

    /// <summary>'CORP\A=Owner; CORP\B=View' (or ':' / '|' instead of '=') -> grants.</summary>
    public static List<Grant> ParseAccess(string text)
    {
        var grants = new List<Grant>();
        foreach (var raw in AccessSplit.Split(text ?? ""))
        {
            var part = Py.Strip(raw);
            if (part.Length == 0) continue;
            var m = PyRe.MatchStart(@"^(.*?)\s*[=|]\s*([^=|]+)$", part);
            grants.Add(m != null ? new Grant(Py.Strip(m.Groups[1].Value), Py.Strip(m.Groups[2].Value)) : new Grant(part, ""));
        }
        return grants;
    }

    public const string Shifted = SourceRecord.ErrorNote + "this row has more values than the header has columns, so its values have " +
        "probably moved (for example an unquoted comma in a password). Values from the secret column " +
        "on are not kept. Fix the export and load it again.";

    static (StrDict, bool) GuardShifted(StrDict row, Dictionary<string, List<string>> aliases, JObj cfg)
    {
        if (!row.Any(kv => ExtraCol.IsMatch(kv.Key) && Py.Strip(kv.Value ?? "").Length > 0)) return (row, false);
        var secretCols = new HashSet<string>();
        foreach (var k in new[] { "password", "private_key" })
            if (aliases.TryGetValue(k, out var list))
                foreach (var a in list) secretCols.Add(Py.Lower(Py.Strip(a)));
        var cols = row.Keys.ToList();
        int? first = null;
        for (int i = 0; i < cols.Count; i++)
            if (secretCols.Contains(Py.Lower(Py.Strip(cols[i]))) || Adapter.IsSecretColumn(cols[i], cfg)) { first = i; break; }
        int start = first ?? cols.FindIndex(c => ExtraCol.IsMatch(c));
        var out_ = new StrDict();
        int j = 0;
        foreach (var kv in row) { out_[kv.Key] = j < start ? kv.Value : ""; j++; }
        return (out_, true);
    }

    static readonly string[] Logical = { "id", "name", "folder", "type", "address", "username", "password",
                                         "private_key", "access", "safe", "platform" };

    /// <summary>fromCsv: values past the header can only mean a shifted row (see Shifted).</summary>
    public static SourceRecord RecordFromRow(StrDict row, JObj cfg, string source, string sourceFile, string rowRef,
        int rowNumber, string typeHint = "", IDictionary<string, string> columns = null, string folderSeparator = "\\",
        string groupColumn = "", string permissionColumn = "", bool fromCsv = false)
    {
        var aliases = new Dictionary<string, List<string>>();
        foreach (var kv in cfg.Obj("field_aliases"))
            aliases[kv.Key] = ((List<object>)kv.Value).Select(x => Py.Str(x)).ToList();
        // An explicit mapping wins over the aliases.
        if (columns != null)
            foreach (var kv in columns)
                if (!string.IsNullOrEmpty(kv.Value)) aliases[kv.Key] = new List<string> { kv.Value };
        bool shifted = false;
        if (fromCsv) (row, shifted) = GuardShifted(row, aliases, cfg);
        var skipCols = new HashSet<string>();
        foreach (var c in new[] { groupColumn, permissionColumn })
            if (!string.IsNullOrEmpty(c)) skipCols.Add(Py.Lower(Py.Strip(c)));
        var fullLookup = Adapter.ColumnLookup(row.Keys.Where(c => !c.StartsWith('_')));
        var lookup = fullLookup.Where(kv => !skipCols.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);
        string groupCol = !string.IsNullOrEmpty(groupColumn) ? fullLookup.GetValueOrDefault(Py.Lower(Py.Strip(groupColumn))) : null;
        string permCol = !string.IsNullOrEmpty(permissionColumn) ? fullLookup.GetValueOrDefault(Py.Lower(Py.Strip(permissionColumn))) : null;

        var used = new Dictionary<string, (string col, string val)>();
        foreach (var logical in Logical)
            used[logical] = Adapter.FirstValue(row, lookup, aliases.GetValueOrDefault(logical) ?? new List<string>());

        var idv = Py.Strip(used["id"].val);
        var rec = new SourceRecord(source, sourceFile, idv.Length > 0 ? idv : $"row{rowNumber}", rowRef);
        if (shifted) rec.Notes.Add(Shifted);
        rec.Name = Py.Strip(used["name"].val);
        rec.Folder = SourceRecord.SplitFolder(used["folder"].val, folderSeparator);
        var tv = used["type"].val;
        rec.Type = Py.Strip(tv.Length > 0 ? tv : (typeHint ?? ""));
        rec.Address = Py.Strip(used["address"].val);
        rec.Username = Py.Strip(used["username"].val);
        rec.TargetSafe = Py.Strip(used["safe"].val);
        rec.TargetPlatform = Py.Strip(used["platform"].val);

        var key = used["private_key"].val;
        var pwd = used["password"].val;
        var keyTypes = cfg.List("key_types").Select(t => Py.Lower(Py.Str(t))).ToHashSet();
        if (Py.Strip(key).Length > 0 || keyTypes.Contains(Py.Lower(rec.Type)))
        {
            rec.SecretType = "key";
            rec.Secret = key;
            foreach (var kv in row)
                if (Py.Lower(kv.Key).Contains("passphrase") && Py.Strip(kv.Value ?? "").Length > 0)
                    rec.Notes.Add($"key has a passphrase in '{kv.Key}'; Privilege Cloud key accounts do not take it, confirm the platform handles it");
        }
        else rec.Secret = pwd;
        if (Py.Strip(rec.Secret).Length == 0 && !shifted) rec.Notes.Add("secret is empty in the source");

        if (!string.IsNullOrEmpty(used["access"].col)) rec.Grants = ParseAccess(used["access"].val);
        var groupVal = groupCol != null ? Py.Strip(row.Get(groupCol) ?? "") : "";
        if (groupVal.Length > 0)
        {
            var permVal = permCol != null ? Py.Strip(row.Get(permCol) ?? "") : "";
            rec.Grants = (rec.Grants ?? new List<Grant>()).Append(new Grant(groupVal, permVal)).ToList();
        }

        rec.Extra = new StrDict();
        var otp = Adapter.OtpFields(row.Where(kv => !kv.Key.StartsWith('_')));
        if (otp.Count > 0) rec.Notes.Add(Adapter.OtpNote(otp));
        var exclude = cfg.List("exclude_field_patterns").Select(x => Py.Str(x)).ToList();
        foreach (var kv in row)
        {
            var col = kv.Key;
            var val = kv.Value;
            if (col.StartsWith('_')) continue;
            if (otp.Contains(col) && (Adapter.IsSecretColumn(col, cfg) || Adapter.IsOtpValue(val))) continue;
            if (Adapter.IsSecretColumn(col, cfg))
            {
                if (Py.Strip(val ?? "").Length > 0 && col != used["password"].col && col != used["private_key"].col
                    && !Py.Lower(col).Contains("passphrase"))
                    rec.Notes.Add($"secret field '{col}' is not migrated (an account takes one secret) and is left out of the review files");
                continue;
            }
            if (Adapter.MatchesAny(col, exclude))
            {
                if (Py.Strip(val ?? "").Length > 0) rec.Notes.Add($"attachment field '{col}' not migrated");
                continue;
            }
            val ??= "";
            if (Py.Strip(val).Length == 0 && ExtraCol.IsMatch(col)) continue;
            rec.Extra[col] = val;
        }
        return rec;
    }
}
