using Imw.Core;

namespace Imw.Adapters;

/// <summary>
/// Generic table: any CSV, TSV or Excel (.xlsx) sheet with one credential per row. Columns are
/// found through config field_aliases, or set explicitly in sources.table.columns.
/// </summary>
public sealed class TableAdapter : Adapter
{
    public override string Name => "table";
    public override string Description => "Generic CSV / TSV / Excel (.xlsx) sheet, one account per row";

    static bool IsExcel(string p) => p.EndsWith(".xlsx") || p.EndsWith(".xlsm");

    public override int Sniff(string path)
    {
        var p = path.ToLowerInvariant();
        if (IsExcel(p)) return 50;
        if (p.EndsWith(".csv") || p.EndsWith(".tsv") || p.EndsWith(".txt"))
            return Py.Strip(ReadHead(path, 1024)).Length > 0 ? 20 : 0;
        return 0;
    }

    static int HeaderRow(JObj tcfg)
    {
        var v = tcfg.Get("header_row");
        if (!Py.Truthy(v)) return 1;
        return (int)(Py.ToLong(v) ?? throw new ValueError($"invalid literal for int() with base 10: {Py.ReprStr(Py.Str(v))}"));
    }

    IEnumerable<(string, int, StrDict)> RowsOf(string path, JObj tcfg, string encoding)
    {
        var p = path.ToLowerInvariant();
        int headerRow = HeaderRow(tcfg);
        List<List<string>> rows;
        string label;
        if (IsExcel(p))
        {
            var (sheet, r) = Xlsx.ReadRows(path, Py.Str(tcfg.Get("sheet", "")));
            rows = r;
            label = $"{sheet}!row ";
        }
        else
        {
            rows = CsvSafe.Reading(path, () =>
            {
                var text = Csv.ReadText(path, encoding);
                var sample = text.Length > 8192 ? text.Substring(0, 8192) : text;
                Dialect dialect;
                try { dialect = Csv.Sniff(sample, ",;\t|"); }
                catch (CsvError) { dialect = p.EndsWith(".tsv") ? Dialect.ExcelTab : Dialect.Excel; }
                return new Csv.Reader(text, dialect).Rows().ToList();
            });
            label = "row ";
        }
        if (rows.Count < headerRow) yield break;
        var headers = new List<string>();
        var seen = new Dictionary<string, int>();
        var hrow = rows[headerRow - 1];
        for (int i = 0; i < hrow.Count; i++)
        {
            var h = Py.Strip(hrow[i] ?? "");
            if (h.Length == 0) h = $"Column_{i + 1}";
            var k = Py.Lower(h);
            seen[k] = seen.GetValueOrDefault(k) + 1;
            headers.Add(seen[k] == 1 ? h : $"{h}_{seen[k]}");
        }
        for (int idx = headerRow; idx < rows.Count; idx++)
        {
            int n = idx + 1;
            var values = rows[idx].ToList();
            if (!values.Any(v => Py.Strip(v ?? "").Length > 0)) continue;
            while (values.Count > headers.Count && Py.Strip(values[^1] ?? "").Length == 0) values.RemoveAt(values.Count - 1);
            while (values.Count < headers.Count) values.Add("");
            var cols = headers.Concat(Enumerable.Range(1, values.Count - headers.Count).Select(i => $"Extra_{i}")).ToList();
            var d = new StrDict();
            for (int i = 0; i < cols.Count; i++) d[cols[i]] = values[i];
            yield return ($"{label}{n}", n, d);
        }
    }

    // The fields the column picker offers, in the order it shows them.
    public static readonly string[] Pickable = { "name", "address", "username", "folder", "type", "password", "private_key",
                                                 "access", "safe", "platform", "id" };

    /// <summary>The file's column headers and, for each field, the column it is read from now.</summary>
    public (List<string>, JObj) ColumnReport(string path, JObj cfg, string encoding = "utf-8-sig")
    {
        var tcfg = cfg.Obj("sources").Obj("table");
        var first = RowsOf(path, tcfg, encoding).Select(r => r.Item3).FirstOrDefault();
        var headers = (first?.Keys ?? new List<string>()).Where(h => !h.StartsWith("Extra_")).ToList();
        var lookup = ColumnLookup(headers);
        var explicit_ = tcfg.Obj("columns") ?? new JObj();
        var current = new JObj();
        foreach (var field in Pickable)
        {
            var aliases = Py.Truthy(explicit_.Get(field))
                ? new List<string> { Py.Str(explicit_[field]) }
                : (cfg.Obj("field_aliases").List(field) ?? new List<object>()).Select(x => Py.Str(x)).ToList();
            current[field] = FindColumn(lookup, aliases) ?? "";
        }
        return (headers, current);
    }

    public override List<SourceRecord> Read(string path, JObj cfg, string encoding = "utf-8-sig")
    {
        var tcfg = cfg.Obj("sources").Obj("table");
        var stem = FileStem(path);
        bool fromCsv = !IsExcel(path.ToLowerInvariant());
        var columns = (tcfg.Obj("columns") ?? new JObj()).ToDictionary(kv => kv.Key, kv => kv.Value == null ? null : Py.Str(kv.Value));
        var sep = Py.Truthy(tcfg.Get("folder_separator")) ? Py.Str(tcfg["folder_separator"]) : "auto";
        var groupCol = Py.Str(tcfg.Get("group_column", "") ?? "");
        var permCol = Py.Str(tcfg.Get("permission_column", "") ?? "");
        var records = RowsOf(path, tcfg, encoding).Select(r =>
            Rows.RecordFromRow(r.Item3, cfg, Name, stem, r.Item1, r.Item2, columns: columns, folderSeparator: sep,
                               groupColumn: groupCol, permissionColumn: permCol, fromCsv: fromCsv));
        if (!Py.Truthy(tcfg.Get("group_column"))) return records.ToList();
        // One grant per row: rows for the same account are merged into one record.
        var merged = new Dictionary<string, SourceRecord>();
        var order = new List<SourceRecord>();
        foreach (var rec in records)
        {
            var key = string.Join("\0", Py.Lower(rec.Name), Py.Lower(rec.Address), Py.Lower(rec.Username), Py.Lower(rec.FolderPath));
            if (merged.TryGetValue(key, out var first))
            {
                first.Grants = (first.Grants ?? new List<Grant>()).Concat(rec.Grants ?? new List<Grant>()).ToList();
                if (rec.Secret != first.Secret)
                    first.Notes.Add($"{rec.SourceRef} has a different secret for the same account; first one kept");
            }
            else
            {
                merged[key] = rec;
                order.Add(rec);
            }
        }
        return order;
    }
}
