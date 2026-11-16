using Imw.Core;

namespace Imw.Adapters;

/// <summary>
/// Delinea (Thycotic) Secret Server exports: the multi-template CSV export, and the XML export /
/// import file (see DelineaXml), which also carries folders and permissions.
///
/// The CSV export repeats a header row for each Secret Template, each with its own columns,
/// often preceded by a one-cell row holding the template name.
/// </summary>
public sealed class DelineaAdapter : Adapter
{
    public override string Name => "delinea";
    public override string Description => "Delinea / Thycotic Secret Server export: multi-template CSV, or XML (with folders and permissions)";

    static bool IsBlank(List<string> row) => !row.Any(c => Py.Strip(c).Length > 0);

    static List<string> Dedupe(List<string> headers)
    {
        var seen = new Dictionary<string, int>();
        var out_ = new List<string>();
        foreach (var raw in headers)
        {
            var h = Py.Strip(raw);
            if (h.Length == 0) h = "Unnamed";
            var k = Py.Lower(h);
            seen[k] = seen.GetValueOrDefault(k) + 1;
            out_.Add(seen[k] == 1 ? h : $"{h}_{seen[k]}");
        }
        return out_;
    }

    /// <summary>(template name, line number, row) for every data row.</summary>
    public static IEnumerable<(string, int, StrDict)> ParseSections(string path, IEnumerable<string> markers, string encoding = "utf-8-sig")
    {
        var mk = markers.Select(m => Py.Lower(m)).ToHashSet();
        var lines = CsvSafe.Reading(path, () =>
        {
            var text = Csv.ReadText(path, encoding);
            var reader = new Csv.Reader(text);
            var all = new List<(int, List<string>)>();
            List<string> row;
            while ((row = reader.Next()) != null) all.Add((reader.LineNum, row));
            return all;
        });
        lines = lines.Where(l => !IsBlank(l.Item2)).ToList();

        bool IsHeader(List<string> r) => r.Any(c => mk.Contains(Py.Lower(Py.Strip(c))));

        List<string> headers = null;
        string template = null, pending = null;
        for (int idx = 0; idx < lines.Count; idx++)
        {
            var (lineNo, row) = lines[idx];
            if (IsHeader(row))
            {
                headers = Dedupe(row);
                template = pending;
                pending = null;
                continue;
            }
            var nonEmpty = row.Where(c => Py.Strip(c).Length > 0).ToList();
            if (nonEmpty.Count == 1 && Py.Strip(row[0]).Length > 0 && idx + 1 < lines.Count && IsHeader(lines[idx + 1].Item2))
            {
                pending = Py.Strip(nonEmpty[0]);
                continue;
            }
            if (headers == null)
            {
                Log.Warning($"line {lineNo}: data before any header row, skipped");
                continue;
            }
            var cols = headers;
            if (row.Count > headers.Count)
            {
                var extra = row.Skip(headers.Count).ToList();
                if (extra.Any(c => Py.Strip(c).Length > 0))
                    Log.Warning($"line {lineNo}: {extra.Count} more values than headers; values may have moved, record marked as an error");
                cols = headers.Concat(Enumerable.Range(1, extra.Count).Select(i => $"Extra_{i}")).ToList();
            }
            else row = row.Concat(Enumerable.Repeat("", headers.Count - row.Count)).ToList();
            var d = new StrDict();
            for (int i = 0; i < cols.Count && i < row.Count; i++) d[cols[i]] = row[i];
            yield return (template, lineNo, d);
        }
    }

    public override int Sniff(string path)
    {
        var p = path.ToLowerInvariant();
        if (p.EndsWith(".xml")) return DelineaXml.Sniff(SafeXml.ReadHeadText(path));
        if (!p.EndsWith(".csv")) return 0;
        var head = Py.Lower(ReadHead(path));
        if (head.Contains("secret name") || head.Contains("secretname"))
            return head.Contains("folder path") || head.Contains("secret id") ? 80 : 60;
        return 0;
    }

    public override List<SourceRecord> Read(string path, JObj cfg, string encoding = "utf-8-sig")
    {
        if (path.ToLowerInvariant().EndsWith(".xml")) return DelineaXml.Read(Name, path, cfg);
        var scfg = cfg.Obj("sources").Obj("delinea");
        var stem = FileStem(path);
        var out_ = new List<SourceRecord>();
        int n = 0;
        foreach (var (template, lineNo, row) in ParseSections(path, scfg.List("header_markers").Select(x => Py.Str(x)), encoding))
        {
            n++;
            out_.Add(Rows.RecordFromRow(row, cfg, Name, stem, $"line {lineNo}", n, template ?? "", folderSeparator: "\\", fromCsv: true));
        }
        return out_;
    }
}
