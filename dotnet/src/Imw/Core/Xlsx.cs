using System.Globalization;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Imw.Core;

/// <summary>
/// Minimal .xlsx reader. Reads cell values as text. Formulas give their cached value. Dates
/// arrive as Excel serial numbers, because the reader does not interpret number formats.
/// </summary>
public static class Xlsx
{
    static readonly XNamespace M = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    static readonly XNamespace R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    static readonly XNamespace PR = "http://schemas.openxmlformats.org/package/2006/relationships";
    static readonly Regex CellRef = new(@"^([A-Z]+)(\d+)$", RegexOptions.CultureInvariant);
    const int MaxRow = 1_048_576, MaxCol = 16_384;
    internal static long MaxPartBytes = 512L * 1024 * 1024;     // tests lower it

    static XElement ReadXml(ZipArchive z, string name, string path)
    {
        var entry = z.GetEntry(name) ?? throw new ValueError($"{path}: the workbook is missing {name}");
        if (entry.Length > MaxPartBytes)
            throw new ValueError($"{path}: {name} unpacks to {entry.Length / (1024 * 1024)} MB, more than the " +
                                 $"{MaxPartBytes / (1024 * 1024)} MB this reader accepts. Save the sheet as CSV and load that instead.");
        byte[] raw;
        try
        {
            using var s = entry.Open();
            var ms = new MemoryStream();
            s.CopyTo(ms);
            raw = ms.ToArray();
        }
        catch (Exception exc) when (exc is InvalidDataException or IOException or NotSupportedException)
        {
            throw new ValueError($"{path}: {name} can't be unpacked, the workbook is damaged ({exc.Message})");
        }
        try { return SafeXml.FromBytes(raw); }
        catch (ValueError exc) { throw new ValueError($"{path}: {name}: {exc.Message}"); }
    }

    static int ColIndex(string letters)
    {
        int n = 0;
        foreach (var ch in letters) n = n * 26 + (ch - 64);
        return n - 1;
    }

    /// <summary>"".join(t.text for t in node.iter("{main}t"))</summary>
    static string Text(XElement node) =>
        string.Concat(node.DescendantsAndSelf(M + "t").Select(t => SafeXml.Text(t) ?? ""));

    /// <summary>Python float(v): whitespace allowed, underscores between digits, inf / nan.</summary>
    static bool PyFloat(string v, out double f)
    {
        var s = Py.Strip(v).Replace("_", "");
        if (Regex.IsMatch(s, @"^[+-]?(inf|infinity)$", RegexOptions.IgnoreCase)) { f = s.StartsWith('-') ? double.NegativeInfinity : double.PositiveInfinity; return true; }
        if (Regex.IsMatch(s, @"^[+-]?nan$", RegexOptions.IgnoreCase)) { f = double.NaN; return true; }
        if (!Regex.IsMatch(s, @"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")) { f = 0; return false; }
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out f);
    }

    static string Number(string v)
    {
        if (!PyFloat(v, out var f)) return v;
        if (!double.IsNaN(f) && !double.IsInfinity(f) && f == Math.Floor(f) && Math.Abs(f) < 1e15)
            return ((long)f).ToString(CultureInfo.InvariantCulture);
        return v;
    }

    static ZipArchive Open(string path)
    {
        try { return ZipFile.OpenRead(path); }
        catch (InvalidDataException)
        {
            throw new ValueError($"{path}: not a readable Excel workbook (the file is damaged, or not an .xlsx). " +
                                 "Open it in Excel and save it again, or save the sheet as CSV.");
        }
    }

    public static List<string> SheetNames(string path)
    {
        using var z = Open(path);
        var wb = ReadXml(z, "xl/workbook.xml", path);
        return wb.Elements(M + "sheets").Elements(M + "sheet").Select(s => (string)s.Attribute("name")).ToList();
    }

    /// <summary>(sheet name, rows); each row is a list of strings (an empty row is an empty list).</summary>
    public static (string, List<List<string>>) ReadRows(string path, string sheet = "")
    {
        string name;
        List<string> shared = new();
        XElement data;
        using (var z = Open(path))
        {
            var wb = ReadXml(z, "xl/workbook.xml", path);
            var rels = ReadXml(z, "xl/_rels/workbook.xml.rels", path);
            var targets = new Dictionary<string, string>();
            foreach (var r in rels.Elements(PR + "Relationship"))
            {
                var id = (string)r.Attribute("Id");
                if (id != null) targets[id] = (string)r.Attribute("Target");
            }
            var sheets = wb.Elements(M + "sheets").Elements(M + "sheet")
                .Select(s => ((string)s.Attribute("name"), (string)s.Attribute(R + "id"))).ToList();
            if (sheets.Count == 0) throw new ValueError($"{path}: workbook has no sheets");
            string rid;
            if (!string.IsNullOrEmpty(sheet))
            {
                var match = sheets.Where(s => Py.Lower(s.Item1) == Py.Lower(sheet)).ToList();
                if (match.Count == 0)
                    throw new ValueError($"{path}: no sheet named '{sheet}' (have: {string.Join(", ", sheets.Select(s => s.Item1))})");
                (name, rid) = match[0];
            }
            else (name, rid) = sheets[0];
            if (rid == null || !targets.TryGetValue(rid, out var tgt) || string.IsNullOrEmpty(tgt))
                throw new ValueError($"{path}: sheet '{name}' points at a part the workbook does not list; the file is damaged");
            var target = tgt.TrimStart('/');
            target = target.StartsWith("xl/") ? target : "xl/" + target;
            if (z.GetEntry("xl/sharedStrings.xml") != null)
            {
                var ss = ReadXml(z, "xl/sharedStrings.xml", path);
                shared = ss.Elements(M + "si").Select(Text).ToList();
            }
            data = ReadXml(z, target, path);
        }

        var rows = new List<List<string>>();
        int lastRnum = 0;
        foreach (var row in data.Elements(M + "sheetData").Elements(M + "row"))
        {
            var rattr = (string)row.Attribute("r");
            int rnum;
            if (string.IsNullOrEmpty(rattr)) rnum = lastRnum + 1;
            else if (!int.TryParse(Py.Strip(rattr), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out rnum))
                throw new ValueError($"{path}: bad row number {Py.ReprStr(rattr)}");
            if (rnum < 1 || rnum > MaxRow) throw new ValueError($"{path}: row number {rnum} is outside an Excel sheet");
            lastRnum = rnum;
            var cells = new SortedDictionary<int, string>();
            var order = new List<int>();
            int nextIdx = 0;
            foreach (var c in row.Elements(M + "c"))
            {
                var cr = (string)c.Attribute("r") ?? "";
                var m = CellRef.Match(cr);
                int idx = m.Success ? ColIndex(m.Groups[1].Value) : nextIdx;
                if (idx < 0 || idx >= MaxCol) throw new ValueError($"{path}: cell {(string)c.Attribute("r")} is outside an Excel sheet");
                nextIdx = idx + 1;
                var t = (string)c.Attribute("t") ?? "n";
                var vEl = c.Element(M + "v");
                var v = vEl == null ? "" : SafeXml.Text(vEl) ?? "";
                string val;
                if (t == "s")
                {
                    if (v.Length == 0) val = "";
                    else if (int.TryParse(Py.Strip(v), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var si)
                             && si >= -shared.Count && si < shared.Count)
                        val = shared[si < 0 ? shared.Count + si : si];
                    else
                        throw new ValueError($"{path}: cell {(string)c.Attribute("r")} points at a shared string that does not exist; the file is damaged");
                }
                else if (t == "inlineStr")
                {
                    var is_ = c.Element(M + "is");
                    val = is_ != null ? Text(is_) : "";
                }
                else if (t == "b") val = v == "1" ? "TRUE" : "FALSE";
                else if (t == "str" || t == "e") val = v;
                else val = v.Length > 0 ? Number(v) : "";
                if (val != "") cells[idx] = val;
            }
            if (cells.Count == 0) continue;
            var values = Enumerable.Repeat("", cells.Keys.Max() + 1).ToList();
            foreach (var kv in cells) values[kv.Key] = kv.Value;
            while (rows.Count < rnum - 1) rows.Add(new List<string>());
            if (rows.Count >= rnum) continue;              // rows out of order or repeated: keep the first
            rows.Add(values);
        }
        return (name, rows);
    }
}
