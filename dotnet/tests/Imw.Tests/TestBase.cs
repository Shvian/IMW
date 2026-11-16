using System.IO.Compression;
using System.Security;
using System.Text;

// Tests change the console, the environment and the current folder: run them one at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Imw.Tests;

/// <summary>Shared helpers (port of the Base class and helpers in tests/test_imw.py).</summary>
public abstract class TestBase : IDisposable
{
    public static readonly string Root = FindRoot();
    public static readonly string Samples = Path.Combine(Root, "samples");
    public static readonly string[] SecretsInSamples =
        { "P@ssw0rd!1", "Kp!root-web02", "FAKEKEYDATA", "Sql!01sa", "Adm!101", "Rt!batch01", "otpauth://" };

    protected readonly string Tmp;

    protected TestBase()
    {
        Tmp = Path.Combine(Path.GetTempPath(), "imw-test-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(Tmp);
    }

    public virtual void Dispose()
    {
        try { Directory.Delete(Tmp, true); } catch (Exception) { }
        GC.SuppressFinalize(this);
    }

    static string FindRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !Directory.Exists(Path.Combine(d.FullName, "samples"))) d = d.Parent;
        return d?.FullName ?? throw new DirectoryNotFoundException("repository root (with samples/) not found");
    }

    public static string S(string name) => Path.Combine(Samples, name);

    /// <summary>A JSON object written as JSON text (Python dict literals in the original tests).</summary>
    public static JObj J(string json) => Json.ParseObj(json);

    /// <summary>config_from_dict(json)</summary>
    public static JObj Cfg(string json = "{}") => Config.FromDict(J(json));
    protected string T(params string[] parts) => Path.Combine(new[] { Tmp }.Concat(parts).ToArray());

    protected static (int, string) RunCli(params string[] args)
    {
        var old = Console.Out;
        var buf = new StringWriter();
        Console.SetOut(buf);
        try { return (Cli.Run(args), buf.ToString()); }
        finally { Console.SetOut(old); }
    }

    protected string ConvertFiles(IEnumerable<string> inputs, string config = null, IEnumerable<string> extra = null, string out_ = "out")
    {
        var args = new List<string> { "convert", "-o", T(out_), "--force" };
        foreach (var i in inputs) args.AddRange(new[] { "-i", i });
        if (config != null) args.AddRange(new[] { "-c", config });
        args.AddRange(extra ?? Array.Empty<string>());
        var (rc, text) = RunCli(args.ToArray());
        Assert.True(rc == 0, text);
        return T(out_);
    }

    protected string ConvertOne(string input, string config = null, params string[] extra) => ConvertFiles(new[] { input }, config, extra);

    public static List<Dictionary<string, string>> ReadCsv(string path)
    {
        var text = Csv.ReadText(path, "utf-8-sig");
        return new Csv.DictReader(text).Rows().Select(r => r.ToDictionary(kv => kv.Key, kv => kv.Value ?? "")).ToList();
    }

    public static string ReadText(string path) => Csv.ReadText(path, "utf-8-sig");

    protected static void AssertNoSecrets(string folder)
    {
        foreach (var f in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            var body = ReadText(f);
            foreach (var s in SecretsInSamples)
                Assert.False(body.Contains(s, StringComparison.Ordinal), $"secret '{s}' leaked into {f}");
        }
    }

    protected static void WriteCsv(string path, IEnumerable<string> header, IEnumerable<IEnumerable<object>> rows, bool bom = true)
    {
        var sw = new StringWriter();
        var w = new Csv.Writer(sw);
        w.WriteRow(header);
        foreach (var r in rows) w.WriteRow(r);
        File.WriteAllText(path, sw.ToString(), new UTF8Encoding(bom));
    }

    protected static void WriteDictCsv(string path, List<Dictionary<string, string>> rows, List<string> fields = null)
    {
        fields ??= rows[0].Keys.ToList();
        WriteCsv(path, fields, rows.Select(r => fields.Select(f => (object)r.GetValueOrDefault(f, ""))));
    }

    protected static void WriteText(string path, string text, bool bom = false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
        File.WriteAllText(path, text, new UTF8Encoding(bom));
    }

    protected static string Id(Dictionary<string, string> row, string col = "Record_ID") => row[col].Split(':').Last();
}

/// <summary>Tiny .xlsx writer for tests (port of tests/xlsx_writer.py).</summary>
public static class XlsxWriter
{
    static string Col(int i)
    {
        var s = "";
        i += 1;
        while (i > 0)
        {
            var r = (i - 1) % 26;
            i = (i - 1) / 26;
            s = (char)(65 + r) + s;
        }
        return s;
    }

    static string Esc(string s) => SecurityElement.Escape(s).Replace("&apos;", "'").Replace("&quot;", "\"");

    /// <summary>sheets: name -> rows. Strings go to sharedStrings, numbers stay numbers.</summary>
    public static void Write(string path, IEnumerable<(string Name, List<object[]> Rows)> sheets)
    {
        var list = sheets.ToList();
        var shared = new List<string>();
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        int Sid(string t)
        {
            if (!index.TryGetValue(t, out var i)) { index[t] = i = shared.Count; shared.Add(t); }
            return i;
        }
        var sheetXml = new List<string>();
        foreach (var (_, rows) in list)
        {
            var out_ = new StringBuilder();
            for (int r = 0; r < rows.Count; r++)
            {
                var cells = new StringBuilder();
                for (int c = 0; c < rows[r].Length; c++)
                {
                    var v = rows[r][c];
                    var refc = $"{Col(c)}{r + 1}";
                    if (v == null || (v is string s0 && s0.Length == 0)) continue;
                    if (v is int or long or double) cells.Append($"<c r=\"{refc}\"><v>{Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)}</v></c>");
                    else cells.Append($"<c r=\"{refc}\" t=\"s\"><v>{Sid(v.ToString())}</v></c>");
                }
                out_.Append($"<row r=\"{r + 1}\">{cells}</row>");
            }
            sheetXml.Add("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                         "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">" +
                         $"<sheetData>{out_}</sheetData></worksheet>");
        }
        if (File.Exists(path)) File.Delete(path);
        using var z = ZipFile.Open(path, ZipArchiveMode.Create);
        void Put(string name, string text)
        {
            using var w = new StreamWriter(z.CreateEntry(name, CompressionLevel.Optimal).Open(), new UTF8Encoding(false));
            w.Write(text);
        }
        int n = list.Count;
        Put("[Content_Types].xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
            "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
            "<Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/>" +
            string.Concat(Enumerable.Range(0, n).Select(i => $"<Override PartName=\"/xl/worksheets/sheet{i + 1}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>")) +
            "</Types>");
        Put("_rels/.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");
        Put("xl/workbook.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" " +
            "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>" +
            string.Concat(list.Select((s, i) => $"<sheet name=\"{Esc(s.Name)}\" sheetId=\"{i + 1}\" r:id=\"rId{i + 1}\"/>")) + "</sheets></workbook>");
        Put("xl/_rels/workbook.xml.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            string.Concat(Enumerable.Range(0, n).Select(i => $"<Relationship Id=\"rId{i + 1}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{i + 1}.xml\"/>")) +
            $"<Relationship Id=\"rId{n + 1}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\" Target=\"sharedStrings.xml\"/>" +
            "</Relationships>");
        Put("xl/sharedStrings.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">" +
            string.Concat(shared.Select(s => $"<si><t xml:space=\"preserve\">{Esc(s)}</t></si>")) + "</sst>");
        for (int i = 0; i < n; i++) Put($"xl/worksheets/sheet{i + 1}.xml", sheetXml[i]);
    }

    public static readonly List<(string, List<object[]>)> Sample = new()
    {
        ("Instructions", new List<object[]> { new object[] { "This sheet is ignored; accounts are on the Accounts sheet." } }),
        ("Accounts", new List<object[]>
        {
            new object[] { "Account Inventory - exported 2026-11" },
            new object[] { "Account Name", "Server", "User Name", "Password", "Platform ID", "Target Safe", "AD Group", "Access Level", "Port" },
            new object[] { "unix-batch01-root", "batch01.corp.example.com", "root", "Rt!batch01", "UnixSSH", "", "CORP\\PAM-Unix-Admins", "Owner", 22 },
            new object[] { "unix-batch01-root", "batch01.corp.example.com", "root", "Rt!batch01", "UnixSSH", "", "CORP\\Helpdesk", "List", 22 },
            new object[] { "payments-api", "pay01.corp.example.com", "svc_pay", "Pay!01", "WinServerLocal", "APP:Payments/Prod", "CORP\\APP-Payments-Owners", "Owner", "" },
            new object[] { "leading zero id", "0042.corp.example.com", "0042", "=1+1", "WinServerLocal", "APP-Payments", "", "", 3389 },
        }),
    };
}
