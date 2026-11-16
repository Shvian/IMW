using Imw.Adapters;
using Imw.Core;

namespace Imw;

/// <summary>A small argparse: sub-commands with options, flags, repeated options and positionals.</summary>
public sealed class ArgSpec
{
    public string[] Names;            // "--input", "-i"
    public string Dest;
    public bool Flag;
    public bool Append;
    public bool Required;
    public bool Positional;
    public bool Optional;              // positional with nargs="?"
    public string Default;
    public string[] Choices;
    public string Help = "";
    public bool IsInt;
}

public sealed class Args
{
    public readonly Dictionary<string, object> Values = new(StringComparer.Ordinal);
    public string Command;
    public string S(string k) => Values.TryGetValue(k, out var v) ? v as string : null;
    public bool B(string k) => Values.TryGetValue(k, out var v) && v is true;
    public List<string> L(string k) => Values.TryGetValue(k, out var v) ? v as List<string> : null;
    public int I(string k) => Values.TryGetValue(k, out var v) && v is int i ? i : 0;
}

public sealed class UsageError : Exception
{
    public UsageError(string message) : base(message) { }
}

public sealed class SubCommand
{
    public string Name, Help;
    public List<ArgSpec> Specs = new();
    public Func<Args, int> Run;

    public SubCommand Opt(string names, string help = "", bool flag = false, bool append = false, bool required = false,
                          string dflt = null, string[] choices = null, bool isInt = false)
    {
        var n = names.Split(' ');
        Specs.Add(new ArgSpec
        {
            Names = n, Dest = n[0].TrimStart('-').Replace('-', '_'), Flag = flag, Append = append, Required = required,
            Default = dflt, Choices = choices, Help = help, IsInt = isInt,
        });
        return this;
    }

    public SubCommand Pos(string name, string help = "", bool optional = false)
    {
        Specs.Add(new ArgSpec { Names = new[] { name }, Dest = name, Positional = true, Optional = optional, Help = help });
        return this;
    }

    public string Usage()
    {
        var parts = new List<string> { $"usage: imw {Name} [-h]" };
        foreach (var s in Specs)
        {
            if (s.Positional) parts.Add(s.Optional ? $"[{s.Dest}]" : s.Dest);
            else
            {
                var meta = s.Flag ? "" : " " + (s.Choices != null ? "{" + string.Join(",", s.Choices) + "}" : s.Dest.ToUpperInvariant());
                parts.Add(s.Required ? $"{s.Names[0]}{meta}" : $"[{s.Names[0]}{meta}]");
            }
        }
        return string.Join(" ", parts);
    }

    public string HelpText()
    {
        var lines = new List<string> { Usage(), "", Help, "" };
        var pos = Specs.Where(s => s.Positional).ToList();
        if (pos.Count > 0)
        {
            lines.Add("positional arguments:");
            foreach (var s in pos) lines.Add($"  {s.Dest,-28} {s.Help}");
            lines.Add("");
        }
        lines.Add("options:");
        lines.Add($"  {"-h, --help",-28} show this help message and exit");
        foreach (var s in Specs.Where(s => !s.Positional))
        {
            var meta = s.Flag ? "" : " " + (s.Choices != null ? "{" + string.Join(",", s.Choices) + "}" : s.Dest.ToUpperInvariant());
            var names = string.Join(", ", s.Names.Reverse().Select(n => n + meta));
            lines.Add(names.Length > 28 ? $"  {names}\n  {"",-28} {s.Help}" : $"  {names,-28} {s.Help}");
        }
        return string.Join("\n", lines);
    }

    public Args Parse(IList<string> argv)
    {
        var a = new Args { Command = Name };
        foreach (var s in Specs)
        {
            if (s.Flag) a.Values[s.Dest] = false;
            else if (s.IsInt) a.Values[s.Dest] = int.Parse(s.Default ?? "0");
            else a.Values[s.Dest] = s.Default;
        }
        var positionals = Specs.Where(s => s.Positional).ToList();
        int pi = 0;
        for (int i = 0; i < argv.Count; i++)
        {
            var tok = argv[i];
            if (tok is "-h" or "--help")
            {
                Console.WriteLine(HelpText());
                throw new ExitException(0);
            }
            if (tok.StartsWith('-') && tok.Length > 1 && !double.TryParse(tok, out _))
            {
                string name = tok, value = null;
                int eq = tok.IndexOf('=');
                if (tok.StartsWith("--") && eq > 0) { name = tok.Substring(0, eq); value = tok.Substring(eq + 1); }
                else if (!tok.StartsWith("--") && tok.Length > 2) { name = tok.Substring(0, 2); value = tok.Substring(2); }
                var matches = Specs.Where(s => !s.Positional && s.Names.Contains(name)).ToList();
                if (matches.Count == 0 && name.StartsWith("--"))
                    matches = Specs.Where(s => !s.Positional && s.Names.Any(n => n.StartsWith("--") && n.StartsWith(name))).ToList();
                if (matches.Count != 1)
                    throw new UsageError(matches.Count == 0 ? $"unrecognized arguments: {tok}"
                        : $"ambiguous option: {name} could match {string.Join(", ", matches.Select(m => m.Names[0]))}");
                var spec = matches[0];
                if (spec.Flag)
                {
                    if (value != null) throw new UsageError($"argument {string.Join("/", spec.Names)}: ignored explicit argument '{value}'");
                    a.Values[spec.Dest] = true;
                    continue;
                }
                if (value == null)
                {
                    if (i + 1 >= argv.Count || (argv[i + 1].StartsWith('-') && argv[i + 1].Length > 1))
                        throw new UsageError($"argument {string.Join("/", spec.Names)}: expected one argument");
                    value = argv[++i];
                }
                if (spec.Choices != null && !spec.Choices.Contains(value))
                    throw new UsageError($"argument {string.Join("/", spec.Names)}: invalid choice: '{value}' (choose from " +
                                         string.Join(", ", spec.Choices.Select(c => $"'{c}'")) + ")");
                if (spec.IsInt)
                {
                    if (!int.TryParse(value, out var iv)) throw new UsageError($"argument {string.Join("/", spec.Names)}: invalid int value: '{value}'");
                    a.Values[spec.Dest] = iv;
                }
                else if (spec.Append)
                {
                    if (a.Values[spec.Dest] is not List<string> l) a.Values[spec.Dest] = l = new List<string>();
                    l.Add(value);
                }
                else a.Values[spec.Dest] = value;
                continue;
            }
            if (pi < positionals.Count) a.Values[positionals[pi++].Dest] = tok;
            else throw new UsageError($"unrecognized arguments: {tok}");
        }
        var missing = Specs.Where(s => (s.Required && !s.Positional && a.Values[s.Dest] == null)
                                       || (s.Positional && !s.Optional && a.Values[s.Dest] == null))
                           .Select(s => s.Positional ? s.Dest : string.Join("/", s.Names)).ToList();
        if (missing.Count > 0) throw new UsageError($"the following arguments are required: {string.Join(", ", missing)}");
        return a;
    }
}

public sealed class ExitException : Exception
{
    public readonly int Code;
    public ExitException(int code) { Code = code; }
}

/// <summary>Command line: IMW.exe &lt;command&gt; ... (port of imw/cli.py).</summary>
public static class Cli
{
    public const string SecretsWarning =
        "WARNING: upload/Accounts.csv now holds PLAINTEXT secrets, as do your source exports.\n" +
        "  - Keep them on an encrypted volume on the migration host, nowhere else.\n" +
        "  - Do not open Accounts.csv in Excel (it can alter values), email it or sync it.\n" +
        "  - Upload, check the result, then securely delete the exports and the upload folder.\n" +
        "  - The review/ folder holds no secret values and can be shared with reviewers.";

    /// <summary>'keepass=C:\x.xml' -> ('keepass', path); plain path -> (null, path).</summary>
    public static (string, string) ParseInput(string spec)
    {
        int eq = spec.IndexOf('=');
        if (eq >= 0 && Adapter.All.ContainsKey(Py.Lower(spec.Substring(0, eq)))) return (Py.Lower(spec.Substring(0, eq)), spec.Substring(eq + 1));
        return (null, spec);
    }

    /// <summary>[(adapter name, path, records)] or null after logging an error.</summary>
    public static List<(string Name, string Path, List<SourceRecord> Records)> ReadInputs(List<string> specs, string source, string encoding, JObj cfg)
    {
        var out_ = new List<(string, string, List<SourceRecord>)>();
        foreach (var spec in specs)
        {
            var (name, path) = ParseInput(spec);
            if (!File.Exists(path))
            {
                Log.Error($"input not found: {path}");
                return null;
            }
            Adapter adapter;
            List<SourceRecord> got;
            try
            {
                var which = name ?? source;
                adapter = which != null ? Adapter.Get(which) : Adapter.Detect(path);
                got = adapter.Read(path, cfg, encoding).ToList();
            }
            catch (Exception exc) when (exc is AdapterError or ValueError or IOException or UnauthorizedAccessException)
            {
                Log.Error(exc.Message.StartsWith(path, StringComparison.Ordinal) ? exc.Message : $"{path}: {exc.Message}");
                return null;
            }
            Log.Info($"{path}: {got.Count} records read with the '{adapter.Name}' adapter");
            out_.Add((adapter.Name, path, got));
        }
        return out_;
    }

    public static void PrintSummary(Plan plan, JObj counts = null)
    {
        int ok = plan.Accounts.Count(p => p.Status == "OK"), review = plan.Accounts.Count(p => p.Status == "REVIEW"),
            error = plan.Accounts.Count(p => p.Status == "ERROR");
        int invalid = plan.Safes.Values.Count(s => !s.Valid);
        Console.WriteLine();
        Console.WriteLine($"Records:                 {plan.Accounts.Count}");
        Console.WriteLine($"  OK / REVIEW / ERROR:   {ok} / {review} / {error}");
        Console.WriteLine($"  Migrate=N:             {plan.Accounts.Count(p => p.Migrate == "N")}");
        Console.WriteLine($"Target Safes:            {plan.Safes.Count} ({invalid} with Valid_Safe_Name=FALSE)");
        if (counts != null)
        {
            Console.WriteLine($"Upload files:            {Py.Str(counts["safes"])} Safes, {Py.Str(counts["members"])} members, " +
                              $"{Py.Str(counts["accounts"])} accounts");
            if (Py.Truthy(counts["members_skipped"]))
                Console.WriteLine($"  {Py.Str(counts["members_skipped"])} member rows left out (no role); see SafeMembers_Review.csv");
        }
        if (error > 0) Console.WriteLine($"  {error} ERROR rows are never in the upload files");
    }

    public static string PrepareOutput(string outDir, bool force)
    {
        if (Directory.Exists(outDir) && Directory.EnumerateFileSystemEntries(outDir).Any())
        {
            if (!force)
            {
                Log.Error($"{outDir} is not empty. Use another --output-dir or pass --force to replace it.");
                return null;
            }
            foreach (var sub in new[] { "review", "upload" })
            {
                try { Directory.Delete(Path.Combine(outDir, sub), true); }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
            }
            var manifest = Path.Combine(outDir, "manifest.json");
            if (File.Exists(manifest)) File.Delete(manifest);
        }
        Directory.CreateDirectory(outDir);
        return outDir;
    }

    static Store OpenStore(Args a, bool create = false)
    {
        string protector = null;
        if (create)
        {
            if (a.B("no_secrets")) protector = "none";
            else if (a.B("insecure_plaintext_secrets")) protector = "plain";
            else if (!OperatingSystem.IsWindows())
                throw new StoreError("secrets are protected with Windows DPAPI, which needs Windows. On this " +
                                     "machine use --no-secrets (metadata only), or --insecure-plaintext-secrets " +
                                     "for test data only.");
        }
        return new Store(a.S("db"), create, protector);
    }

    static Permissions LoadPerms(Args a) => a.L("permissions") is { Count: > 0 } p ? new Permissions(p, a.S("encoding")) : null;

    static int Ingest(Args a)
    {
        var cfg = Config.Load(a.S("config"));
        Store store;
        try { store = OpenStore(a, create: true); }
        catch (StoreError exc) { Log.Error(exc.Message); return 2; }
        using var _ = store;
        var loaded = ReadInputs(a.L("input"), a.S("source"), a.S("encoding"), cfg);
        if (loaded == null) return 2;
        Permissions perms;
        try { perms = LoadPerms(a); }
        catch (Exception exc) when (exc is ValueError or IOException or UnauthorizedAccessException)
        {
            Log.Error($"permissions: {exc.Message}");
            return 2;
        }
        try
        {
            foreach (var (name, path, records) in loaded)
            {
                var (n, replaced) = store.Ingest(name, path, records, perms, a.L("permissions"));
                Console.WriteLine($"{path}: {n} records stored ({replaced} replaced earlier copies)");
            }
        }
        catch (Exception exc) when (exc is StoreError or ProtectError)
        {
            Log.Error(exc.Message);
            return 2;
        }
        var mode = store.Meta("protector");
        var how = mode switch
        {
            "dpapi" => "encrypted with Windows DPAPI", "none" => "not stored", "plain" => "PLAINTEXT - test data only",
            _ => throw new KeyError(mode),
        };
        Console.WriteLine($"Database: {Path.GetFullPath(a.S("db"))}  (secrets: {how})");
        if (mode == "dpapi") Console.WriteLine("The export files are no longer needed: securely delete them now.");
        Console.WriteLine("Next: IMW map --db " + a.S("db") + " -c <config.json>");
        return 0;
    }

    static int Map(Args a)
    {
        Plan plan;
        Store store;
        try
        {
            store = OpenStore(a);
            var cfg = a.S("config") != null ? Config.Load(a.S("config"))
                : store.Meta("config") != null ? store.StoredConfig() : Config.Load(null);
            plan = store.Map(cfg, a.S("config") ?? store.Meta("config_path"));
        }
        catch (StoreError exc) { Log.Error(exc.Message); return 2; }
        PrintSummary(plan);
        Console.WriteLine("Results are in the database. Try: IMW query --db " + a.S("db") + " --report summary");
        store.Close();
        return 0;
    }

    static int Set(Args a)
    {
        var values = new OrderedPairs
        {
            { "migrate", a.S("migrate") != null ? a.S("migrate").ToUpperInvariant() : null }, { "target_safe", a.S("safe") },
            { "platform_id", a.S("platform") }, { "account_name", a.S("name") },
        };
        if (a.B("clear"))
        {
            var cleared = new OrderedPairs();
            foreach (var kv in values) cleared[kv.Key] = "";
            values = cleared;
        }
        Plan plan;
        Store store;
        try
        {
            store = OpenStore(a);
            if (a.S("from_review") != null)
            {
                var n = store.ImportReview(a.S("from_review"), a.S("encoding"));
                Console.WriteLine($"Imported changes for {n} records from {a.S("from_review")}");
            }
            else
            {
                if (values.All(kv => kv.Value == null))
                {
                    Log.Error("nothing to set: give --migrate, --safe, --platform, --name or --clear");
                    return 2;
                }
                if (values["migrate"] is not (null or "" or "Y" or "N"))
                {
                    Log.Error("--migrate must be Y or N");
                    return 2;
                }
                var ids = (a.L("record") ?? new List<string>()).ToList();
                if (a.S("where") != null) ids.AddRange(store.SelectIds(a.S("where")));
                if (ids.Count == 0)
                {
                    Log.Error("no records selected: give --record or a --where that matches something");
                    return 2;
                }
                store.SetEdits(ids, values, a.S("reason") ?? "");
                Console.WriteLine($"Updated {ids.Count} records");
            }
            plan = store.Map(store.StoredConfig(), store.Meta("config_path"));
        }
        catch (Exception exc) when (exc is StoreError or ValueError or IOException or UnauthorizedAccessException)
        {
            Log.Error(exc.Message);
            return 2;
        }
        PrintSummary(plan);
        store.Close();
        return 0;
    }

    static int Query(Args a)
    {
        if (a.S("report") == "list" || (a.S("sql") == null && a.S("report") == null))
        {
            foreach (var (name, sql) in Store.Reports) Console.WriteLine($"{name,-14} {sql}");
            Console.WriteLine("\nTables: inputs, records, grants, edits, plan_accounts (view: accounts), plan_safes, " +
                              "plan_members, audit. records.secret_enc always reads as NULL.");
            return 0;
        }
        var sqlText = a.S("report") != null ? Store.Reports[a.S("report")] : a.S("sql");
        if (sqlText == null)
        {
            Log.Error($"unknown report '{a.S("report")}'; use --report list");
            return 2;
        }
        List<string> cols;
        List<object[]> rows;
        try
        {
            using var store = OpenStore(a);
            (cols, rows) = store.Query(sqlText);
        }
        catch (StoreError exc) { Log.Error(exc.Message); return 2; }
        if (a.S("csv") != null)
        {
            using (var fh = Csv.OpenWrite(a.S("csv")))
            {
                var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
                w.WriteRow(cols);
                foreach (var r in rows) w.WriteRow(r);
            }
            Console.WriteLine($"Wrote {rows.Count} rows to {a.S("csv")}");
        }
        else Store.PrintTable(cols, rows);
        return 0;
    }

    static int Extract(Args a)
    {
        var outDir = PrepareOutput(a.S("output_dir"), a.B("force"));
        if (outDir == null) return 2;
        Plan plan;
        JObj counts;
        try
        {
            using var store = OpenStore(a);
            (plan, counts, _) = Store.RunExtract(store, outDir, a.S("where"), a.B("include_secrets"));
        }
        catch (StoreError exc) { Log.Error(exc.Message); return 2; }
        PrintSummary(plan, counts);
        Console.WriteLine($"Output: {Path.GetFullPath(outDir)}");
        Console.WriteLine();
        Console.WriteLine(a.B("include_secrets") ? SecretsWarning
            : "Accounts.csv has an empty 'secret' column. Add --include-secrets for the upload-ready version.");
        return 0;
    }

    static int Sources(Args a)
    {
        foreach (var (name, make) in Adapter.All) Console.WriteLine($"{name,-10} {make().Description}");
        return 0;
    }

    static int InitConfig(Args a)
    {
        Config.WriteDefault(a.S("path"));
        Console.WriteLine($"Wrote starter config to {a.S("path")}");
        return 0;
    }

    static int Convert(Args a)
    {
        var cfg = Config.Load(a.S("config"));
        var outDir = PrepareOutput(a.S("output_dir"), a.B("force"));
        if (outDir == null) return 2;
        var loaded = ReadInputs(a.L("input"), a.S("source"), a.S("encoding"), cfg);
        if (loaded == null) return 2;
        var records = loaded.SelectMany(l => l.Records).ToList();
        var inputs = loaded.Select(l => (object)(l.Name, l.Path)).ToList();
        int cleaned = records.Count(r => Transform.SanitizeRecord(r).Count > 0);
        if (cleaned > 0) Log.Warning($"{cleaned} records had control or invisible characters removed (see their Notes)");
        if (records.Count == 0)
        {
            Log.Error("No records found. Check --source and the column names (field_aliases).");
            return 1;
        }
        Permissions perms;
        Dictionary<string, Dictionary<string, string>> overrides;
        try
        {
            perms = LoadPerms(a);
            overrides = a.S("overrides") != null ? Transform.LoadOverrides(a.S("overrides"), a.S("encoding")) : null;
        }
        catch (Exception exc) when (exc is ValueError or IOException or UnauthorizedAccessException)
        {
            Log.Error(exc.Message);
            return 2;
        }
        var plan = Transform.BuildPlan(records, cfg, perms, overrides);
        var files = Writers.WriteReview(plan, outDir);
        files.Add(Writers.WriteConvention(plan, cfg, outDir));
        var (uploadFiles, counts) = Writers.WriteUpload(plan, cfg, outDir, a.B("include_secrets"));
        files.AddRange(uploadFiles);
        counts["records"] = (long)plan.Accounts.Count;
        var manifest = Writers.WriteManifest(outDir, inputs, files, counts, a.B("include_secrets"), a.S("config"));
        PrintSummary(plan, counts);
        Console.WriteLine($"Output: {Path.GetFullPath(outDir)}  (manifest: {Path.GetFileName(manifest)})");
        Console.WriteLine();
        Console.WriteLine(a.B("include_secrets") ? SecretsWarning
            : "Accounts.csv has an empty 'secret' column (dry run). Review the files, then run " +
              "again with --include-secrets to produce the upload-ready version.");
        return 0;
    }

    public static Func<Args, int> UiCommand = Ui.UiServer.Command;

    static List<SubCommand> Commands()
    {
        var sources = Adapter.Names.OrderBy(n => n, StringComparer.Ordinal).ToArray();
        const string inputHelp = "Export file. Repeat for several files. Prefix with the source to skip " +
                                 "auto-detection, e.g. keepass=vault.xml or table=accounts.xlsx";
        const string permHelp = "Permissions CSV: groups per folder or record. Repeat to merge several files";
        SubCommand AddInputs(SubCommand c) => c
            .Opt("--input -i", inputHelp, append: true, required: true)
            .Opt("--source", "Source for every --input without a prefix", choices: sources)
            .Opt("--permissions -p", permHelp, append: true)
            .Opt("--encoding", "Text encoding of CSV inputs (try cp1252)", dflt: "utf-8-sig");
        SubCommand AddDb(SubCommand c) => c.Opt("--db -d", "Local staging database file, e.g. migration.db", required: true);

        return new List<SubCommand>
        {
            new() { Name = "sources", Help = "List the supported source formats", Run = Sources },
            new SubCommand { Name = "init-config", Help = "Write a starter config file", Run = InitConfig }.Pos("path"),
            new SubCommand { Name = "convert", Help = "Convert one or more exports", Run = Convert }
                .Opt("--input -i", inputHelp, append: true, required: true)
                .Opt("--source", "Source for every --input without a prefix", choices: sources)
                .Opt("--config -c", "Config JSON (see init-config)")
                .Opt("--permissions -p", permHelp, append: true)
                .Opt("--overrides", "An edited review/Accounts_Review.csv; changed Migrate, Target_Safe, Platform_ID and Account_Name values win")
                .Opt("--output-dir -o", dflt: "imw_output")
                .Opt("--include-secrets", "Write secret values into upload/Accounts.csv (default: left empty)", flag: true)
                .Opt("--force", "Replace an existing output folder", flag: true)
                .Opt("--encoding", "Text encoding of CSV inputs (try cp1252)", dflt: "utf-8-sig"),
            AddInputs(AddDb(new SubCommand { Name = "ingest", Help = "Load exports into the local database (secrets encrypted)", Run = Ingest }))
                .Opt("--config -c", "Config JSON (only source-reading options are used here)")
                .Opt("--no-secrets", "New database only: store metadata, no secrets", flag: true)
                .Opt("--insecure-plaintext-secrets", "New database only: store secrets UNENCRYPTED (test data on non-Windows only)", flag: true),
            AddDb(new SubCommand { Name = "map", Help = "Apply the config rules to everything in the database", Run = Map })
                .Opt("--config -c", "Config JSON (default: the one used by the last map)"),
            AddDb(new SubCommand { Name = "set", Help = "Record changes: Migrate, Safe, platform or account name", Run = Set })
                .Opt("--record -r", "Record_ID to change (repeatable)", append: true)
                .Opt("--where -w", "SQL condition on the accounts view, e.g. \"target_safe = 'X'\"")
                .Opt("--migrate", choices: new[] { "Y", "N", "y", "n" })
                .Opt("--safe", "Target Safe (cleaned to the Safe name rules)")
                .Opt("--platform", "Platform ID")
                .Opt("--name", "Account name")
                .Opt("--clear", "Remove earlier changes for these records", flag: true)
                .Opt("--reason", "Why; kept in the edits table and audit log")
                .Opt("--from-review", "Import changed values from an edited Accounts_Review.csv")
                .Opt("--encoding", dflt: "utf-8-sig"),
            AddDb(new SubCommand { Name = "query", Help = "Read-only SQL or a built-in report", Run = Query })
                .Pos("sql", "SELECT statement", optional: true)
                .Opt("--report", "Built-in report name; 'list' shows them")
                .Opt("--csv", "Write the result to this CSV file instead of the screen"),
            AddDb(new SubCommand { Name = "extract", Help = "Write review and upload CSVs from the database", Run = Extract })
                .Opt("--output-dir -o", required: true)
                .Opt("--where -w", "Only upload accounts matching this SQL condition (a wave)")
                .Opt("--include-secrets", "Decrypt secrets into upload/Accounts.csv (default: left empty)", flag: true)
                .Opt("--force", "Replace an existing output folder", flag: true),
            new SubCommand { Name = "ui", Help = "Start the Idira Migration Workbench (local web UI over HTTPS)", Run = a => UiCommand(a) }
                .Opt("--workspace -w", "Folder for the database, config, inbox and outputs (default: imw_workspace)", dflt: "imw_workspace")
                .Opt("--port", "Port on 127.0.0.1 (default: any free port)", isInt: true, dflt: "0")
                .Opt("--no-browser", "Print the link instead of opening a browser", flag: true)
                .Opt("--no-secrets", "New database only: metadata, no secrets", flag: true)
                .Opt("--insecure-plaintext-secrets", "New database only: secrets UNENCRYPTED (test data on non-Windows only)", flag: true)
                .Opt("--trust-cert", "Windows: trust the Workbench's self-signed HTTPS certificate for your user " +
                                     "(Windows asks you to confirm), so the browser stops warning", flag: true)
                .Opt("--new-cert", "Make a new HTTPS certificate and key", flag: true)
                .Opt("--no-tls", "Plain HTTP instead of HTTPS (troubleshooting only)", flag: true),
        };
    }

    const string Description = "Convert PAM exports into Privilege Cloud API-ready CSV files. Offline: makes no network connections.";

    public static int Run(string[] argv)
    {
        var commands = Commands();
        string Usage() => "usage: imw [-h] [--version] [-v] {" + string.Join(",", commands.Select(c => c.Name)) + "} ...";
        int i = 0;
        bool verbose = false;
        while (i < argv.Length && argv[i].StartsWith('-'))
        {
            switch (argv[i])
            {
                case "-h" or "--help":
                    Console.WriteLine(Usage() + "\n\n" + Description + "\n\npositional arguments:");
                    foreach (var c in commands) Console.WriteLine($"    {c.Name,-12} {c.Help}");
                    Console.WriteLine("\noptions:\n  -h, --help     show this help message and exit\n" +
                                      "  --version      show program's version number and exit\n  -v, --verbose");
                    return 0;
                case "--version":
                    Console.WriteLine($"Idira Migration Workbench (imw) {Writers.Version}");
                    return 0;
                case "-v" or "--verbose":
                    verbose = true;
                    break;
                default:
                    Console.Error.WriteLine(Usage());
                    Console.Error.WriteLine($"imw: error: unrecognized arguments: {argv[i]}");
                    return 2;
            }
            i++;
        }
        if (i >= argv.Length)
        {
            Console.Error.WriteLine(Usage());
            Console.Error.WriteLine("imw: error: the following arguments are required: command");
            return 2;
        }
        var cmd = commands.FirstOrDefault(c => c.Name == argv[i]);
        if (cmd == null)
        {
            Console.Error.WriteLine(Usage());
            Console.Error.WriteLine($"imw: error: argument command: invalid choice: '{argv[i]}' (choose from " +
                                    string.Join(", ", commands.Select(c => $"'{c.Name}'")) + ")");
            return 2;
        }
        Args args;
        try
        {
            args = cmd.Parse(argv.Skip(i + 1).ToList());
            if (args.Values.TryGetValue("verbose", out var v) && v is true) verbose = true;
        }
        catch (ExitException exc) { return exc.Code; }
        catch (UsageError exc)
        {
            Console.Error.WriteLine(cmd.Usage());
            Console.Error.WriteLine($"imw {cmd.Name}: error: {exc.Message}");
            return 2;
        }
        Log.Verbose = verbose;
        try { return cmd.Run(args); }
        catch (Exception exc) when (exc is ValueError or IOException or UnauthorizedAccessException or OwnerError or StoreError or ProtectError)
        {
            Log.Error(exc.Message);
            return 1;
        }
    }
}
