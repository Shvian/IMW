using System.Text.RegularExpressions;

namespace Imw.Core;

/// <summary>
/// Safe naming convention: build short, layered Safe names from abbreviations (port of imw/naming.py).
///
/// Follows the usual CyberArk convention layers, most important first:
///   Environment (P/D/T/Q) - Location - Business unit/Application - Technology (SVR, DB,
///   NET, DOM...) - Flavor (WIN, LNX, SQL, ORC, CSC...) - Account type (LA, DA, LS, DS, RT, EN, SA)
///
/// Existing structure comes first: when a record has folders, safe_convention.template
/// (default "{folder}") names the Safe after its folder levels, in order, each level abbreviated.
/// Only records with no folders use template_no_folders (default "{env}-{tech}-{flavor}-{acct}").
/// </summary>
public static class Naming
{
    public const string WordSplit = @"[\s\-_/\\:;,.()\[\]{}""'&+]+";
    public static readonly HashSet<string> Vowels = new() { "A", "E", "I", "O", "U" };

    static OrderedPairs P(params string[] kv)
    {
        var o = new OrderedPairs();
        for (int i = 0; i < kv.Length; i += 2) o.Add(kv[i], kv[i + 1]);
        return o;
    }

    public static readonly OrderedPairs DefaultAbbreviations = P(
        // Environment (category 1)
        "production", "P", "prod", "P", "prd", "P", "development", "D", "dev", "D",
        "test", "T", "testing", "T", "tst", "T", "qa", "Q", "uat", "Q", "quality assurance", "Q",
        "staging", "S", "stage", "S", "dr", "DR", "disaster recovery", "DR", "sandbox", "SBX", "lab", "LAB",
        // Location (category 2)
        "datacenter", "DC", "data center", "DC", "east", "E", "west", "W", "north", "N", "south", "S",
        "europe", "EU", "united states", "US", "boston", "BOS", "new york", "NYC", "california", "CA",
        // Business unit / application (category 3)
        "security", "SEC", "engineering", "ENG", "support", "SUP", "support desk", "SUP", "helpdesk", "SUP",
        "finance", "FIN", "human resources", "HR", "payments", "PAY", "payroll", "PAY", "storefront", "SF",
        "marketing", "MKT", "sales", "SLS", "operations", "OPS", "ops", "OPS", "self service", "SS",
        "vendor", "VND", "vendors", "VND", "portal", "PRT", "portals", "PRT", "reporting", "RPT",
        "replica", "RPL", "replicas", "RPL", "batch", "BAT", "jobs", "JOB", "nightly", "NGT", "weekly", "WKL",
        "deploy", "DPL", "deployment", "DPL", "keys", "KEY", "key", "KEY", "legacy", "LGC", "break glass", "BG",
        "subscriptions", "SUB", "accounts", "ACC", "tier", "TR", "edge", "EDG", "proxy", "PRX",
        // Technology (category 4)
        "server", "SVR", "servers", "SVR", "member servers", "SVR", "workstation", "WKS", "workstations", "WKS",
        "network", "NET", "network devices", "NET", "database", "DB", "databases", "DB", "mainframe", "MF",
        "domain", "DOM", "domain controllers", "DC", "infrastructure", "INF", "applications", "APP",
        "application", "APP", "web", "WEB", "cloud", "CLD", "firewall", "FW", "firewalls", "FW",
        "switch", "SW", "switches", "SW", "core switches", "CSW", "router", "RTR", "routers", "RTR",
        "wireless", "WLS", "storage", "STG", "backup", "BKP", "middleware", "MW",
        // Flavor (category 5)
        "windows", "WIN", "unix", "UNX", "linux", "LNX", "hp-ux", "HP", "hpux", "HP", "aix", "AIX",
        "solaris", "SOL", "cisco", "CSC", "juniper", "JNP", "palo alto", "PAN", "sql", "SQL",
        "sql server", "SQL", "mssql", "SQL", "oracle", "ORC", "mysql", "MYS", "postgres", "PG",
        "postgresql", "PG", "db2", "DB2", "azure", "AZ", "aws", "AWS", "gcp", "GCP", "vmware", "VMW",
        "esxi", "ESX", "active directory", "AD",
        // Account type (category 6)
        "local", "LA", "service", "SVC", "service accounts", "SVC", "admin", "ADM", "admins", "ADM",
        "administrators", "ADM", "root", "RT");

    /// <summary>Word parts recognised inside compound folder names (Storefront -> Store+front -> SF).</summary>
    public static readonly HashSet<string> CompoundParts = new(StringComparer.Ordinal)
    {
        "store", "front", "back", "end", "pay", "roll", "net", "work", "share", "point", "data", "base",
        "web", "mail", "time", "sheet", "book", "desk", "help", "cash", "gate", "way", "key", "vault",
        "fire", "wall", "out", "look", "box", "drop", "cloud", "hub", "line", "sales", "force", "power",
        "shell", "file", "ware", "soft", "user", "check", "card", "bank", "pass", "word", "site", "core",
        "edge", "home", "page", "app", "apps", "ops", "dev", "sec", "log", "logs", "stream", "flow",
        "market", "place", "self", "service", "client", "server", "admin", "main", "frame",
    };

    public static readonly HashSet<string> Stopwords = new(StringComparer.Ordinal)
        { "and", "of", "the", "for", "a", "an", "to", "in", "on", "at", "with" };

    /// <summary>Platform ID -> technology / flavor / default account type (categories 4-6).</summary>
    public static readonly List<(string Platform, string Tech, string Flavor, string Acct)> DefaultPlatformCodes = new()
    {
        ("WinDomain", "DOM", "WIN", "DA"),
        ("WinServerLocal", "SVR", "WIN", "LA"),
        ("WinDesktopLocal", "WKS", "WIN", "LA"),
        ("WinService", "SVR", "WIN", "LS"),
        ("UnixSSH", "SVR", "UNX", "LA"),
        ("UnixSSHKeys", "SVR", "UNX", "LA"),
        ("MSSql", "DB", "SQL", "LA"),
        ("Oracle", "DB", "ORC", "LA"),
        ("MySQL", "DB", "MYS", "LA"),
        ("PostgreSQL", "DB", "PGS", "LA"),
        ("CiscoSSH", "NET", "CSC", "LA"),
        ("CiscoEnable", "NET", "CSC", "EN"),
        ("PaloAltoNetworks", "NET", "PAN", "LA"),
        ("VMwareESX", "VRT", "ESX", "LA"),
        ("GenericWebApp", "WEB", "", "LA"),
        ("AzureWebAccount", "CLD", "AZ", "LA"),
        ("AWSAccessKeys", "CLD", "AWS", "LA"),
    };

    /// <summary>DEFAULT_PLATFORM_CODES as the JSON the UI gets.</summary>
    public static JObj PlatformCodesJson()
    {
        var o = new JObj();
        foreach (var (p, t, f, a) in DefaultPlatformCodes) o[p] = Json.O(("tech", t), ("flavor", f), ("acct", a));
        return o;
    }

    public static readonly OrderedPairs LayerFields = P(
        "folder_word", "a word or phrase in any folder level",
        "folder_level", "any whole folder level",
        "folder", "the whole folder path",
        "platform", "the platform ID",
        "username", "the username",
        "address", "the address",
        "address_domain", "the address's domain (srv01.boston.corp.example.com -> boston.corp.example.com)",
        "name", "the account name",
        "type", "the record type / template",
        "source", "the source (delinea, keepass, table)",
        "env", "the {env} code", "tech", "the {tech} code", "flavor", "the {flavor} code", "acct", "the {acct} code");

    public static readonly string[] BuiltinLayers = { "env", "tech", "flavor", "acct" };

    public static readonly HashSet<string> EnvWords = new(StringComparer.Ordinal)
    {
        "production", "prod", "prd", "development", "dev", "test", "testing", "tst", "qa", "uat",
        "quality assurance", "staging", "stage",
    };

    static JObj Rule(string field, string pattern, string code, string field2 = "", string pattern2 = "")
    {
        var r = Json.O(("field", field), ("pattern", pattern), ("code", code));
        if (field2.Length > 0) { r["field2"] = field2; r["pattern2"] = pattern2; }
        return r;
    }

    static List<object> ByPlatform(string key)
    {
        var groups = new List<(string Code, List<string> Platforms)>();
        foreach (var pc in DefaultPlatformCodes)
        {
            var code = key == "tech" ? pc.Tech : key == "flavor" ? pc.Flavor : pc.Acct;
            var g = groups.FindIndex(x => x.Code == code);
            if (g < 0) groups.Add((code, new List<string> { pc.Platform }));
            else groups[g].Platforms.Add(pc.Platform);
        }
        return groups.Where(g => g.Code.Length > 0)
                     .Select(g => (object)Rule("platform", "^(" + string.Join("|", g.Platforms) + ")$", g.Code)).ToList();
    }

    /// <summary>The built-in placeholder layers (editable copies go into safe_convention.layers).</summary>
    public static JObj DefaultLayers()
    {
        const string unix = "^(UNX|LNX|HP|AIX|SOL)$";
        const string svc = "^(svc|srv|service)[_.-]";
        var acct = new List<object>
        {
            Rule("username", "^root$", "RT", "flavor", unix),
            Rule("username", "^sa$", "SA", "tech", "^DB$"),
            Rule("username", "^enable$", "EN", "tech", "^NET$"),
            Rule("username", svc, "DS", "tech", "^DOM$"),
            Rule("username", svc, "LS"),
        };
        acct.AddRange(ByPlatform("acct"));
        return Json.O(
            ("env", Json.O(("label", "Environment"), ("default", ""), ("rules", new List<object>
            {
                Rule("folder_word", "^(production|prod|prd)$", "P"),
                Rule("folder_word", "^(development|dev)$", "D"),
                Rule("folder_word", "^(test|testing|tst)$", "T"),
                Rule("folder_word", "^(qa|uat|quality assurance)$", "Q"),
                Rule("folder_word", "^(staging|stage)$", "S"),
            }))),
            ("tech", Json.O(("label", "Technology"), ("default", ""), ("rules", ByPlatform("tech")))),
            ("flavor", Json.O(("label", "Flavor"), ("default", ""), ("rules", ByPlatform("flavor")))),
            ("acct", Json.O(("label", "Account type"), ("default", ""), ("rules", acct))));
    }

    const string IpAddress = @"^\d{1,3}(\.\d{1,3}){3}$|:";

    /// <summary>'srv01.boston.corp.example.com' -> 'boston.corp.example.com'; '' for a short name or an IP.</summary>
    public static string AddressDomain(string address)
    {
        var host = Py.RStrip(Py.Lower(Py.Strip(address ?? "")), ".");
        if (host.Length == 0 || PyRe.Search(IpAddress, host) != null || !host.Contains('.')) return "";
        return host.Substring(host.IndexOf('.') + 1);
    }

    /// <summary>Folder name or phrase -> lookup key ("Batch: Nightly/Weekly" -> "batch nightly weekly").</summary>
    public static string Norm(string text) =>
        string.Join(" ", PyRe.Split(WordSplit, Py.Lower(text ?? "")).Where(w => w.Length > 0));

    /// <summary>The code points of a string, each as a string (Python iteration over str).</summary>
    public static List<string> CodePoints(string s)
    {
        var out_ = new List<string>();
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { out_.Add(s.Substring(i, 2)); i++; }
            else out_.Add(s[i].ToString());
        }
        return out_;
    }
}

/// <summary>An insertion-ordered string -> string table (a Python dict of strings).</summary>
public sealed class OrderedPairs : IEnumerable<KeyValuePair<string, string>>
{
    readonly List<string> _keys = new();
    readonly Dictionary<string, string> _map = new(StringComparer.Ordinal);

    public void Add(string k, string v) => this[k] = v;

    public string this[string k]
    {
        get => _map.TryGetValue(k, out var v) ? v : null;
        set { if (!_map.ContainsKey(k)) _keys.Add(k); _map[k] = value; }
    }

    public bool ContainsKey(string k) => _map.ContainsKey(k);
    public bool TryGetValue(string k, out string v) => _map.TryGetValue(k, out v);
    public int Count => _keys.Count;
    public IReadOnlyList<string> Keys => _keys;

    public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
    {
        foreach (var k in _keys) yield return new(k, _map[k]);
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>One part of a Safe name being assembled: its kind and its levels of codes.</summary>
public sealed class NamePart
{
    public string Kind;
    public List<List<string>> Levels;
    public NamePart(string kind, List<List<string>> levels) { Kind = kind; Levels = levels; }
}

/// <summary>The codes worked out for one record.</summary>
public sealed class LayerCodes
{
    public readonly OrderedPairs Codes = new();
    public List<List<string>> Folder = new();
    public List<string> Type = new();
}

public sealed class Namer
{
    readonly JObj _conv;
    public readonly string Template, TemplateFlat, Sep;
    public readonly int MaxLen;
    readonly OrderedPairs _abbr = new();
    readonly OrderedPairs _userAbbr = new();
    readonly HashSet<string> _skipLevels = new(StringComparer.Ordinal);
    readonly string _defaultEnv;
    readonly int _maxPhrase;
    readonly List<(string Name, List<(List<(string Field, Regex Rx)> Conds, string Code)> Rules, string Default)> _layerDefs;

    /// <summary>Words that had no abbreviation and got an automatic code (word -> code).</summary>
    public readonly OrderedPairs Unknown = new();

    // Set by the rules code while it names one account's Safe.
    public List<string> LastNotes = new();
    public bool Used;

    public Namer(JObj cfg)
    {
        var conv = cfg.Obj("safe_convention") ?? new JObj();
        _conv = conv;
        Template = Py.Truthy(conv.Get("template")) ? Py.Str(conv.Get("template")) : "{folder}";
        TemplateFlat = Py.Truthy(conv.Get("template_no_folders")) ? Py.Str(conv.Get("template_no_folders")) : "{env}-{tech}-{flavor}-{acct}";
        Sep = conv.ContainsKey("separator") ? (conv.Get("separator") as string ?? "") : "-";
        MaxLen = (int)(Py.ToLong(cfg.Obj("safe_name")["max_length"]) ?? 28);
        foreach (var kv in Naming.DefaultAbbreviations) _abbr[Naming.Norm(kv.Key)] = kv.Value;
        if (conv.Get("abbreviations") is JObj ua)
            foreach (var kv in ua) _userAbbr[Naming.Norm(kv.Key)] = Py.Strip(Py.Str(kv.Value));
        foreach (var kv in _userAbbr) _abbr[kv.Key] = kv.Value;
        if (conv.Get("skip_folder_levels") is List<object> skips)
            foreach (var s in skips) _skipLevels.Add(Naming.Norm(Py.Str(s)));
        _defaultEnv = conv.Get("default_environment", "") as string ?? "";
        _maxPhrase = _abbr.Keys.Max(k => Py.SplitWs(k).Count);
        _layerDefs = LayerDefs(conv);
    }

    public bool IsUserAbbreviation(string normed) => _userAbbr.ContainsKey(normed);
    public bool HasAbbreviation(string normed) => _abbr.ContainsKey(normed);

    List<(string, List<(List<(string, Regex)>, string)>, string)> LayerDefs(JObj conv)
    {
        var src = conv.Get("layers") is JObj lj && lj.Count > 0 ? lj : Naming.DefaultLayers();
        var layers = new JObj();
        foreach (var kv in src) layers[kv.Key] = kv.Value is JObj o ? o.Copy() : new JObj();
        foreach (var kv in Naming.DefaultLayers()) layers.SetDefault(kv.Key, kv.Value);
        // Older settings: extra platform codes and environment words still count.
        if (conv.Get("platform_codes") is JObj pcs)
        {
            foreach (var pkv in pcs)
            {
                if (pkv.Value is not JObj codes) continue;
                foreach (var key in new[] { "tech", "flavor", "acct" })
                {
                    if (codes.Get(key) == null) continue;
                    var rule = new JObj { ["field"] = "platform", ["pattern"] = "^" + PyRe.Escape(pkv.Key) + "$", ["code"] = codes[key] };
                    var layer = (JObj)layers[key];
                    var rules = new List<object>(layer.List("rules") ?? new List<object>());
                    int at = 0;
                    if (key == "acct")
                    {
                        at = rules.FindIndex(r => r is JObj ro && Py.Eq(ro.Get("field"), "platform"));
                        if (at < 0) at = rules.Count;
                    }
                    rules.Insert(at, rule);
                    layer["rules"] = rules;
                }
            }
        }
        var words = (conv.Get("environment_words") as List<object> ?? new List<object>()).Where(Py.Truthy).Select(Py.Str).ToList();
        if (words.Count > 0)
        {
            var env = (JObj)layers["env"];
            var rules = new List<object>(env.List("rules") ?? new List<object>());
            foreach (var w in words)
            {
                var code = _abbr[Naming.Norm(w)];
                if (string.IsNullOrEmpty(code)) code = Py.Head(Auto(w), 1);
                rules.Add(new JObj { ["field"] = "folder_word", ["pattern"] = "^" + PyRe.Escape(Py.Lower(w)) + "$", ["code"] = code });
            }
            env["rules"] = rules;
        }
        var compiled = new List<(string, List<(List<(string, Regex)>, string)>, string)>();
        foreach (var kv in layers)
        {
            var layer = kv.Value as JObj ?? new JObj();
            var rules = new List<(List<(string, Regex)>, string)>();
            foreach (var ro in layer.List("rules") ?? new List<object>())
            {
                if (ro is not JObj r) continue;
                var conds = new List<(string, Regex)>();
                foreach (var (f, p) in new[] { (r.Get("field"), r.Get("pattern")), (r.Get("field2"), r.Get("pattern2")) })
                    if (Py.Truthy(f)) conds.Add((Py.Str(f), PyRe.Compile(Py.Truthy(p) ? Py.Str(p) : "", ignoreCase: true)));
                if (conds.Count > 0) rules.Add((conds, Py.Strip(Py.Truthy(r.Get("code")) ? Py.Str(r.Get("code")) : "")));
            }
            var dflt = Py.Strip(Py.Truthy(layer.Get("default")) ? Py.Str(layer.Get("default")) : "");
            if (kv.Key == "env" && dflt.Length == 0) dflt = _defaultEnv;
            compiled.Add((kv.Key, rules, dflt));
        }
        return compiled;
    }

    List<string> Field(string field, SourceRecord rec, string platform, List<(string Src, string Code)> units, OrderedPairs codes)
    {
        switch (field)
        {
            case "folder_word": return units.Select(u => u.Src).ToList();
            case "folder_level": return Levels(rec);
            case "folder": return new() { rec.Folder.Count > 0 ? "\\" + string.Join("\\", rec.Folder) : "" };
            case "platform": return new() { platform ?? "" };
            case "address_domain": return new() { Naming.AddressDomain(rec.Address) };
        }
        if (codes.ContainsKey(field)) return new() { codes[field] };
        if (field.StartsWith("column:", StringComparison.Ordinal))
        {
            var want = Py.Lower(Py.Strip(field.Substring(7)));
            var vals = rec.Extra.Where(kv => Py.Lower(kv.Key) == want).Select(kv => kv.Value ?? "None").ToList();
            return vals.Count > 0 ? vals : new() { "" };
        }
        return new() { Attr(rec, field) };
    }

    /// <summary>str(getattr(rec, field, "") or "")</summary>
    static string Attr(SourceRecord rec, string field) => field switch
    {
        "source" => rec.Source ?? "",
        "source_file" => rec.SourceFile ?? "",
        "source_id" => rec.SourceId ?? "",
        "source_ref" => rec.SourceRef ?? "",
        "name" => rec.Name ?? "",
        "type" => rec.Type ?? "",
        "address" => rec.Address ?? "",
        "username" => rec.Username ?? "",
        "secret" => rec.Secret ?? "",
        "secret_type" => rec.SecretType ?? "",
        "has_secret" => rec.HasSecret == true ? "True" : "",
        "access_source" => rec.AccessSource ?? "",
        "target_safe" => rec.TargetSafe ?? "",
        "target_platform" => rec.TargetPlatform ?? "",
        "record_id" => rec.RecordId,
        "folder_path" => rec.FolderPath,
        "notes" => rec.Notes.Count > 0 ? Py.Repr(rec.Notes) : "",
        _ => "",
    };

    /// <summary>(code, matched folder units) for one layer.</summary>
    (string, List<string>) LayerValue(string name, SourceRecord rec, string platform, List<(string, string)> units, OrderedPairs codes)
    {
        var def = _layerDefs.FirstOrDefault(d => d.Name == name);
        if (def.Name == null) return ("", new List<string>());
        foreach (var (conds, code) in def.Rules)
        {
            var hits = new List<string>();
            bool all = true;
            foreach (var (field, rx) in conds)
            {
                var vals = Field(field, rec, platform, units, codes).Where(v => rx.IsMatch(v)).ToList();
                if (vals.Count == 0) { all = false; break; }
                if (field == "folder_word") hits.AddRange(vals);
            }
            if (all) return (code, hits);
        }
        return (def.Default, new List<string>());
    }

    // -- words ----------------------------------------------------------------

    /// <summary>Automatic code for a word missing from the dictionary.</summary>
    public string Auto(string word)
    {
        var w = Py.Upper(word);
        if (Py.Len(w) <= 4 || Py.IsDigit(w) || (Py.IsAlnum(w) && Py.IsUpper(word))) return Py.Head(w, 4);
        // CamelCase (SharePoint -> SP, HRApp -> HRA) or a known compound (Storefront -> SF).
        var parts = PyRe.FindAll(@"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", word);
        if (parts.Count == 1)
        {
            var low = Py.Lower(word);
            var known = new HashSet<string>(Naming.CompoundParts, StringComparer.Ordinal);
            foreach (var k in _abbr.Keys) if (!k.Contains(' ') && Py.Len(k) >= 3) known.Add(k);
            int n = Py.Len(low);
            for (int i = 3; i < n - 2; i++)
            {
                if (known.Contains(Py.Head(low, i)) && known.Contains(Py.Tail(low, i)))
                {
                    parts = new List<string> { Py.Head(low, i), Py.Tail(low, i) };
                    break;
                }
            }
        }
        if (parts.Count > 1 && parts.Count <= 4)
            return Py.Head(string.Concat(parts.Select(p => Py.IsUpper(p) || Py.IsDigit(p) ? p : Py.Upper(Py.Head(p, 1)))), 4);
        var cps = Naming.CodePoints(w);
        var out_ = new List<string> { cps[0] };
        foreach (var ch in cps.Skip(1))
        {
            if (!Naming.Vowels.Contains(ch) && Py.IsAlnum(ch) && ch != out_[^1]) out_.Add(ch);
            if (out_.Count == 3) break;
        }
        return string.Concat(out_);
    }

    /// <summary>'SQL Production Reporting' -> [('SQL','SQL'), ('Production','P'), ...] (source, code).</summary>
    public List<(string Src, string Code)> LevelCodes(string text)
    {
        text ??= "";
        var whole = Naming.Norm(text);
        if (_abbr.ContainsKey(whole) && whole.Contains(' '))       // a whole multi-word folder name
            return string.IsNullOrEmpty(_abbr[whole]) ? new() : new() { (text, _abbr[whole]) };
        var words = PyRe.Split(Naming.WordSplit, text).Where(x => x.Length > 0).ToList();
        var out_ = new List<(string, string)>();
        int i = 0;
        while (i < words.Count)
        {
            bool found = false;
            for (int n = Math.Min(_maxPhrase, words.Count - i); n > 0; n--)
            {
                var src = string.Join(" ", words.GetRange(i, n));
                var phrase = Py.Lower(src);
                if (_abbr.ContainsKey(phrase))
                {
                    if (!string.IsNullOrEmpty(_abbr[phrase])) out_.Add((src, _abbr[phrase]));
                    i += n;
                    found = true;
                    break;
                }
            }
            if (found) continue;
            var w = words[i];
            if (!Naming.Stopwords.Contains(Py.Lower(w)))
            {
                var code = Auto(w);
                Unknown[w] = code;
                out_.Add((w, code));
            }
            i++;
        }
        return out_;
    }

    // -- layers ---------------------------------------------------------------

    public List<string> Levels(SourceRecord rec) => rec.Folder.Where(l => !_skipLevels.Contains(Naming.Norm(l))).ToList();

    public LayerCodes Layers(SourceRecord rec, string platform, bool withType = false, bool envInPlace = false)
    {
        var levels = Levels(rec).Select(LevelCodes).ToList();
        var units = levels.SelectMany(l => l).ToList();
        var lc = new LayerCodes();
        var codes = lc.Codes;
        var envUnits = new HashSet<string>(StringComparer.Ordinal);
        var names = Naming.BuiltinLayers.Concat(_layerDefs.Select(d => d.Name).Where(n => !Naming.BuiltinLayers.Contains(n)));
        foreach (var name in names)
        {
            var (code, hits) = LayerValue(name, rec, platform, units, codes);
            codes[name] = code;
            if (name == "env") envUnits = new HashSet<string>(hits.Select(Naming.Norm), StringComparer.Ordinal);
        }
        foreach (var lvl in levels)
        {
            var out_ = new List<string>();
            foreach (var (src, c) in lvl)
            {
                var code = c;
                if (envUnits.Contains(Naming.Norm(src)))
                {
                    if (!envInPlace) continue;
                    code = string.IsNullOrEmpty(codes["env"]) ? code : codes["env"];
                }
                out_.Add(code);
            }
            if (out_.Count > 0) lc.Folder.Add(out_);
        }
        if (envUnits.Count > 0 && string.IsNullOrEmpty(codes["env"])) codes["env"] = _defaultEnv;
        lc.Type = withType && !string.IsNullOrEmpty(rec.Type) ? LevelCodes(rec.Type).Select(p => p.Code).ToList() : new List<string>();
        return lc;
    }

    /// <summary>(code, automatic) for one whole folder name as it would appear in a Safe name.</summary>
    public (string Code, bool Auto) FolderCode(string level)
    {
        var pairs = LevelCodes(level);
        bool auto = pairs.Any(p => !_abbr.ContainsKey(Naming.Norm(p.Src)));
        return (string.Join(Sep, pairs.Select(p => p.Code)), auto);
    }

    /// <summary>Distinct folder names -> suggested codes, so a table can be filled from the data.
    /// folderCounts: folder name -> accounts. Codes another name already uses are flagged.</summary>
    public List<JObj> Suggest(IEnumerable<KeyValuePair<string, long>> folderCounts)
    {
        var rows = new List<JObj>();
        var byCode = new Dictionary<string, string>(StringComparer.Ordinal);
        var ordered = Py.Sorted(folderCounts.ToList(), (a, b) =>
        {
            int c = b.Value.CompareTo(a.Value);
            return c != 0 ? c : Py.Cmp(Py.Lower(a.Key), Py.Lower(b.Key));
        });
        foreach (var (name, count) in ordered)
        {
            if (_skipLevels.Contains(Naming.Norm(name))) continue;
            var (code, auto) = FolderCode(name);
            var row = Json.O(("folder", name), ("code", code), ("accounts", count), ("automatic", auto),
                             ("yours", _userAbbr.ContainsKey(Naming.Norm(name))), ("clash", ""));
            var key = Py.Upper(code);
            if (byCode.TryGetValue(key, out var other) && !string.IsNullOrEmpty(other) && auto && Naming.Norm(other) != Naming.Norm(name))
                row["clash"] = other;
            byCode.TryAdd(key, name);
            rows.Add(row);
        }
        return rows;
    }

    // -- assemble -------------------------------------------------------------

    /// <summary>Return (name, notes). The name already fits max_length when possible.</summary>
    public (string Name, List<string> Notes) Build(SourceRecord rec, string platform, string template = null)
    {
        if (string.IsNullOrEmpty(template)) template = Levels(rec).Count > 0 ? Template : TemplateFlat;
        var lay = Layers(rec, platform, withType: template.Contains("{type}"), envInPlace: !template.Contains("{env}"));
        var parts = new List<NamePart>();
        foreach (Match m in PyRe.Compile(@"\{(\w+)\}|([^{}]+)").Matches(template))
        {
            var key = m.Groups[1].Success ? m.Groups[1].Value : "";
            var literal = m.Groups[2].Success ? m.Groups[2].Value : "";
            if (literal.Length > 0)
            {
                var lit = Py.Strip(literal, Sep);
                if (lit.Length > 0) parts.Add(new("literal", new() { new() { lit } }));
            }
            else if (key == "folder")
                parts.Add(new("folder", lay.Folder.Select(l => new List<string>(l)).ToList()));
            else if (key == "folder_leaf")
                parts.Add(new("folder", lay.Folder.Count > 0 ? new() { new List<string>(lay.Folder[^1]) } : new()));
            else if (key == "type")
                parts.Add(new("type", lay.Type.Count > 0 ? new() { new List<string>(lay.Type) } : new()));
            else if (lay.Codes.ContainsKey(key))
            {
                var v = lay.Codes[key];
                parts.Add(new(key, string.IsNullOrEmpty(v) ? new() : new() { new() { v } }));
            }
        }
        // Drop codes already used earlier in the name (e.g. SQL from the folder and the flavor).
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in parts)
        {
            foreach (var lvl in part.Levels)
            {
                var keep = lvl.Where(c => part.Kind == "literal" || !seen.Contains(Py.Upper(c))).ToList();
                foreach (var c in lvl) seen.Add(Py.Upper(c));
                lvl.Clear();
                lvl.AddRange(keep);
            }
        }
        return Fit(parts);
    }

    /// <summary>Shorten in steps until the name fits, keeping the most specific folders:
    /// 1. a multi-word folder level above the last one becomes its initials (Customer Facing -> CF)
    /// 2. the last folder level becomes its initials
    /// 3. folder levels are dropped from the top (most generic) down, never the last one
    /// 4. the end is cut off (reported as an issue).</summary>
    public (string, List<string>) Fit(List<NamePart> parts)
    {
        string Render() => string.Join(Sep, parts.SelectMany(p => p.Levels).SelectMany(l => l).Where(c => !string.IsNullOrEmpty(c)));
        bool Fits() => Py.Len(Render()) <= MaxLen;

        if (Fits()) return (Render(), new List<string>());
        var folders = parts.Where(p => (p.Kind == "folder" || p.Kind == "type") && p.Levels.Count > 0).Select(p => p.Levels).ToList();

        static void Initials(List<string> lvl)
        {
            if (lvl.Count > 1)
            {
                var s = string.Concat(lvl.Select(c => Py.Head(c, 1)));
                lvl.Clear();
                lvl.Add(s);
            }
        }

        foreach (var levels in folders)
            foreach (var lvl in levels.Take(levels.Count - 1))
            {
                Initials(lvl);
                if (Fits()) return (Render(), new List<string> { "long folder names turned into initials to fit" });
            }
        foreach (var levels in folders)
        {
            if (levels.Count > 0)
            {
                Initials(levels[^1]);
                if (Fits()) return (Render(), new List<string> { "long folder names turned into initials to fit" });
            }
        }
        foreach (var levels in folders)
        {
            while (levels.Count > 1 && !Fits()) levels.RemoveAt(0);
            if (Fits()) return (Render(), new List<string> { "top folder levels left out to fit" });
        }
        return (Py.RStrip(Py.Head(Render(), MaxLen), Sep), new List<string> { "convention name still too long; cut to fit" });
    }
}
