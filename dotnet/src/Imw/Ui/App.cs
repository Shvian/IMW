using System.Text;
using System.Text.RegularExpressions;
using Imw.Adapters;
using Imw.Core;

namespace Imw.Ui;

public class UiError : Exception
{
    public readonly int Status;
    public UiError(string message, int status = 400) : base(message) { Status = status; }
}

/// <summary>
/// The Workbench's API. Every method takes the parsed JSON
/// body and returns a JSON-like value; the web server (Server.cs) calls them one at a time under Lock.
/// </summary>
public sealed class UiApp
{
    public const string Product = "Idira Migration Workbench";
    public const int IdleSeconds = 10 * 60;      // auto-lock
    public const int MaxFailures = 5;            // then a growing wait between attempts
    public const int PageSize = 200;
    static readonly string[] Editable = { "migrate", "target_safe", "platform_id", "account_name" };

    // The review menu: key -> (label, SQL condition on the accounts view).
    public static readonly OrderedMap<string, (string Label, string Sql)> Views = MakeViews();

    static OrderedMap<string, (string, string)> MakeViews()
    {
        var v = new OrderedMap<string, (string, string)>(StringComparer.Ordinal);
        v["all"] = ("All accounts", "1=1");
        v["upload"] = ("Will be uploaded", "migrate = 'Y' AND status <> 'ERROR'");
        v["review"] = ("Needs a look", "status = 'REVIEW'");
        v["review_open"] = ("Needs a look, not approved yet", "status = 'REVIEW' AND COALESCE(approved, '') <> 'Y'");
        v["approved"] = ("Needs a look, approved by you", "status = 'REVIEW' AND approved = 'Y'");
        v["errors"] = ("Errors (not uploaded)", "status = 'ERROR'");
        v["excluded"] = ("Left out by you", "migrate = 'N'");
        v["renamed_safes"] = ("Safe name was changed", "valid_safe_name = 'FALSE'");
        v["no_access"] = ("No access groups", "access_groups = ''");
        v["no_secret"] = ("Empty secret", "has_secret = 'N'");
        v["fallback"] = ("Safe named by the convention (no rule matched)", "safe_mapping_source LIKE 'fallback:%'");
        v["duplicates"] = ("Possible duplicates (same username and address)", "notes LIKE '%possible duplicate%'");
        v["otp"] = ("One-time password in the source", "notes LIKE '%one-time password (OTP)%'");
        v["edited"] = ("Changed by you", "record_id IN (SELECT record_id FROM edits)");
        v["sanitized"] = ("Forbidden characters changed", "(notes LIKE '%forbidden characters%' OR valid_safe_name = 'FALSE' " +
                          "OR record_id IN (SELECT record_id FROM records WHERE notes_json LIKE '%forbidden characters%'))");
        return v;
    }

    static readonly (string Key, string Col)[] FilterColumns =
    {
        ("safe", "target_safe"), ("source", "source"), ("platform", "platform_id"), ("status", "status"), ("type", "source_type"),
    };
    static readonly HashSet<string> Sortable = new(StringComparer.Ordinal)
    {
        "target_safe", "account_name", "username", "address", "platform_id", "status", "folder", "source", "record_id",
    };

    public readonly string Ws, Inbox, Output, DbPath, ConfigPath;
    public readonly Identity Owner_;
    readonly string _protectorFlag;
    public readonly object Lock = new();
    public string LaunchToken = NewToken();
    public string Sid;
    public double LastSeen;
    public bool Unlocked;
    public readonly IAuthenticator Auth;
    public int Failures;
    public double WaitUntil;
    public Action Shutdown;                               // set by the server: stops it
    public Func<string, int, int, string, bool> PeerCheck = Owner.PeerIsOwner;
    readonly Dictionary<(string, long, long), string> _shaCache = new();

    public static string NewToken()
    {
        var b = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Test hook: replaces the clock (seconds since 1970) for the idle lock and sign-in waits.</summary>
    public static Func<double> Clock;
    public static double Now() => Clock?.Invoke() ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    public UiApp(string workspace, string protectorFlag = null, IAuthenticator authenticator = null)
    {
        Ws = ResolvePath(workspace);
        Inbox = Path.Combine(Ws, "inbox");
        Output = Path.Combine(Ws, "output");
        DbPath = Path.Combine(Ws, "migration.db");
        bool hasDb;
        try { hasDb = File.Exists(DbPath); }
        catch (UnauthorizedAccessException) { hasDb = false; }   // ClaimWorkspace explains
        if (hasDb) new Store(DbPath).Close();                     // refuses another user's database before anything starts
        // Only the Windows user who created the workspace may use it; it is locked to that user.
        Owner_ = Owner.ClaimWorkspace(Ws);
        Directory.CreateDirectory(Inbox);
        Directory.CreateDirectory(Output);
        ConfigPath = Path.Combine(Ws, "config.json");
        _protectorFlag = protectorFlag;
        Auth = authenticator ?? Ui.Auth.Get();
    }

    /// <summary>Path.resolve(): absolute, with a linked folder followed to its target.</summary>
    public static string ResolvePath(string path)
    {
        var full = Path.GetFullPath(path);
        try
        {
            var target = new DirectoryInfo(full).ResolveLinkTarget(true);
            if (target != null) return Path.GetFullPath(target.FullName);
        }
        catch (IOException) { }
        return full;
    }

    static bool SamePath(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(a), Path.TrimEndingDirectorySeparator(b),
                      OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    static int PathCmp(string a, string b) => OperatingSystem.IsWindows() ? Py.Cmp(Py.Lower(a), Py.Lower(b)) : Py.Cmp(a, b);

    static bool DbExists(string p) => File.Exists(p);

    // ---------------------------------------------------------------- helpers

    Store OpenStore(bool create = false)
    {
        if (!DbExists(DbPath) && !create) throw new UiError("No data yet. Start with step 1, Load exports.", 409);
        string protector = null;
        if (create && !DbExists(DbPath))
        {
            if (!string.IsNullOrEmpty(_protectorFlag)) protector = _protectorFlag;
            else if (!OperatingSystem.IsWindows())
                throw new UiError("Secrets are protected with Windows DPAPI, which needs Windows. Start the " +
                                  "UI with --no-secrets or --insecure-plaintext-secrets on this machine.");
        }
        return new Store(DbPath, create, protector);
    }

    JObj LoadConfig() => File.Exists(ConfigPath) ? Config.Load(ConfigPath) : Config.Load(null);

    static object G(JObj b, string k) => b?.Get(k);
    static bool T(object v) => Py.Truthy(v);
    /// <summary>str(x or "")</summary>
    static string OrE(object v) => T(v) ? Py.Str(v) : "";
    /// <summary>(x or "") as a value, for Python's != between possibly different types.</summary>
    static object OrV(object v) => T(v) ? v : "";
    static bool Differs(object a, object b) => !Py.Eq(OrV(a), OrV(b));
    static long Count(Db db, string sql, params object[] args) => Convert.ToInt64(db.Scalar(sql, args) ?? 0L);
    static JObj Zip(List<string> cols, object[] r)
    {
        var o = new JObj();
        for (int i = 0; i < cols.Count; i++) o[cols[i]] = r[i];
        return o;
    }
    static List<object> Strings(IEnumerable<string> items) => items.Cast<object>().ToList();

    /// <summary>int(x) of a JSON value; anything else fails like Python's int() (an unexpected error).</summary>
    static long IntOf(object v) => v switch
    {
        long l => l,
        int i => i,
        bool b => b ? 1 : 0,
        double d => (long)Math.Truncate(d),
        string s when long.TryParse(Py.Strip(s).Replace("_", ""), System.Globalization.NumberStyles.AllowLeadingSign,
                                    System.Globalization.CultureInfo.InvariantCulture, out var n) => n,
        _ => throw new FormatException($"invalid literal for int(): {Py.Repr(v)}"),
    };

    /// <summary>One typed value without control or invisible characters; notes in cleaned when any went.</summary>
    static string Line(object v, List<string> cleaned)
    {
        var raw = Py.Strip(v != null ? Py.Str(v) : "");
        var out_ = Transform.CleanLine(raw);
        if (out_ != raw) cleaned.Add(raw);
        return out_;
    }

    /// <summary>Turn a menu choice and filters into a parameterised WHERE clause.</summary>
    public static (string, List<object>) BuildWhere(JObj body)
    {
        var view = Py.Or(G(body, "view"), "all");
        if (view is not string vs || !Views.ContainsKey(vs)) throw new UiError($"unknown view {Py.Str(view)}");
        var parts = new List<string> { $"({Views[vs].Sql})" };
        var pars = new List<object>();
        var filters = G(body, "filters") as JObj ?? new JObj();
        foreach (var (key, col) in FilterColumns)
        {
            var val = filters.Get(key);
            if (T(val))
            {
                parts.Add($"{col} = ?");
                pars.Add(val);
            }
        }
        var search = Py.Strip(OrE(filters.Get("search")));
        if (search.Length > 0)
        {
            // % and _ are wildcards in LIKE; the search is plain text, so escape them (a bulk edit
            // of the rows found for "svc_" must not also change "svc1").
            var escaped = search.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
            var like = $"%{escaped}%";
            var cols = new[] { "account_name", "username", "address", "folder", "record_id", "target_safe" };
            parts.Add("(" + string.Join(" OR ", cols.Select(c => $"{c} LIKE ? ESCAPE '\\'")) + ")");
            foreach (var _ in cols) pars.Add(like);
        }
        return (string.Join(" AND ", parts), pars);
    }

    /// <summary>Custom roles and the permission map must make sense before they are saved.</summary>
    public static void CheckRoles(JObj cfg)
    {
        foreach (var kv in cfg.Obj("custom_roles") ?? new JObj())
        {
            var name = kv.Key;
            var perms = kv.Value as List<object> ?? new List<object>();
            if (Py.Strip(name).Length == 0) throw new UiError("Every custom role needs a name.");
            if (Config.PermissionPresets.Keys.Any(p => Py.Lower(name) == Py.Lower(p)))
                throw new UiError($"'{name}' is a built-in preset name; give your custom role another name.");
            var bad = perms.Where(p => p is not string s || !Config.AllPermissions.Contains(s)).Select(Py.Str).ToList();
            if (bad.Count > 0) throw new UiError($"Custom role '{name}' has unknown permissions: {string.Join(", ", bad)}");
            if (perms.Count == 0) throw new UiError($"Custom role '{name}' has no permissions ticked.");
            if (perms.Contains("requestsAuthorizationLevel1") && perms.Contains("requestsAuthorizationLevel2"))
                throw new UiError($"Custom role '{name}': pick authorization level 1 or level 2, not both.");
        }
        foreach (var kv in cfg.Obj("permission_map") ?? new JObj())
            if (Config.ResolveRole(kv.Value, cfg).Length == 0)
                throw new UiError($"Source permission '{kv.Key}' maps to '{Py.Str(kv.Value)}', which is not a preset or custom role.");
    }

    /// <summary>Mark files loaded more than once: same name with the same or different content, or the
    /// same content under another name (which loads every record twice).</summary>
    public static List<JObj> CompareInputs(List<JObj> inputs)
    {
        for (int i = 0; i < inputs.Count; i++)
        {
            var cur = inputs[i];
            var name = Py.Lower(Path.GetFileName(Py.Str(cur["path"])));
            var notes = new List<string>();
            foreach (var prev in inputs.Take(i))
            {
                var pname = Path.GetFileName(Py.Str(prev["path"]));
                if (Py.Lower(pname) == name)
                {
                    var same = Py.Eq(prev["sha256"], cur["sha256"]);
                    notes.Add($"{(same ? "same content as" : "different content from")} load #{Py.Str(prev["id"])}");
                }
                else if (Py.Eq(prev["sha256"], cur["sha256"]))
                    notes.Add($"same content as load #{Py.Str(prev["id"])} ({pname}); records are loaded twice");
            }
            cur["file"] = Path.GetFileName(Py.Str(cur["path"]));
            cur["repeat"] = string.Join("; ", notes);
        }
        return inputs;
    }

    /// <summary>Safe settings typed on the pages or in the JSON: no control or invisible characters.
    /// Returns how many values changed.</summary>
    public static int CleanSafeSettings(JObj cfg)
    {
        var cleaned = new List<string>();
        var bodies = new List<JObj> { cfg.Obj("safe_defaults") ?? new JObj() };
        bodies.AddRange((cfg.List("safe_rules") ?? new List<object>()).OfType<JObj>());
        foreach (var body in bodies)
            foreach (var k in new[] { "description", "location", "managingCPM" })
                if (body.Get(k) is string s)
                    body[k] = Line(s, cleaned);
        return cleaned.Count;
    }

    static void Rx(object pattern, string where)
    {
        try { PyRe.Check(T(pattern) ? Py.Str(pattern) : ""); }
        catch (PyReError exc) { throw new UiError($"{where}: '{Py.Str(pattern)}' is not a valid pattern ({exc.Message})."); }
    }

    static readonly Regex StandardPlaceholders = new(@"\{(\w*)\}", RegexOptions.CultureInvariant);

    /// <summary>Regexes and Safe settings must be usable before they are saved.</summary>
    public static void CheckSettings(JObj cfg)
    {
        var conv = cfg.Obj("safe_convention") ?? throw new KeyError("safe_convention");
        foreach (var kv in conv.Obj("layers") ?? new JObj())
        {
            var name = kv.Key;
            if (PyRe.FullMatch(@"[A-Za-z_][A-Za-z0-9_]*", name) == null)
                throw new UiError($"Placeholder name '{name}' can only use letters, digits and _.");
            if (name is "folder" or "folder_leaf" or "type" or "convention" or "folder_abbrev")
                throw new UiError($"{{{name}}} is a built-in placeholder; pick another name.");
            var layer = kv.Value as JObj ?? new JObj();
            foreach (var r in (layer.List("rules") ?? new List<object>()).OfType<JObj>())
            {
                Rx(r.Get("pattern"), $"{{{name}}} rule");
                if (T(r.Get("field2"))) Rx(r.Get("pattern2"), $"{{{name}}} rule");
            }
        }
        foreach (var src in (cfg.List("directory_sources") ?? new List<object>()).OfType<JObj>())
        {
            var match = Py.Str(src.Get("match", ""));
            if (Py.Lower(match).StartsWith("re:", StringComparison.Ordinal)) Rx(match.Substring(3), "Directory source match");
            if (T(src.Get("find"))) Rx(src["find"], "Directory source find");
        }
        foreach (var row in (cfg.List("domain_map") ?? new List<object>()).OfType<JObj>())
        {
            var to = Py.LStrip(Py.Strip(OrE(row.Get("to"))), "@");
            if (Py.Strip(OrE(row.Get("from"))).Length == 0)
                throw new UiError("Each domain conversion row needs the source domain(s) it converts, or *.");
            if (to.Length > 0 && PyRe.FullMatch(@"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*", to) == null)
                throw new UiError($"'{to}' is not a domain name (for example corp.example.com).");
        }
        static bool Has(JObj o, string k) => Py.Strip(Py.Str(o.Get(k, ""))).Length > 0;
        foreach (var rule in (cfg.List("safe_rules") ?? new List<object>()).OfType<JObj>())
        {
            Rx(rule.Get("safe_pattern"), "Safe settings rule");
            if (Has(rule, "numberOfVersionsRetention") && Has(rule, "numberOfDaysRetention"))
                throw new UiError("A Safe keeps either a number of versions or a number of days, not both.");
        }
        var d = cfg.Obj("safe_defaults") ?? new JObj();
        if (Has(d, "numberOfVersionsRetention") && Has(d, "numberOfDaysRetention"))
            throw new UiError("Safes keep either a number of versions or a number of days, not both.");
        foreach (var rule in (cfg.List("platform_rules") ?? new List<object>()).OfType<JObj>())
            Rx(rule.Get("pattern"), "Platform rule");
        var std = cfg.Obj("standard_members") ?? new JObj();
        if (OrE(std.Get("apply_to")) is var applyTo && (applyTo.Length == 0 ? "no_source_members" : applyTo) is not ("no_source_members" or "all" or "off"))
            throw new UiError("Standard member groups: 'add to' must be no_source_members, all or off.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in (std.List("members") ?? new List<object>()).OfType<JObj>())
        {
            var nameObj = Transform.CleanLineObj(row.Get("name"));
            if (!T(nameObj)) throw new UiError("Every standard member group row needs a name pattern, for example {safe}-Users.");
            var name = Py.Str(nameObj);
            var bad = StandardPlaceholders.Matches(name).Select(m => m.Groups[1].Value).Where(p => p != "safe").ToList();
            if (bad.Count > 0 || name.Count(c => c == '{') != name.Count(c => c == '}'))
                throw new UiError($"Standard member group '{name}': the only placeholder is {{safe}}.");
            var mt = Py.Lower(Py.Strip(T(row.Get("member_type")) ? Py.Str(row.Get("member_type")) : "Group"));
            if (mt is not ("user" or "group" or "role"))
                throw new UiError($"Standard member group '{name}': the member type must be User, Group or Role.");
            if (Config.ResolveRole(row.Get("role"), cfg).Length == 0)
                throw new UiError($"Standard member group '{name}': pick a role (a preset or one of your custom roles).");
            if (!seen.Add(Py.Lower(name))) throw new UiError($"The standard member group '{name}' is listed twice.");
        }
    }

    /// <summary>A CSV whose header has a group/user column and a permission column, and no password column
    /// (the Workbench layout, or a Delinea folder-permissions report).</summary>
    public static bool LooksLikePermissions(string path)
    {
        if (Py.Lower(Path.GetExtension(path)) != ".csv" || Reference.Kind(path).Length > 0) return false;
        string line;
        try
        {
            using var r = new StreamReader(path, new UTF8Encoding(false, false), false);
            line = r.ReadLine() ?? "";
            if (line.StartsWith('\ufeff')) line = line.Substring(1);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { return false; }
        var header = line.Split(',').Select(h => Py.Strip(Py.Strip(Py.Lower(Py.Strip(h))), "\"")).Select(h => Py.Strip(h)).ToList();
        var who = Permissions.GroupColumns.Concat(Permissions.UserColumns).Select(Py.Lower).ToHashSet(StringComparer.Ordinal);
        var roles = Permissions.RoleColumns.Select(Py.Lower).ToHashSet(StringComparer.Ordinal);
        return header.Any(who.Contains) && header.Any(roles.Contains) && !header.Any(h => h.Contains("password"));
    }

    /// <summary>Overwrite then delete. Best effort: SSDs and some file systems keep old copies.
    /// Writes zeros in 1 MB blocks, so a large file does not need its size in memory.</summary>
    public static void SecureDelete(string path, int chunk = 1 << 20)
    {
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            long left = fs.Length;
            var zeros = new byte[(int)Math.Max(1, Math.Min(chunk, left))];
            while (left > 0)
            {
                int n = (int)Math.Min(left, zeros.Length);
                fs.Write(zeros, 0, n);
                left -= n;
            }
            fs.Flush(true);
        }
        File.Delete(path);
    }

    // ---------------------------------------------------------------- API

    public object ApiState(JObj _)
    {
        var sources = new JObj();
        foreach (var kv in Adapter.All) sources[kv.Key] = kv.Value().Description;
        var views = new JObj();
        foreach (var kv in Views) views[kv.Key] = kv.Value.Label;
        var inboxFiles = new List<object>();
        var outputs = new List<object>();
        var kinds = new JObj();
        foreach (var kv in Reference.Kinds)
            kinds[kv.Key] = Json.O(("label", kv.Value), ("help", Reference.KindHelp[kv.Key]), ("used", Reference.UsedKinds.Contains(kv.Key)));
        var state = Json.O(("version", Writers.Version), ("workspace", Ws), ("inbox", Inbox), ("output", Output),
            ("has_db", DbExists(DbPath)), ("sources", sources), ("inbox_files", inboxFiles), ("outputs", outputs), ("views", views),
            ("kinds", kinds));
        foreach (var f in Directory.EnumerateFileSystemEntries(Inbox).OrderBy(x => x, Comparer<string>.Create(PathCmp)))
        {
            if (!File.Exists(f)) continue;
            string guess;
            try { guess = Adapter.Detect(f).Name; }
            catch (AdapterError) { guess = ""; }
            var reference = Reference.Kind(f);
            var perm = LooksLikePermissions(f);
            var kind = reference.Length > 0 ? reference : perm ? "permissions" : guess.Length > 0 ? "accounts" : "";
            inboxFiles.Add(Json.O(("name", Path.GetFileName(f)), ("size", new FileInfo(f).Length), ("guess", guess),
                                  ("permissions", perm), ("kind", kind)));
        }
        foreach (var d in Directory.EnumerateFileSystemEntries(Output).OrderBy(x => x, Comparer<string>.Create(PathCmp)).Reverse())
        {
            if (!Directory.Exists(d)) continue;
            var man = Path.Combine(d, "manifest.json");
            var info = File.Exists(man) ? Json.ParseObj(PyFile.ReadText(man)) : new JObj();
            outputs.Add(Json.O(("name", Path.GetFileName(d)), ("created", info.Get("created_utc", "")),
                ("secrets", info.Get("includes_secrets", false)), ("counts", info.Get("counts", new JObj())),
                ("has_upload", Directory.Exists(Path.Combine(d, "upload")) || File.Exists(Path.Combine(d, "upload")))));
        }
        if (T(state["has_db"]))
        {
            var st = OpenStore();
            try
            {
                var db = st.Db;
                state["protector"] = st.Meta("protector");
                state["mapped"] = st.Meta("mapped_utc");
                state["records"] = Count(db, "SELECT COUNT(*) FROM records");
                state["inputs"] = CompareInputs(db.Query("SELECT id, source, path, sha256, records, permissions_path, permissions_sha256, " +
                                                         "loaded_utc, loaded_by FROM inputs ORDER BY id").Select(r => r.ToJObj()).ToList())
                                  .Cast<object>().ToList();
                var counts = new JObj();
                foreach (var r in db.Query("SELECT status, COUNT(*) FROM plan_accounts GROUP BY status")) counts[Py.Str(r[0])] = r[1];
                state["status_counts"] = counts;
                state["approved"] = Count(db, "SELECT COUNT(*) FROM plan_accounts WHERE status = 'REVIEW' AND approved = 'Y'");
                state["excluded"] = Count(db, "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'N'");
                state["to_upload"] = Count(db, "SELECT COUNT(*) FROM plan_accounts WHERE migrate = 'Y' AND status <> 'ERROR'");
                state["safes"] = Count(db, "SELECT COUNT(*) FROM plan_safes");
                state["invalid_safes"] = Count(db, "SELECT COUNT(*) FROM plan_safes WHERE valid_safe_name = 'FALSE'");
                state["edits"] = Count(db, "SELECT COUNT(DISTINCT record_id) FROM edits");
                state["sanitized"] = Count(db, "SELECT COUNT(*) FROM accounts WHERE " + Views["sanitized"].Sql);
                state["member_edits"] = Count(db, "SELECT COUNT(*) FROM member_edits");
                state["undecided"] = Count(db, "SELECT COUNT(*) FROM plan_undecided WHERE decision = ''");
                state["undecided_all"] = Count(db, "SELECT COUNT(*) FROM plan_undecided");
                state["references"] = Json.O(("templates", Count(db, "SELECT COUNT(*) FROM ref_templates")),
                                             ("users", Count(db, "SELECT COUNT(*) FROM ref_users")));
                state["stale"] = Count(db, "SELECT COUNT(*) FROM records WHERE record_id NOT IN (SELECT record_id FROM plan_accounts)") != 0;
            }
            finally { st.Close(); }
            MarkLoaded(state);
        }
        return state;
    }

    /// <summary>Tell the Load page which inbox files are already loaded, with the same or changed content.</summary>
    void MarkLoaded(JObj state)
    {
        var known = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var i in (state.List("inputs") ?? new List<object>()).OfType<JObj>())
        {
            known[Py.Lower(Path.GetFileName(Py.Str(i["path"])))] = i["sha256"];
            var paths = OrE(i.Get("permissions_path")).Split(" | ");
            var shas = OrE(i.Get("permissions_sha256")).Split(" | ");
            for (int k = 0; k < Math.Min(paths.Length, shas.Length); k++)
                if (paths[k].Length > 0) known[Py.Lower(Path.GetFileName(paths[k]))] = shas[k];
        }
        foreach (var f in state.List("inbox_files").OfType<JObj>())
        {
            var sha = known.GetValueOrDefault(Py.Lower(Py.Str(f["name"])));
            if (!T(sha)) continue;
            var path = Path.Combine(Inbox, Py.Str(f["name"]));
            try
            {
                var fi = new FileInfo(path);
                var key = (path, fi.Length, fi.LastWriteTimeUtc.Ticks);
                if (!_shaCache.TryGetValue(key, out var h)) _shaCache[key] = h = Store.Sha256File(path);
                f["loaded"] = Py.Eq(h, sha) ? "same" : "changed";
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        }
    }

    public object ApiIngest(JObj body)
    {
        var files = G(body, "files") as List<object> ?? new List<object>();
        var refs = G(body, "references") as List<object> ?? new List<object>();
        if (files.Count == 0 && refs.Count == 0) throw new UiError("Pick at least one export file.");
        var cfg = LoadConfig();
        var permObj = Py.Or(G(body, "permissions"), new List<object>());
        var permNames = permObj is string ps ? new List<object> { ps } : permObj as List<object> ?? new List<object>();
        var permPaths = permNames.Select(n => InboxFile(n)).ToList();
        Permissions perms;
        try { perms = permPaths.Count > 0 ? new Permissions(permPaths) : null; }
        catch (Exception exc) when (exc is ValueError or IOException or UnauthorizedAccessException)
        {
            throw new UiError($"Permissions file: {exc.Message}");
        }
        var results = new List<object>();
        var st = OpenStore(create: true);
        try
        {
            foreach (var ro in refs)
            {
                var f = ro as JObj ?? throw new UiError("Pick at least one export file.");
                var path = InboxFile(f.Get("name"));
                var kind = T(f.Get("kind")) ? Py.Str(f["kind"]) : Reference.Kind(path);
                if (!Reference.UsedKinds.Contains(kind)) throw new UiError($"{Path.GetFileName(path)} is not a template list or users list");
                var rows = kind == "templates" ? Reference.ReadTemplates(path) : Reference.ReadUsers(path);
                var n = st.IngestReference(kind, path, rows);
                results.Add(Json.O(("name", f.Get("name")), ("source", kind), ("records", (long)n), ("replaced", 0L), ("sanitized", 0L)));
            }
            foreach (var fo in files)
            {
                var f = fo as JObj ?? throw new UiError("Pick at least one export file.");
                var path = InboxFile(f.Get("name"));
                var adapter = T(f.Get("source")) ? Adapter.Get(Py.Str(f["source"])) : Adapter.Detect(path);
                var records = adapter.Read(path, cfg);
                var (n, replaced) = st.Ingest(adapter.Name, path, records, perms, permPaths);
                var result = Json.O(("name", f.Get("name")), ("source", adapter.Name), ("records", (long)n), ("replaced", (long)replaced),
                                    ("sanitized", (long)st.LastSanitized));
                // A spreadsheet whose headers the Workbench didn't recognise: offer the column picker.
                var missing = new List<object>();
                if (records.Count > 0 && !records.Any(r => T(r.Username))) missing.Add("username");
                if (records.Count > 0 && !records.Any(r => T(r.Address))) missing.Add("address");
                if (missing.Count > 0 && adapter is TableAdapter table)
                {
                    var (headers, current) = table.ColumnReport(path, cfg);
                    result["columns"] = Json.O(("missing", missing), ("headers", Strings(headers)), ("current", current));
                }
                results.Add(result);
            }
            st.Map(cfg, File.Exists(ConfigPath) ? ConfigPath : null);
        }
        catch (Exception exc) when (exc is AdapterError or ValueError or IOException or UnauthorizedAccessException
                                        or ProtectError or StoreError or System.Xml.XmlException)
        {
            throw new UiError(exc.Message);
        }
        finally { st.Close(); }
        return Json.O(("results", results), ("protector", string.IsNullOrEmpty(_protectorFlag) ? "dpapi" : _protectorFlag));
    }

    /// <summary>Users from the users report who may get their access through a group (one row per folder, Safe
    /// and user), with your decision.</summary>
    public object ApiUndecided(JObj _)
    {
        if (!DbExists(DbPath)) return Json.O(("rows", new List<object>()));
        var st = OpenStore();
        try
        {
            var rows = st.Db.Query("SELECT folder, safe_name, member, member_name, permission, groups, accounts, decision, notes " +
                                   "FROM plan_undecided ORDER BY groups, member, folder");
            return Json.O(("rows", rows.Select(r => (object)r.ToJObj()).ToList()));
        }
        finally { st.Close(); }
    }

    public object ApiDecide(JObj body)
    {
        var items = (G(body, "items") as List<object> ?? new List<object>()).OfType<JObj>()
            .Select(i => (Py.Str(Py.Or(i.Get("folder"), "")), Py.Str(Py.Or(i.Get("member"), "")))).ToList();
        if (items.Count == 0) throw new UiError("Tick at least one user first.");
        var decision = Py.Str(Py.Or(G(body, "decision"), ""));
        var st = OpenStore();
        try
        {
            var n = st.SetDecisions(items, decision, Py.Str(Py.Or(G(body, "reason"), "")));
            st.Map(LoadConfig(), File.Exists(ConfigPath) ? ConfigPath : null);
            return Json.O(("changed", (long)n));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
    }

    string InboxFile(object name)
    {
        var n = name as string ?? Py.Str(name);
        var path = ResolveFile(Path.Combine(Inbox, n));
        if (!SamePath(Path.GetDirectoryName(path) ?? "", Inbox) || !File.Exists(path))
            throw new UiError($"{n} is not in the inbox folder");
        return path;
    }

    /// <summary>Path.resolve() for a file: absolute, "..", and a link followed to its target.</summary>
    static string ResolveFile(string path)
    {
        var full = Path.GetFullPath(path);
        try
        {
            var target = new FileInfo(full).ResolveLinkTarget(true);
            if (target != null) return Path.GetFullPath(target.FullName);
        }
        catch (IOException) { }
        return full;
    }

    public object ApiInboxDelete(JObj body)
    {
        var path = InboxFile(G(body, "name") ?? "");
        SecureDelete(path);
        return Json.O(("deleted", Path.GetFileName(path)));
    }

    public object ApiConfigGet(JObj _)
    {
        var cfg = LoadConfig();
        var hints = Json.O(("types_without_platform", new List<object>()), ("groups", new List<object>()),
                           ("folders", new List<object>()), ("columns", new List<object>()));
        var used = new List<string>();
        if (DbExists(DbPath))
        {
            var st = OpenStore();
            try
            {
                var db = st.Db;
                hints["types_without_platform"] = db.Query("SELECT DISTINCT source_type FROM plan_accounts WHERE platform_id = '' ORDER BY 1")
                    .Select(r => r[0]).ToList();
                hints["groups"] = db.Query("SELECT member, COUNT(DISTINCT record_id) FROM grants GROUP BY lower(member) ORDER BY 2 DESC LIMIT 200")
                    .Select(r => (object)Json.O(("name", r[0]), ("accounts", r[1]))).ToList();
                hints["folders"] = db.Query("SELECT folder, COUNT(*) FROM records GROUP BY folder ORDER BY 1 LIMIT 500")
                    .Select(r => (object)Json.O(("name", r[0]), ("accounts", r[1]))).ToList();
                hints["types"] = db.Query("SELECT type, COUNT(*) FROM records GROUP BY type ORDER BY 2 DESC")
                    .Select(r => (object)Json.O(("name", r[0]), ("accounts", r[1]))).ToList();
                used = db.Query("SELECT DISTINCT platform_id FROM plan_accounts WHERE platform_id <> ''").Select(r => Py.Str(r[0])).ToList();
                hints["columns"] = SourceColumns(st);
                hints["records"] = Count(db, "SELECT COUNT(*) FROM records");
                hints["without_folder"] = Count(db, "SELECT COUNT(*) FROM records WHERE folder_json IN ('', '[]')");
                hints["with_grants"] = Count(db, "SELECT COUNT(DISTINCT record_id) FROM grants");
            }
            finally { st.Close(); }
        }
        hints["platforms"] = PlatformIds(cfg, used);
        return Json.O(("config", cfg), ("defaults", Config.DefaultConfig()), ("hints", hints), ("saved", File.Exists(ConfigPath)),
                      ("presets", Config.PresetsJson()), ("permissions", Strings(Config.AllPermissions)),
                      ("standard_member_set", Config.StandardMemberSet()));
    }

    /// <summary>Every extra source column in the loaded records, with how many records have a value in it.</summary>
    static List<object> SourceColumns(Store st)
    {
        var counts = new OrderedMap<string, long[]>(StringComparer.Ordinal);
        foreach (var r in st.Db.Query("SELECT extra_json FROM records"))
        {
            var extra = Json.ParseObj(T(r[0]) ? Py.Str(r[0]) : "{}");
            foreach (var kv in extra)
            {
                var n = counts.GetOrAdd(kv.Key, () => new long[2]);
                n[0] += 1;
                n[1] += Py.Strip(OrE(kv.Value)).Length > 0 ? 1 : 0;
            }
        }
        return Py.Sorted(counts.ToList(), (a, b) => Py.Cmp(Py.Lower(a.Key), Py.Lower(b.Key)))
            .Select(kv => (object)Json.O(("name", kv.Key), ("records", kv.Value[0]), ("filled", kv.Value[1]))).ToList();
    }

    /// <summary>Platform IDs to suggest: the usual Privilege Cloud IDs plus every one already in use.</summary>
    static List<object> PlatformIds(JObj cfg, IEnumerable<string> used)
    {
        var ids = new OrderedMap<string, string>(StringComparer.Ordinal);
        foreach (var p in Naming.DefaultPlatformCodes) ids[p.Platform] = "standard Privilege Cloud platform";
        var mine = new List<object>();
        mine.AddRange((cfg.Obj("platform_map") ?? new JObj()).Values);
        mine.AddRange((cfg.List("platform_rules") ?? new List<object>()).Select(r => (r as JObj)?.Get("platform", "")));
        mine.Add(Py.Or(cfg.Get("default_platform"), ""));
        foreach (var p in mine)
            if (T(p) && !ids.ContainsKey(Py.Str(p))) ids[Py.Str(p)] = "used in your rules";
        foreach (var p in used)
            if (T(p) && !ids.ContainsKey(p)) ids[p] = "used by loaded accounts";
        return Py.Sorted(ids.ToList(), (a, b) => Py.Cmp(Py.Lower(a.Key), Py.Lower(b.Key)))
            .Select(kv => (object)Json.O(("id", kv.Key), ("note", kv.Value))).ToList();
    }

    static SourceRecord RecordFrom(DbRow r, string folderJson)
    {
        var rec = new SourceRecord(OrE(r["source"]), "", "", "")
        {
            Folder = (Json.Parse(folderJson) as List<object> ?? new List<object>()).Select(Py.Str).ToList(),
            Type = Py.Str(r["type"]),
            Username = Py.Str(r["username"]),
            Address = OrE(r["address"]),
            Name = OrE(r["name"]),
        };
        foreach (var kv in Json.ParseObj(T(r["extra_json"]) ? Py.Str(r["extra_json"]) : "{}"))
            rec.Extra[kv.Key] = kv.Value as string ?? Py.Str(kv.Value);
        return rec;
    }

    /// <summary>Generated convention names for the distinct folder/platform/username combinations.</summary>
    (List<object>, List<object>) NamingSamples(Store st, JObj cfg, int limit = 400)
    {
        var namer = new Namer(cfg);
        var rows = st.Db.Query(
            "SELECT r.folder_json, r.folder, r.type, r.username, p.platform_id, MIN(r.address) AS address, " +
            "MIN(r.name) AS name, MIN(r.source) AS source, MIN(r.extra_json) AS extra_json, COUNT(*) AS n " +
            "FROM records r JOIN plan_accounts p USING (record_id) " +
            "GROUP BY r.folder_json, p.platform_id, r.username ORDER BY r.folder LIMIT ?", (long)limit);
        var out_ = new List<object>();
        var seen = new HashSet<(string, string)>();
        foreach (var r in rows)
        {
            var rec = RecordFrom(r, Py.Str(r["folder_json"]));
            var (name, notes) = namer.Build(rec, Py.Str(r["platform_id"]));
            if (!seen.Add((Py.Str(r["folder"]), name))) continue;
            out_.Add(Json.O(("folder", r["folder"]), ("platform", r["platform_id"]), ("name", name),
                            ("length", (long)Py.Len(name)), ("notes", string.Join("; ", notes))));
        }
        var unknown = Py.Sorted(namer.Unknown.ToList(), (a, b) => Py.Cmp(Py.Lower(a.Key), Py.Lower(b.Key)))
            .Select(kv => (object)Json.O(("word", kv.Key), ("code", kv.Value))).ToList();
        return (out_, unknown);
    }

    /// <summary>Every distinct folder name in the loaded data with the code it gets.</summary>
    static List<object> FolderCodes(Store st, JObj cfg)
    {
        var counts = new OrderedMap<string, long>(StringComparer.Ordinal);
        foreach (var r in st.Db.Query("SELECT folder_json, COUNT(*) FROM records GROUP BY folder_json"))
        {
            var levels = (Json.Parse(Py.Str(r[0])) as List<object> ?? new List<object>()).Select(Py.Str).Distinct();
            foreach (var level in levels) counts[level] = counts.GetValueOrDefault(level) + Convert.ToInt64(r[1]);
        }
        return new Namer(cfg).Suggest(counts).Cast<object>().ToList();
    }

    static JObj ConfigOf(object user, string what = "config is not valid")
    {
        if (user is not JObj u) throw new UiError("config must be a JSON object");
        try { return Config.FromDict(u); }
        catch (UiError) { throw; }
        catch (Exception exc) { throw new UiError($"{what}: {exc.Message}"); }
    }

    public object ApiNamingPreview(JObj body)
    {
        var cfg = ConfigOf(G(body, "config"));
        if (!DbExists(DbPath))
            return Json.O(("samples", new List<object>()), ("unknown", new List<object>()), ("folder_codes", new List<object>()));
        var st = OpenStore();
        try
        {
            var (samples, unknown) = NamingSamples(st, cfg);
            var folderCodes = FolderCodes(st, cfg);
            return Json.O(("samples", samples), ("unknown", unknown), ("folder_codes", folderCodes));
        }
        finally { st.Close(); }
    }

    static readonly string[] ValueFields = { "address_domain", "type", "platform" };
    const int MaxLayerValues = 300;

    /// <summary>The distinct values of one account detail in the loaded records, with how many accounts have
    /// each and a suggested 1-4 letter code. field: column:&lt;source column&gt;, address_domain, type or platform.</summary>
    public object ApiRulesValues(JObj body)
    {
        var field = Py.Strip(OrE(G(body, "field")));
        if (!(field.StartsWith("column:", StringComparison.Ordinal) && Py.Strip(field.Substring(7)).Length > 0) && !ValueFields.Contains(field))
            throw new UiError("Pick a source column or account detail first.");
        var user = G(body, "config");
        var cfg = user is JObj u ? Config.FromDict(u) : LoadConfig();
        var counts = new OrderedMap<string, (string V, long N)>(StringComparer.Ordinal);
        long empty = 0;
        if (DbExists(DbPath))
        {
            List<DbRow> rows;
            var st = OpenStore();
            try
            {
                rows = st.Db.Query("SELECT r.address, r.type, r.username, r.extra_json, p.platform_id " +
                                   "FROM records r LEFT JOIN plan_accounts p USING (record_id)");
            }
            finally { st.Close(); }
            var want = field.StartsWith("column:", StringComparison.Ordinal) ? Py.Lower(Py.Strip(field.Substring(7))) : "";
            foreach (var r in rows)
            {
                string v;
                if (want.Length > 0)
                {
                    var extra = Json.ParseObj(T(r["extra_json"]) ? Py.Str(r["extra_json"]) : "{}");
                    v = extra.Where(kv => Py.Lower(kv.Key) == want).Select(kv => Py.Str(kv.Value)).FirstOrDefault() ?? "";
                }
                else if (field == "address_domain") v = Naming.AddressDomain(Py.Str(r["address"]));
                else if (field == "platform") v = OrE(r["platform_id"]);
                else v = OrE(r["type"]);
                v = Transform.CleanLine(v);
                if (string.IsNullOrEmpty(v))
                {
                    empty++;
                    continue;
                }
                var key = Py.Lower(v);
                var c = counts.GetValueOrDefault(key, (v, 0));
                counts[key] = (c.V, c.N + 1);
            }
        }
        var namer = new Namer(cfg);
        var values = new List<object>();
        var byCode = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (v, n) in Py.Sorted(counts.Values.ToList(), (a, b) => a.N != b.N ? b.N.CompareTo(a.N) : Py.Cmp(Py.Lower(a.V), Py.Lower(b.V))))
        {
            var pairs = namer.LevelCodes(field == "address_domain" ? v.Split('.')[0] : v);
            var codes = pairs.Select(p => p.Code).Where(c => !string.IsNullOrEmpty(c)).ToList();
            var code = codes.Count == 1 ? codes[0] : Py.Head(string.Concat(codes.Select(c => Naming.CodePoints(c)[0])), 4);
            var row = Json.O(("value", v), ("accounts", n), ("code", Py.Upper(code)), ("clash", ""));
            if (byCode.TryGetValue(Py.Str(row["code"]), out var other)) row["clash"] = other;
            byCode.TryAdd(Py.Str(row["code"]), v);
            values.Add(row);
        }
        return Json.O(("field", field), ("values", values.Take(MaxLayerValues).ToList()), ("distinct", (long)values.Count),
                      ("empty", empty), ("too_many", values.Count > MaxLayerValues));
    }

    static readonly string[] PreviewKinds = { "safes", "members", "platforms", "accounts" };

    public object ApiSafesPreview(JObj body)
    {
        var b = body.Copy();
        b["kind"] = "safes";
        return ApiRulesPreview(b);
    }

    sealed class Saved
    {
        public Dictionary<string, JObj> Accounts = new(StringComparer.Ordinal);
        public Dictionary<string, JObj> Safes = new(StringComparer.Ordinal);
        public Dictionary<(string, string), JObj> Members = new();
        public Dictionary<string, object> SourceAddress;
    }

    /// <summary>What a mapping rules page's settings would give, before they are saved. Writes nothing.</summary>
    public object ApiRulesPreview(JObj body)
    {
        var kindObj = Py.Or(G(body, "kind"), "safes");
        var kind = kindObj as string;
        if (kind == null || !PreviewKinds.Contains(kind)) throw new UiError($"unknown preview {Py.Str(kindObj)}");
        var user = G(body, "config");
        if (G(body, "patch") is JObj patch)
        {
            var c = LoadConfig();
            c.Update(patch);
            user = c;
        }
        var cfg = ConfigOf(user);
        CheckSettings(cfg);
        CheckRoles(cfg);
        if (!DbExists(DbPath))
            return Json.O(("kind", kind), ("rows", new List<object>()), ("folder_codes", new List<object>()), ("safes", 0L),
                          ("accounts", 0L), ("total_rows", 0L));
        var limit = Math.Max(1, Math.Min(IntOf(Py.Or(G(body, "limit"), 500L)), 2000));
        var st = OpenStore();
        Plan plan;
        var saved = new Saved();
        List<object> folderCodes;
        try
        {
            try { plan = st.Plan(cfg); }
            catch (PyReError exc) { throw new UiError($"A pattern on this page is not valid: {exc.Message}"); }
            foreach (var r in st.Db.Query("SELECT * FROM plan_accounts")) saved.Accounts[Py.Str(r["record_id"])] = r.ToJObj();
            foreach (var r in st.Db.Query("SELECT * FROM plan_safes")) saved.Safes[Py.Str(r["safe_name"])] = r.ToJObj();
            foreach (var r in st.Db.Query("SELECT * FROM plan_members"))
                saved.Members[(Py.Lower(Py.Str(r["safe_name"])), Py.Lower(OrE(r["source_member"])))] = r.ToJObj();
            if (kind == "accounts")
            {
                saved.SourceAddress = new Dictionary<string, object>(StringComparer.Ordinal);
                foreach (var r in st.Db.Query("SELECT record_id, address FROM records")) saved.SourceAddress[Py.Str(r[0])] = r[1];
            }
            folderCodes = kind == "safes" ? FolderCodes(st, cfg) : new List<object>();
        }
        finally { st.Close(); }
        var rows = kind switch
        {
            "safes" => PreviewSafes(plan, cfg, saved),
            "members" => PreviewMembers(plan, saved),
            "platforms" => PreviewPlatforms(plan, saved),
            _ => PreviewAccounts(plan, cfg, saved),
        };
        return Json.O(("kind", kind), ("rows", rows.Take((int)limit).Cast<object>().ToList()), ("total_rows", (long)rows.Count),
                      ("safes", (long)plan.Safes.Count), ("accounts", (long)plan.Accounts.Count), ("folder_codes", folderCodes));
    }

    static int CmpLower(string a, string b) => Py.Cmp(Py.Lower(a ?? ""), Py.Lower(b ?? ""));

    static List<JObj> PreviewSafes(Plan plan, JObj cfg, Saved saved)
    {
        var settings = new Dictionary<string, JObj>(StringComparer.Ordinal);
        foreach (var kv in plan.Safes)
        {
            var (name, info) = (kv.Key, kv.Value);
            var b = Transform.SafeSettings(name, info, cfg);
            string keeps;
            if (Py.Strip(Py.Str(b.Get("numberOfVersionsRetention", ""))).Length > 0) keeps = $"{Py.Str(b["numberOfVersionsRetention"])} versions";
            else if (Py.Strip(Py.Str(b.Get("numberOfDaysRetention", ""))).Length > 0) keeps = $"{Py.Str(b["numberOfDaysRetention"])} days";
            else keeps = "";
            settings[name] = Json.O(("cpm", OrV(b.Get("managingCPM", ""))), ("keeps", keeps), ("description", OrV(b.Get("description", ""))),
                ("issues", string.Join("; ", Py.Sorted(info.Issues))), ("valid", info.Valid), ("accounts", (long)info.Accounts));
        }
        var savedSafe = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var a in saved.Accounts.Values)
        {
            var folder = Py.Str(a["folder"]);
            if (!savedSafe.TryGetValue(folder, out var set)) savedSafe[folder] = set = new HashSet<string>(StringComparer.Ordinal);
            set.Add(Py.Str(a["target_safe"]));
        }
        var groups = new OrderedMap<(string Folder, string Safe), (long Accounts, HashSet<string> How)>();
        foreach (var p in plan.Accounts)
        {
            var key = (p.Rec.FolderPath, p.Safe);
            var g = groups.GetOrAdd(key, () => (0, new HashSet<string>(StringComparer.Ordinal)));
            g.How.Add(p.SafeSource);
            groups[key] = (g.Accounts + 1, g.How);
        }
        var rows = new List<JObj>();
        foreach (var kv in Py.Sorted(groups.ToList(), (a, b) =>
                 {
                     var c = CmpLower(a.Key.Folder, b.Key.Folder);
                     return c != 0 ? c : CmpLower(a.Key.Safe, b.Key.Safe);
                 }))
        {
            var (folder, safe) = kv.Key;
            var s = settings[safe];
            var before = savedSafe.GetValueOrDefault(folder);
            var old = saved.Safes.GetValueOrDefault(safe);
            var changed = new List<object>();
            if (before != null && !before.Contains(safe)) changed.Add("safe");
            if (old != null)
                foreach (var (key, col) in new[] { ("cpm", "managing_cpm"), ("keeps", "retention"), ("description", "description") })
                    if (!Py.Eq(OrV(old.Get(col)), s[key])) changed.Add(key);
            rows.Add(Json.O(("folder", folder), ("safe", safe), ("length", (long)Py.Len(safe)), ("accounts", kv.Value.Accounts),
                ("how", Strings(Py.Sorted(kv.Value.How))), ("cpm", s["cpm"]), ("keeps", s["keeps"]), ("description", s["description"]),
                ("issues", s["issues"]), ("valid", s["valid"]), ("changed", changed)));
        }
        return rows;
    }

    static List<JObj> PreviewMembers(Plan plan, Saved saved)
    {
        var rows = new List<JObj>();
        foreach (var kv in plan.Members)
        {
            var safe = kv.Key.Safe;
            var m = kv.Value;
            var sources = m.Sources is { Count: > 0 } ? m.Sources : new List<string> { m.SourceName };
            JObj old = null;
            foreach (var src in sources)
                old ??= saved.Members.GetValueOrDefault((Py.Lower(safe), Py.Lower(src ?? "")));
            var shown = string.Join(" | ", sources);
            if (m.Standard) shown = $"(standard member group {m.Template ?? ""})";
            var row = Json.O(("safe", safe), ("source", shown), ("standard", m.Standard), ("member_name", m.MemberName),
                ("member_type", m.MemberType), ("search_in", m.SearchIn), ("permission", m.Permission),
                ("role", T(m.Role) ? m.Role : "UNMAPPED"), ("accounts", (long)m.Accounts), ("directory_source", m.DirectorySource ?? ""),
                ("notes", string.Join("; ", m.Notes ?? new List<string>())));
            List<object> changed;
            if (old == null && (saved.Members.Count > 0 || m.Standard)) changed = new List<object> { "new" };
            else
            {
                changed = new List<object>();
                foreach (var (k, col) in new[] { ("member_name", "member_name"), ("role", "role"), ("search_in", "search_in"), ("member_type", "member_type") })
                    if (old != null && Differs(old.Get(col), row[k])) changed.Add(k);
            }
            row["changed"] = changed;
            rows.Add(row);
        }
        return Py.Sorted(rows, (a, b) =>
        {
            var c = CmpLower(Py.Str(a["safe"]), Py.Str(b["safe"]));
            return c != 0 ? c : CmpLower(a["member_name"] as string, b["member_name"] as string);
        });
    }

    sealed class PlatformGroup
    {
        public long Accounts, Changed, Errors;
        public HashSet<string> Folders = new(StringComparer.Ordinal);
    }

    static List<JObj> PreviewPlatforms(Plan plan, Saved saved)
    {
        var groups = new OrderedMap<(string Type, string Platform, string How), PlatformGroup>();
        foreach (var p in plan.Accounts)
        {
            var g = groups.GetOrAdd((p.Rec.Type, p.Platform, p.PlatformSource), () => new PlatformGroup());
            g.Accounts++;
            g.Folders.Add(p.Rec.FolderPath);
            g.Errors += p.Errors.Count > 0 ? 1 : 0;
            var old = saved.Accounts.GetValueOrDefault(p.Rec.RecordId);
            if (old != null && !Py.Eq(OrV(old.Get("platform_id")), p.Platform)) g.Changed++;
        }
        var rows = new List<JObj>();
        foreach (var kv in Py.Sorted(groups.ToList(), (a, b) =>
                 {
                     var c = CmpLower(a.Key.Type, b.Key.Type);
                     return c != 0 ? c : CmpLower(a.Key.Platform, b.Key.Platform);
                 }))
        {
            var g = kv.Value;
            var folders = Py.Sorted(g.Folders);
            rows.Add(Json.O(("type", kv.Key.Type), ("platform", kv.Key.Platform), ("how", kv.Key.How), ("accounts", g.Accounts),
                ("errors", g.Errors), ("moved", g.Changed),
                ("folders", string.Join("; ", folders.Take(3)) + (folders.Count > 3 ? $" and {folders.Count - 3} more" : "")),
                ("changed", g.Changed > 0 ? new List<object> { "platform" } : new List<object>())));
        }
        return rows;
    }

    static List<JObj> PreviewAccounts(Plan plan, JObj cfg, Saved saved)
    {
        var props = cfg.Obj("account_property_map") ?? new JObj();
        var rows = new List<JObj>();
        foreach (var p in plan.Accounts)
        {
            var old = saved.Accounts.GetValueOrDefault(p.Rec.RecordId);
            var extra = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in p.Rec.Extra) extra[Py.Lower(kv.Key)] = kv.Value;
            var shown = new List<string>();
            foreach (var kv in props)
            {
                var v = extra.GetValueOrDefault(Py.Lower(kv.Key), "");
                if (Py.Strip(v ?? "None").Length > 0) shown.Add($"{Py.Str(kv.Value)}={v ?? "None"}");
            }
            var srcAddr = saved.SourceAddress != null && saved.SourceAddress.TryGetValue(p.Rec.RecordId, out var sa) ? sa : p.Rec.Address;
            var row = Json.O(("record_id", p.Rec.RecordId), ("source_name", p.Rec.Name), ("address", p.Rec.Address),
                ("source_address", srcAddr), ("username", p.Rec.Username), ("safe", p.Safe), ("platform", p.Platform),
                ("account_name", p.AccountName), ("properties", string.Join("; ", shown)),
                ("notes", string.Join("; ", p.Errors.Concat(p.Warnings))));
            var changed = new List<object>();
            foreach (var k in new[] { "account_name", "address" })
                if (old != null && Differs(old.Get(k), row[k])) changed.Add(k);
            row["changed"] = changed;
            rows.Add(row);
        }
        return Py.Sorted(rows, (a, b) =>
        {
            bool ua = ((List<object>)a["changed"]).Count == 0, ub = ((List<object>)b["changed"]).Count == 0;
            if (ua != ub) return ua ? 1 : -1;
            var c = CmpLower(Py.Str(a["safe"]), Py.Str(b["safe"]));
            return c != 0 ? c : CmpLower(a["account_name"] as string, b["account_name"] as string);
        });
    }

    public object ApiConfigSave(JObj body)
    {
        var user = G(body, "config");
        if (G(body, "patch") is JObj patch)
        {
            // One settings page saves only its own keys on top of everything else.
            var c = LoadConfig();
            c.Update(patch);
            user = c;
        }
        if (user is not JObj) throw new UiError("config must be a JSON object");
        var tmp = Path.ChangeExtension(ConfigPath, ".tmp");
        PyFile.WriteText(tmp, Json.Dumps(user, 2));
        JObj cfg;
        int cleaned;
        try
        {
            cfg = Config.Load(tmp);
            cleaned = CleanSafeSettings(cfg);
            foreach (var rule in (cfg.List("group_rules") ?? new List<object>()).OfType<JObj>())
                if (!T(rule.Get("safe")) || !(T(rule.Get("group")) || T(rule.Get("group_pattern"))))
                    throw new UiError("Every group rule needs a group (or pattern) and a Safe.");
            foreach (var rule in (cfg.List("folder_rules") ?? new List<object>()).OfType<JObj>())
                if (!T(rule.Get("safe")) || !T(rule.Get("folder_prefix")))
                    throw new UiError("Every folder rule needs a folder and a Safe.");
            CheckRoles(cfg);
            CheckSettings(cfg);
        }
        catch (UiError)
        {
            File.Delete(tmp);
            throw;
        }
        catch (Exception exc)
        {
            File.Delete(tmp);
            throw new UiError($"config is not valid: {exc.Message}");
        }
        // Keep only what differs from the built-in defaults, so later default updates apply.
        PyFile.WriteText(tmp, Json.Dumps(Config.ConfigDiff(cfg), 2));
        File.Move(tmp, ConfigPath, overwrite: true);
        if (!DbExists(DbPath)) return Json.O(("saved", true), ("mapped", false), ("cleaned", (long)cleaned));
        var st = OpenStore();
        try { st.Map(cfg, ConfigPath); }
        finally { st.Close(); }
        return Json.O(("saved", true), ("mapped", true), ("cleaned", (long)cleaned));
    }

    public object ApiAccounts(JObj body)
    {
        var (where, pars) = BuildWhere(body);
        var sort = G(body, "sort") is string s && Sortable.Contains(s) ? s : "target_safe";
        var order = T(G(body, "desc")) ? "DESC" : "ASC";
        var page = Math.Max(0, IntOf(Py.Or(G(body, "page"), 0L)));
        var st = OpenStore();
        try
        {
            var total = st.Query($"SELECT COUNT(*) FROM accounts WHERE {where}", pars).Item2[0][0];
            var (cols, rows) = st.Query(
                "SELECT record_id, migrate, status, target_safe, platform_id, account_name, address, " +
                "username, secret_type, has_secret, source, folder, access_groups, notes, approved, source_type, " +
                "(SELECT r.name FROM records r WHERE r.record_id = accounts.record_id) AS source_name, " +
                "(SELECT r.address FROM records r WHERE r.record_id = accounts.record_id) AS source_address FROM accounts " +
                $"WHERE {where} ORDER BY {sort} {order}, record_id LIMIT ? OFFSET ?",
                pars.Concat(new object[] { (long)PageSize, page * PageSize }).ToList());
            var facets = new JObj();
            foreach (var (key, col) in FilterColumns)
                facets[key] = st.Query($"SELECT DISTINCT {col} FROM accounts ORDER BY 1").Item2.Select(r => r[0]).ToList();
            return Json.O(("total", total), ("page", page), ("page_size", (long)PageSize),
                          ("rows", rows.Select(r => (object)Zip(cols, r)).ToList()), ("facets", facets));
        }
        finally { st.Close(); }
    }

    public object ApiRecord(JObj body)
    {
        var rid = G(body, "id") ?? "";
        var st = OpenStore();
        try
        {
            var db = st.Db;
            var rec = db.One("SELECT * FROM records WHERE record_id = ?", rid);
            var plan = db.One("SELECT * FROM plan_accounts WHERE record_id = ?", rid);
            if (rec == null) throw new UiError("record not found", 404);
            var out_ = new JObj();
            foreach (var kv in rec.ToJObj()) if (kv.Key != "secret_enc") out_[kv.Key] = kv.Value;
            out_["extra"] = Json.Parse(Py.Str(out_.Pop("extra_json")));
            out_["notes_source"] = Json.Parse(Py.Str(out_.Pop("notes_json")));
            out_.Pop("folder_json");
            var planObj = plan?.ToJObj() ?? new JObj();
            out_["plan"] = planObj;
            out_["grants"] = db.Query("SELECT member, permission, member_type FROM grants WHERE record_id = ?", rid)
                .Select(r => (object)r.ToJObj()).ToList();
            out_["edits"] = db.Query("SELECT field, value, changed_utc, changed_by, reason FROM edits WHERE record_id = ?", rid)
                .Select(r => (object)r.ToJObj()).ToList();
            var appr = db.One("SELECT approved_utc, approved_by, reason FROM approvals WHERE record_id = ?", rid);
            out_["approval"] = appr != null && Py.Eq(planObj.Get("approved"), "Y") ? appr.ToJObj() : null;
            return out_;
        }
        finally { st.Close(); }
    }

    List<string> SelectedIds(Store st, JObj body)
    {
        if (T(G(body, "ids"))) return (G(body, "ids") as List<object> ?? new List<object>()).Select(Py.Str).ToList();
        var (where, pars) = BuildWhere(body);
        return st.SelectIds(where, pars);
    }

    public object ApiEdit(JObj body)
    {
        var values = G(body, "values") as JObj ?? new JObj();
        if (values.Keys.Any(k => !Editable.Contains(k)))
            throw new UiError("only Migrate, Safe, platform and account name can be changed");
        if (values.ContainsKey("migrate") && !(values["migrate"] is string m && m is "Y" or "N" or ""))
            throw new UiError("Migrate must be Y or N");
        var cleaned = new List<string>();
        foreach (var k in new[] { "target_safe", "platform_id", "account_name" })
            if (values.Get(k) is string s) values[k] = Line(s, cleaned);
        var st = OpenStore();
        List<string> ids;
        try
        {
            ids = SelectedIds(st, body);
            if (ids.Count == 0) throw new UiError("No accounts selected.");
            if (ids.Count > 1 && T(values.Get("account_name")) && Py.Lower(Py.Str(values["account_name"])) != "(none)")
                throw new UiError("Rename one account at a time.");
            var pairs = new OrderedPairs();
            foreach (var kv in values) pairs[kv.Key] = kv.Value == null ? null : Py.Str(kv.Value);
            st.SetEdits(ids, pairs, OrE(G(body, "reason")));
            st.Map(st.StoredConfig(), st.Meta("config_path"));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
        return Json.O(("changed", (long)ids.Count), ("cleaned", (long)cleaned.Count));
    }

    /// <summary>Approve the ticked accounts that need a look, or take the approval back.</summary>
    public object ApiApprove(JObj body)
    {
        var approve = !(body.Get("approve", true) is false);
        var st = OpenStore();
        List<string> ids;
        int n;
        try
        {
            ids = SelectedIds(st, body);
            if (ids.Count == 0) throw new UiError("No accounts selected.");
            n = st.Approve(ids, approve, Line(OrE(G(body, "reason")), new List<string>()));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
        return Json.O(("changed", (long)n), ("selected", (long)ids.Count));
    }

    public object ApiSafes(JObj _)
    {
        var st = OpenStore();
        List<string> cols, mcols;
        List<object[]> rows, mrows;
        List<JObj> edits;
        Dictionary<string, JObj> overrides, safeOv;
        List<DbRow> grants;
        References refs;
        try
        {
            (cols, rows) = st.Query(
                "SELECT s.*, (SELECT group_concat(folder, ' | ') FROM (SELECT DISTINCT folder FROM plan_accounts a " +
                "WHERE a.target_safe = s.safe_name ORDER BY folder)) AS source_folders FROM plan_safes s ORDER BY safe_name");
            (mcols, mrows) = st.Query("SELECT * FROM plan_members ORDER BY safe_name, member_name");
            edits = st.MemberEdits();
            overrides = st.MemberOverrides();
            safeOv = st.SafeOverrides();
            // Users waiting for your decision are listed on their own page, not here.
            grants = st.Db.Query("SELECT member, max(member_type) AS member_type, COUNT(DISTINCT record_id) AS n " +
                                 "FROM grants WHERE coalesce(basis, '') <> 'undecided' GROUP BY lower(member)");
            refs = st.References();
        }
        finally { st.Close(); }
        var cfg = LoadConfig();
        var roles = Strings(Config.AllRoles(cfg).Keys);
        var members = mrows.Select(r => Zip(mcols, r)).ToList();
        var dirs = members.Select(m => m.Get("search_in")).Where(T).Select(Py.Str).Append("Vault").Distinct();
        return Json.O(("safes", rows.Select(r => (object)Zip(cols, r)).ToList()), ("members", members.Cast<object>().ToList()),
            ("member_edits", edits.Cast<object>().ToList()),
            ("safe_overrides", Py.Sorted(safeOv.Values.ToList(), (a, b) => Py.Cmp(OrE(a.Get("changed_utc")), OrE(b.Get("changed_utc")))).Cast<object>().ToList()),
            ("people", People(members, grants, overrides, cfg, refs)), ("roles", roles), ("directories", Strings(Py.Sorted(dirs))),
            ("known_members", Strings(Py.Sorted(members.Select(m => Py.Str(m["member_name"])).Distinct().ToList(), (a, b) => Py.Cmp(Py.Lower(a), Py.Lower(b))))));
    }

    /// <summary>One row per member (user, group or role), with the Safes it is on. Members from the
    /// export whose accounts are not uploaded are listed too, with no Safes.</summary>
    static List<object> People(List<JObj> members, List<DbRow> grants, Dictionary<string, JObj> overrides, JObj cfg, References refs = null)
    {
        var inExport = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var r in grants) inExport[Py.Lower(Py.Str(r["member"]))] = r["n"];
        var people = new OrderedMap<string, JObj>(StringComparer.Ordinal);
        foreach (var m in members)
        {
            // A merged row lists several source members ("CORP\\X | LEGACY\\X"); each one is
            // its own person here, so a change (keyed by source member) reaches the right one.
            foreach (var source in Py.Str(Py.Or(m["source_member"], m["member_name"])).Split(" | "))
            {
                var key = Py.Lower(source);
                var p = people.GetOrAdd(key, () => Json.O(("key", key), ("source_member", source), ("member_name", m["member_name"]),
                    ("member_type", m["member_type"]), ("search_in", m["search_in"]), ("directory_source", m["directory_source"]),
                    ("export_accounts", inExport.GetValueOrDefault(key, 0L)), ("edited", overrides.ContainsKey(key)),
                    ("override", overrides.GetValueOrDefault(key)), ("safes", new List<object>())));
                ((List<object>)p["safes"]).Add(Json.O(("safe_name", m["safe_name"]), ("role", m["role"]), ("accounts", m["accounts"]),
                    ("source_permission", m["source_permission"]), ("notes", m["notes"])));
            }
        }
        var defaultType = Transform.NormalizeMemberType(cfg.Get("default_member_type"));
        foreach (var r in grants)
        {
            var member = Py.Str(r["member"]);
            var key = Py.Lower(member);
            if (people.ContainsKey(key)) continue;
            var mtype = Transform.NormalizeMemberType(r["member_type"], defaultType);
            var (name, searchIn, src) = Transform.TargetFor(member, cfg, mtype, refs);
            var m = Transform.ApplyMemberOverride(new MemberInfo
            {
                SourceName = member, MemberName = name, MemberType = mtype, Type = mtype, SearchIn = searchIn,
                DirectorySource = T(src) ? src : "default", Notes = null,
            }, overrides.GetValueOrDefault(key));
            people[key] = Json.O(("key", key), ("source_member", member), ("member_name", m.MemberName), ("member_type", m.MemberType),
                ("search_in", m.SearchIn), ("directory_source", m.DirectorySource), ("export_accounts", r["n"]),
                ("edited", overrides.ContainsKey(key)), ("override", overrides.GetValueOrDefault(key)), ("safes", new List<object>()));
        }
        return Py.Sorted(people.Values.ToList(), (a, b) => Py.Cmp(Py.Lower(OrE(a["member_name"])), Py.Lower(OrE(b["member_name"]))))
            .Cast<object>().ToList();
    }

    /// <summary>Change one member's memberName, memberType or searchIn everywhere (kept across re-mapping).</summary>
    public object ApiMembersChange(JObj body)
    {
        var key = Py.Strip(OrE(G(body, "key")));
        if (key.Length == 0) throw new UiError("Pick a member first.");
        var undo = T(G(body, "undo"));
        var cleaned = new List<string>();
        var name = Line(G(body, "member_name"), cleaned);
        var mtype = Py.Strip(OrE(G(body, "member_type")));
        if (mtype.Length > 0 && Py.Lower(mtype) is not ("user" or "group" or "role"))
            throw new UiError("Member type must be User, Group or Role.");
        var si = G(body, "search_in");
        var searchIn = si == null ? null : Line(si, cleaned);
        if (!undo && name.Length == 0) throw new UiError("The member name can't be empty.");
        var st = OpenStore();
        try
        {
            st.SetMemberOverride(key, name.Length > 0 ? name : null, mtype.Length > 0 ? Transform.NormalizeMemberType(mtype) : null,
                                 searchIn, OrE(G(body, "reason")), undo);
            st.Map(st.StoredConfig(), st.Meta("config_path"));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
        return Json.O(("changed", 1L), ("cleaned", (long)cleaned.Count));
    }

    /// <summary>Rename one Safe, or change its description, location, CPM, retention, OLAC or auto purge.</summary>
    public object ApiSafesChange(JObj body)
    {
        var key = Py.Strip(OrE(G(body, "key")));
        var current = Py.Strip(OrE(G(body, "current")));
        if (key.Length == 0) throw new UiError("Pick a Safe first.");
        var undo = T(G(body, "undo"));
        var cfg = LoadConfig();
        var raw = Py.Or(G(body, "settings"), new JObj()) as JObj ?? new JObj();
        var settings = new JObj();
        var cleaned = new List<string>();
        var newName = Py.Strip(OrE(raw.Get("new_name")));
        if (newName.Length > 0 && Py.Lower(newName) != Py.Lower(key))
        {
            var (clean, valid, issues) = Transform.SanitizeSafeName(newName, cfg);
            if (!valid) throw new UiError($"The Safe name '{newName}' can't be used: {string.Join("; ", issues)}.");
            settings["new_name"] = clean;
        }
        foreach (var k in new[] { "description", "location", "managingCPM" })
        {
            var v = Line(raw.Get(k), cleaned);
            if (v.Length > 0) settings[k] = v;
        }
        if (Py.Len(OrE(settings.Get("description"))) > 100) throw new UiError("The description can be at most 100 characters.");
        if (Py.Len(OrE(settings.Get("managingCPM"))) > 20) throw new UiError("The CPM name can be at most 20 characters.");
        var kind = OrE(raw.Get("retention_kind"));
        var value = Py.Strip(OrE(raw.Get("retention_value")));
        if (kind.Length > 0 && value.Length > 0)
        {
            long n = 0;
            if (!Py.IsDigit(value) || !long.TryParse(value, out n) || !(0 < n && n <= (kind == "versions" ? 999 : 3650)))
                throw new UiError("Keep: type a whole number (versions 1-999, days 1-3650).");
            settings[kind == "versions" ? "numberOfVersionsRetention" : "numberOfDaysRetention"] = n;
        }
        foreach (var k in new[] { "olacEnabled", "autoPurgeEnabled" })
        {
            var v = Py.Lower(OrE(raw.Get(k)));
            if (v is "true" or "false") settings[k] = v == "true";
        }
        if (!undo && settings.Count == 0) undo = true;                 // nothing differs from the rules
        var target = undo ? key : OrE(settings.Get("new_name", key));
        var st = OpenStore();
        try
        {
            st.SetSafeOverride(key, settings, OrE(G(body, "reason")), undo, current.Length > 0 ? current : key, target);
            st.Map(st.StoredConfig(), st.Meta("config_path"));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
        return Json.O(("changed", 1L), ("safe_name", target), ("cleaned", (long)cleaned.Count));
    }

    /// <summary>Add a member to, or remove one from, any number of Safes (kept across re-mapping).</summary>
    public object ApiMembersEdit(JObj body)
    {
        var action = G(body, "action");
        var cleaned = new List<string>();
        var name = Line(G(body, "member_name"), cleaned);
        var pairsObj = Py.Or(G(body, "pairs"), (G(body, "safes") as List<object> ?? new List<object>())
            .Select(s => (object)new List<object> { s, name }).ToList());
        var pairs = pairsObj as List<object>;
        if (pairs != null)
            pairs = pairs.Select(p => p is List<object> { Count: 2 } l
                ? new List<object> { l[0], Py.Eq(action, "add") ? Line(l[1], cleaned) : l[1] } : p).ToList();
        if (pairs == null || pairs.Count == 0 || !pairs.All(p => p is List<object> { Count: 2 } l && T(l[0]) && T(l[1])))
            throw new UiError("Tick at least one Safe and name the member.");
        var role = Py.Strip(OrE(G(body, "role")));
        if (Py.Eq(action, "add") && Config.ResolveRole(role, LoadConfig()).Length == 0)
            throw new UiError("Pick the member's role.");
        var st = OpenStore();
        int n = 0;
        try
        {
            var byMember = new OrderedMap<string, List<string>>(StringComparer.Ordinal);
            foreach (List<object> p in pairs) byMember.GetOrAdd(Py.Str(p[1]), () => new List<string>()).Add(Py.Str(p[0]));
            foreach (var kv in byMember)
                n += st.SetMemberEdits(kv.Value, kv.Key, action as string ?? Py.Str(action), Line(G(body, "search_in"), cleaned),
                                       T(G(body, "member_type")) ? Transform.NormalizeMemberType(G(body, "member_type")) : "",
                                       role, OrE(G(body, "reason")));
            st.Map(st.StoredConfig(), st.Meta("config_path"));
        }
        catch (StoreError exc) { throw new UiError(exc.Message); }
        finally { st.Close(); }
        return Json.O(("changed", (long)n), ("cleaned", (long)cleaned.Count));
    }

    public object ApiExtract(JObj body)
    {
        var name = Py.Strip(string.Concat(Naming.CodePoints(OrE(G(body, "name"))).Where(c => Py.IsAlnum(c) || c is "-" or "_" or " ")));
        if (name.Length == 0) name = DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        var out_ = Path.Combine(Output, name);
        if (Directory.Exists(out_) || File.Exists(out_))
        {
            if (!T(G(body, "replace"))) throw new UiError($"An output called '{name}' already exists. Pick another name or tick Replace.");
            Directory.Delete(out_, true);
        }
        var include = T(G(body, "include_secrets"));
        if (include && !Py.Eq(G(body, "confirm"), "INCLUDE SECRETS")) throw new UiError("Type INCLUDE SECRETS to confirm.");
        string where = null;
        IReadOnlyList<object> pars = Array.Empty<object>();
        var label = "everything";
        if (Py.Eq(G(body, "scope"), "filter"))
        {
            List<object> p;
            (where, p) = BuildWhere(body);
            pars = p;
            label = Json.Dumps(Json.O(("view", G(body, "view")), ("filters", G(body, "filters"))));
        }
        var st = OpenStore();
        JObj counts;
        List<string> files;
        try { (_, counts, files) = Store.RunExtract(st, out_, where, include, pars, label); }
        catch (Exception exc) when (exc is StoreError or ProtectError)
        {
            try { if (Directory.Exists(out_)) Directory.Delete(out_, true); } catch (Exception) { }
            throw new UiError(exc.Message);
        }
        finally { st.Close(); }
        var rel = files.Select(f => (object)Path.GetRelativePath(out_, f)).ToList();
        rel.Add("manifest.json");
        return Json.O(("name", name), ("path", out_), ("counts", counts), ("files", rel));
    }

    public object ApiOutputDelete(JObj body)
    {
        var name = Py.Str(G(body, "name") ?? "");
        var path = ResolvePath(Path.Combine(Output, name));
        if (!SamePath(Path.GetDirectoryName(path) ?? "", Output) || !Directory.Exists(path)) throw new UiError("no such output");
        var what = G(body, "what") ?? "upload";
        var target = Py.Eq(what, "upload") ? Path.Combine(path, "upload") : path;
        if (Directory.Exists(target) || File.Exists(target))
        {
            if (Directory.Exists(target))
                foreach (var f in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).OrderByDescending(x => x, StringComparer.Ordinal))
                    SecureDelete(f);
            try { Directory.Delete(target, true); } catch (Exception) { }
        }
        return Json.O(("deleted", target));
    }

    public object ApiAudit(JObj _)
    {
        var st = OpenStore();
        try
        {
            var db = st.Db;
            var (cols, rows) = st.Query("SELECT ts, user, action, detail FROM audit ORDER BY id DESC LIMIT 300");
            var (ecols, erows) = st.Query("SELECT * FROM edits ORDER BY changed_utc DESC LIMIT 500");
            List<object> Dicts(string sql) => db.Query(sql).Select(r => (object)r.ToJObj()).ToList();
            var summary = Json.O(
                ("entries", Count(db, "SELECT COUNT(*) FROM audit")),
                ("first", db.Scalar("SELECT MIN(ts) FROM audit")),
                ("last", db.Scalar("SELECT MAX(ts) FROM audit")),
                ("by_action", Dicts("SELECT action, COUNT(*) AS count, MAX(ts) AS last FROM audit GROUP BY action ORDER BY 2 DESC")),
                ("by_user", Dicts("SELECT user, COUNT(*) AS count, MIN(ts) AS first, MAX(ts) AS last FROM audit GROUP BY user ORDER BY 2 DESC")),
                ("edits", Count(db, "SELECT COUNT(*) FROM edits")),
                ("edited_accounts", Count(db, "SELECT COUNT(DISTINCT record_id) FROM edits")),
                ("edits_by_field", Dicts("SELECT field, COUNT(*) AS count FROM edits GROUP BY field ORDER BY 2 DESC")));
            return Json.O(("audit", rows.Select(r => (object)Zip(cols, r)).ToList()),
                          ("edits", erows.Select(r => (object)Zip(ecols, r)).ToList()), ("summary", summary));
        }
        finally { st.Close(); }
    }

    /// <summary>Every row of the activity log or of the changes, or the Safe naming convention, as CSV text.</summary>
    public string ExportCsv(string what)
    {
        var st = OpenStore();
        List<object> cols;
        List<List<object>> rows;
        try
        {
            if (what == "convention")
            {
                var cfg = LoadConfig();
                (cols, rows) = Writers.ConventionRows(st.Plan(cfg), cfg);
            }
            else
            {
                var (c, r) = what == "audit"
                    ? st.Query("SELECT id, ts, user, host, action, detail FROM audit ORDER BY id")
                    : st.Query("SELECT record_id, field, value, changed_utc, changed_by, reason FROM edits ORDER BY changed_utc, record_id");
                cols = c.Cast<object>().ToList();
                rows = r.Select(x => x.ToList()).ToList();
            }
            st.Audit("export_log", Json.O(("what", what), ("rows", (long)rows.Count)));
            st.Db.Commit();
        }
        finally { st.Close(); }
        var sw = new StringWriter();
        var w = new Csv.Writer(sw);
        w.WriteRow(cols);
        foreach (var r in rows) w.WriteRow(CsvSafe.Row(r));
        return "\ufeff" + sw;
    }

    public object ApiOpenFolder(JObj body)
    {
        var which = G(body, "which") ?? "inbox";
        string path = which switch { "inbox" => Inbox, "output" => Output, "workspace" => Ws, _ => null };
        if (path == null) throw new UiError("unknown folder");
        var sub = G(body, "name");
        if (T(sub) && Py.Eq(which, "output"))
        {
            var cand = ResolvePath(Path.Combine(Output, Py.Str(sub)));
            if (SamePath(Path.GetDirectoryName(cand) ?? "", Output) && Directory.Exists(cand)) path = cand;
        }
        bool opened = false;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();
                WinFront.BringToFront(path);      // otherwise it opens behind the browser
                opened = true;
            }
            else if (Environment.GetEnvironmentVariable("IMW_UI_NO_OPEN") != "1")
            {
                var tool = OperatingSystem.IsMacOS() ? "open" : "xdg-open";
                if (Which(tool) != null)
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(tool) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                    psi.ArgumentList.Add(path);
                    System.Diagnostics.Process.Start(psi)?.Dispose();
                    opened = true;
                }
            }
        }
        catch (Exception exc) when (exc is IOException or System.ComponentModel.Win32Exception)
        {
            throw new UiError($"Could not open the folder: {exc.Message}");
        }
        return Json.O(("path", path), ("opened", opened));
    }

    public static string Which(string tool)
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (dir.Length == 0) continue;
            var p = Path.Combine(dir, tool);
            if (File.Exists(p)) return p;
        }
        return null;
    }

    /// <summary>How each distinct member in the loaded data comes out with the given settings.</summary>
    public object ApiMembersPreview(JObj body)
    {
        var cfg = LoadConfig();
        if (G(body, "patch") is JObj patch) cfg.Update(patch);
        try
        {
            cfg = Config.FromDict(cfg);
            CheckSettings(cfg);
        }
        catch (UiError) { throw; }
        catch (Exception exc) { throw new UiError($"settings are not valid: {exc.Message}"); }
        if (!DbExists(DbPath)) return Json.O(("members", new List<object>()));
        List<DbRow> rows;
        References refs;
        var st = OpenStore();
        try
        {
            rows = st.Db.Query("SELECT member, member_type, COUNT(DISTINCT record_id) AS n FROM grants " +
                               "GROUP BY lower(member), member_type ORDER BY 3 DESC LIMIT 300");
            refs = st.References();
        }
        finally { st.Close(); }
        JObj before;
        try { before = Config.FromDict(LoadConfig()); }
        catch (Exception) { before = null; }
        var out_ = new List<object>();
        foreach (var r in rows)
        {
            var member = Py.Str(r["member"]);
            var mtype = Transform.NormalizeMemberType(r["member_type"], Transform.NormalizeMemberType(cfg.Get("default_member_type")));
            var (name, searchIn, src) = Transform.TargetFor(member, cfg, mtype, refs);
            var changed = new List<object>();
            if (before != null)
            {
                var oldType = Transform.NormalizeMemberType(r["member_type"], Transform.NormalizeMemberType(before.Get("default_member_type")));
                var (oldName, oldIn, _) = Transform.TargetFor(member, before, oldType, refs);
                foreach (var (k, a, b) in new[] { ("member_name", oldName, name), ("search_in", oldIn, searchIn), ("type", oldType, mtype) })
                    if ((a ?? "") != (b ?? "")) changed.Add(k);
            }
            out_.Add(Json.O(("source", r["member"]), ("type", mtype), ("accounts", r["n"]), ("member_name", name),
                ("search_in", searchIn), ("directory_source", T(src) ? src : "(not matched; default)"), ("changed", changed)));
        }
        return Json.O(("members", out_));
    }

    public object ApiPing(JObj _) => Json.O(("ok", true));

    // ---------------------------------------------------------------- session

    public object ApiSession(JObj _) =>
        Json.O(("locked", !Unlocked), ("user", Auth.Display), ("kind", Auth.Kind), ("idle_minutes", (long)(IdleSeconds / 60)),
               ("wait", (long)Math.Max(0, Math.Truncate(WaitUntil - Now()))));

    public void AuditIfDb(string action, JObj detail)
    {
        if (!DbExists(DbPath)) return;
        try
        {
            var st = OpenStore();
            try
            {
                st.Audit(action, detail);
                st.Db.Commit();
            }
            finally { st.Close(); }
        }
        catch (Exception exc) { Log.Error($"audit failed: {exc.Message}"); }    // never block sign-in on logging
    }

    public object ApiUnlock(JObj body)
    {
        var now = Now();
        if (now < WaitUntil)
            throw new UiError($"Too many wrong passwords. Try again in {(long)Math.Truncate(WaitUntil - now) + 1} seconds.", 429);
        var password = OrE(G(body, "password"));
        if (password.Length > 0 && Auth.Check(password))
        {
            (Unlocked, Failures, LastSeen) = (true, 0, now);
            AuditIfDb("sign_in", Json.O(("user", Auth.Display)));
            return Json.O(("ok", true));
        }
        Failures++;
        if (Failures >= MaxFailures) WaitUntil = now + Math.Min(300, 30 * Math.Pow(2, Failures - MaxFailures));
        AuditIfDb("sign_in_failed", Json.O(("user", Auth.Display), ("failures", (long)Failures)));
        throw new UiError("That password is not right for " + Auth.Display + ".");
    }

    public object ApiLock(JObj _)
    {
        Unlocked = false;
        AuditIfDb("lock", Json.O(("reason", "button")));
        return Json.O(("locked", true));
    }

    public object ApiEnd(JObj body)
    {
        // Ending is one click (the page sends END SESSION); deleting the database needs DELETE DB typed.
        var delete = T(G(body, "delete_db"));
        if (delete)
        {
            if (!Py.Eq(G(body, "confirm"), "DELETE DB")) throw new UiError("Type DELETE DB to confirm deleting the database.");
        }
        else if (!Py.Eq(G(body, "confirm"), "END SESSION")) throw new UiError("Confirm with the End session button.");
        if (!delete) AuditIfDb("end_session", Json.O(("database", "kept")));
        // End the session first: whatever happens to the files, nobody stays signed in and the server stops.
        (Sid, Unlocked) = (null, false);
        if (Shutdown != null) _ = Task.Delay(500).ContinueWith(_ => Shutdown());
        bool deleted = false;
        var failed = new List<object>();
        if (delete)
        {
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var f = DbPath + suffix;
                try
                {
                    if (File.Exists(f))
                    {
                        SecureDelete(f);
                        deleted = true;
                    }
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)   // e.g. Windows still holds a lock
                {
                    Log.Warning($"could not delete {f}: {exc.Message}");
                    failed.Add(Path.GetFileName(f));
                }
            }
        }
        return Json.O(("ended", true), ("database_deleted", deleted && failed.Count == 0), ("not_deleted", failed));
    }

    /// <summary>Routes, and the ones allowed while locked.</summary>
    public Dictionary<(string, string), Func<JObj, object>> Routes() => new()
    {
        [("GET", "/api/state")] = ApiState, [("POST", "/api/ingest")] = ApiIngest,
        [("POST", "/api/inbox/delete")] = ApiInboxDelete, [("GET", "/api/config")] = ApiConfigGet,
        [("POST", "/api/config")] = ApiConfigSave, [("POST", "/api/accounts")] = ApiAccounts,
        [("POST", "/api/record")] = ApiRecord, [("POST", "/api/edit")] = ApiEdit,
        [("GET", "/api/safes")] = ApiSafes, [("POST", "/api/extract")] = ApiExtract,
        [("POST", "/api/output/delete")] = ApiOutputDelete, [("GET", "/api/audit")] = ApiAudit,
        [("POST", "/api/naming/preview")] = ApiNamingPreview, [("POST", "/api/safes/preview")] = ApiSafesPreview,
        [("POST", "/api/rules/preview")] = ApiRulesPreview, [("POST", "/api/rules/values")] = ApiRulesValues,
        [("POST", "/api/approve")] = ApiApprove, [("POST", "/api/open")] = ApiOpenFolder,
        [("GET", "/api/undecided")] = ApiUndecided, [("POST", "/api/decide")] = ApiDecide,
        [("POST", "/api/lock")] = ApiLock, [("POST", "/api/end")] = ApiEnd, [("POST", "/api/ping")] = ApiPing,
        [("POST", "/api/members/preview")] = ApiMembersPreview, [("POST", "/api/members/edit")] = ApiMembersEdit,
        [("POST", "/api/members/change")] = ApiMembersChange, [("POST", "/api/safes/change")] = ApiSafesChange,
    };

    public Dictionary<(string, string), Func<JObj, object>> OpenRoutes() => new()
    {
        [("GET", "/api/session")] = ApiSession, [("POST", "/api/unlock")] = ApiUnlock,
    };

    /// <summary>POST routes whose method never reads the body (Python passes any JSON value to them).</summary>
    public static readonly HashSet<string> BodyFree = new(StringComparer.Ordinal) { "/api/ping", "/api/lock" };
}
