using System.Security.Cryptography;

namespace Imw.Core;

/// <summary>Output files: review CSVs (no secrets) and upload CSVs (API body fields). Port of imw/writers.py.</summary>
public static class Writers
{
    public const string Version = "2.0.0";

    // Upload CSV columns, named and ordered like the Privilege Cloud (ISPSS) bulk-upload samples:
    // (CSV column, field it holds). The optional columns are added at the end only when a value is set.
    public static readonly (string Col, string Field)[] SafeColumns = { ("SafeName", "safeName"), ("Description", "description"),
        ("Location", "location"), ("ManagingCPM", "managingCPM"), ("NumberOfDaysRetention", "numberOfDaysRetention"),
        ("NumberOfVersionsRetention", "numberOfVersionsRetention") };
    public static readonly (string Col, string Field)[] SafeOptional = { ("OlacEnabled", "olacEnabled"), ("AutoPurgeEnabled", "autoPurgeEnabled") };
    public static readonly string[] MemberColumns = { "SafeName", "MemberName", "MemberType" };   // then one column per permission
    public static readonly string[] MemberOptional = { "SearchIn" };
    public static readonly string[] AccountColumns = { "Name", "SafeName", "PlatformId", "UserName", "Address", "SecretType", "Secret",
        "AutomaticManagement", "ManualManagementReason" };
    public const string PropertyPrefix = "platformAccountProperties.";
    public const string DefaultLocation = "\\";               // the Vault root, as the samples write it

    // Accounts.csv column -> Vault file category (what the account stores it as) and a note.
    static readonly Dictionary<string, (string, string)> FileCategories = new()
    {
        ["Name"] = ("", "Account (object) name in the Safe (not a file category)"),
        ["SafeName"] = ("", "Safe the account is stored in (not a file category)"),
        ["PlatformId"] = ("PolicyID", "Platform ID"),
        ["UserName"] = ("UserName", "Account username"),
        ["Address"] = ("Address", "Target address"),
        ["SecretType"] = ("", "password or key (the type of the account's secret)"),
        ["Secret"] = ("", "The password or private key itself"),
        ["AutomaticManagement"] = ("CPMDisabled", "False sets CPMDisabled on the account"),
        ["ManualManagementReason"] = ("CPMDisabled", "Text stored in CPMDisabled when the CPM does not manage it"),
    };

    static (string, string) Category(string col)
    {
        if (col.StartsWith(PropertyPrefix, StringComparison.Ordinal))
            return (col.Substring(col.IndexOf('.') + 1), "Platform account property from the source column(s) mapped in account_property_map");
        return FileCategories.TryGetValue(col, out var c) ? c : ("", "");
    }

    sealed class PlatformUsage
    {
        public int Accounts;
        public Dictionary<string, int> Cols;
    }

    /// <summary>FileCategories.csv: every Accounts.csv column and how often it is filled.
    /// PlatformProperties.csv: per platform, which file categories its accounts use.</summary>
    public static List<string> WriteCategories(string out_, List<string> header, List<Dictionary<string, string>> rows)
    {
        var cols = header.ToList();
        var used = cols.Distinct().ToDictionary(c => c, _ => 0);
        var perPlatform = new OrderedMap<string, PlatformUsage>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var plat = row["PlatformId"];
            var pp = perPlatform.GetOrAdd(plat, () => new PlatformUsage { Cols = cols.Distinct().ToDictionary(c => c, _ => 0) });
            pp.Accounts++;
            foreach (var c in cols)
            {
                if (Py.Strip(row.TryGetValue(c, out var v) ? v ?? "" : "").Length > 0)
                {
                    used[c]++;
                    pp.Cols[c]++;
                }
            }
        }
        var catPath = Path.Combine(out_, "FileCategories.csv");
        using (var fh = Open(catPath))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
            w.WriteRow(new object[] { "column", "fileCategory", "accountsWithValue", "accountsTotal", "platforms", "description" });
            foreach (var c in cols)
            {
                var (fc, desc) = Category(c);
                var plats = Py.Sorted(perPlatform.Where(kv => kv.Value.Cols[c] > 0).Select(kv => kv.Key));
                w.WriteRow(new object[] { c, fc, (long)used[c], (long)rows.Count, string.Join("; ", plats), desc });
            }
        }
        var platPath = Path.Combine(out_, "PlatformProperties.csv");
        using (var fh = Open(platPath))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
            w.WriteRow(new object[] { "platformId", "column", "fileCategory", "accountsWithValue", "accountsOnPlatform" });
            foreach (var plat in Py.Sorted(perPlatform.Keys))
            {
                var v = perPlatform[plat];
                foreach (var c in cols)
                    if (v.Cols[c] > 0) w.WriteRow(new object[] { plat, c, Category(c).Item1, (long)v.Cols[c], (long)v.Accounts });
            }
        }
        return new List<string> { catPath, platPath };
    }

    /// <summary>Upload CSV booleans: True / False, as the Privilege Cloud samples write them.</summary>
    public static string Bool(object v)
    {
        if (v is string t && (Py.Lower(Py.Strip(t)) == "true" || Py.Lower(Py.Strip(t)) == "false"))
            v = Py.Lower(Py.Strip(t)) == "true";
        return v switch
        {
            bool b => b ? "True" : "False",
            null => "",
            _ => Py.Str(v),
        };
    }

    static bool IsTrue(object v) => v is true || (v is string t && Py.Lower(Py.Strip(t)) == "true");

    static StreamWriter Open(string path) => Csv.OpenWrite(path);

    public static string Sha256(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(fs));
    }

    /// <summary>Owner-only file mode where the OS supports it (POSIX). On Windows rely on folder ACLs.</summary>
    public static void Restrict(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    // ----------------------------------------------------------------- review files

    public static List<string> WriteReview(Plan plan, string outDir)
    {
        var out_ = Path.Combine(outDir, "review");
        var extraCols = new List<string>();
        foreach (var p in plan.Accounts)
            foreach (var k in p.Rec.Extra.Keys)
                if (!extraCols.Contains(k)) extraCols.Add(k);

        var accounts = Path.Combine(out_, "Accounts_Review.csv");
        using (var fh = Open(accounts))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh, Csv.Quoting.All));
            w.WriteRow(new object[] { "Record_ID", "Migrate", "Status", "Notes", "Target_Safe", "Proposed_Safe_Name",
                "Valid_Safe_Name", "Safe_Name_Issues", "Safe_Mapping_Source", "Platform_ID",
                "Platform_Source", "Account_Name", "Address", "Username", "Secret_Type",
                "Has_Secret", "Source", "Source_Ref", "Source_Type", "Folder", "Access_Groups",
                "Access_Source" }.Concat(extraCols.Select(c => (object)$"Source.{c}")));
            foreach (var p in plan.Accounts)
            {
                var r = p.Rec;
                bool hasSecret = r.HasSecret ?? Py.Strip(r.Secret ?? "").Length > 0;
                w.WriteRow(new object[] { r.RecordId, p.Migrate, p.Status, string.Join("; ", p.Errors.Concat(p.Warnings)), p.Safe,
                    p.ProposedSafe, p.ValidSafe ? "TRUE" : "FALSE", string.Join("; ", p.SafeIssues), p.SafeSource, p.Platform,
                    p.PlatformSource, p.AccountName, r.Address, r.Username, r.SecretType, hasSecret ? "Y" : "N",
                    r.Source, r.SourceRef, r.Type, r.FolderPath, string.Join("; ", p.Grants.Select(g => $"{g.Member}={g.Permission}")),
                    p.AccessSource }.Concat(extraCols.Select(c => (object)(r.Extra.Get(c) ?? ""))));
            }
        }

        var safes = Path.Combine(out_, "Safes_Review.csv");
        using (var fh = Open(safes))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
            w.WriteRow(new object[] { "Target_Safe", "Length", "Valid_Safe_Name", "Proposed_Safe_Names",
                "Safe_Name_Issues", "Mapping_Sources", "Accounts", "Accounts_To_Upload" });
            foreach (var (name, s) in plan.Safes)
                w.WriteRow(new object[] { name, (long)Py.Len(name), s.Valid ? "TRUE" : "FALSE",
                    string.Join(" | ", Py.Sorted(s.Proposed)), string.Join(" | ", Py.Sorted(s.Issues)),
                    string.Join(" | ", Py.Sorted(s.Sources)), (long)s.Accounts, (long)s.Migrating });
        }

        var members = Path.Combine(out_, "SafeMembers_Review.csv");
        using (var fh = Open(members))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
            w.WriteRow(new object[] { "Target_Safe", "Source_Member", "Member_Name", "Search_In", "Member_Type",
                "Source_Permission", "Role", "Accounts_With_Access", "Notes" });
            foreach (var kv in plan.Members)
            {
                var m = kv.Value;
                w.WriteRow(new object[] { kv.Key.Item1, m.SourceName, m.MemberName, m.SearchIn, m.MemberType,
                    m.Permission, string.IsNullOrEmpty(m.Role) ? "UNMAPPED" : m.Role, (long)m.Accounts, string.Join("; ", m.Notes ?? new()) });
            }
        }
        var files = new List<string> { accounts, safes, members };
        var create = GroupsToCreate(plan);
        if (create.Count > 0)
        {
            var path = Path.Combine(out_, "MemberGroups_To_Create.csv");
            using (var fh = Open(path))
            {
                var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
                w.WriteRow(new object[] { "Member_Name", "Member_Type", "Search_In", "Safes", "Roles", "Safe_Names", "Notes" });
                foreach (var g in create)
                    w.WriteRow(new object[] { g.MemberName, g.MemberType, g.SearchIn, (long)g.Safes.Count,
                        string.Join(" | ", Py.Sorted(g.Roles)), string.Join(" | ", g.Safes), string.Join("; ", g.Notes) });
            }
            files.Add(path);
        }
        return files;
    }

    public sealed class GroupToCreate
    {
        public string MemberName, MemberType, SearchIn;
        public List<string> Safes = new();
        public HashSet<string> Roles = new(StringComparer.Ordinal);
        public List<string> Notes = new();
    }

    /// <summary>The standard member groups and roles (standard_members) to create in the directory before the
    /// upload: one row per name, with the Safes it goes on. Users are left out.</summary>
    public static List<GroupToCreate> GroupsToCreate(Plan plan)
    {
        var out_ = new OrderedMap<(string, string), GroupToCreate>();
        foreach (var kv in plan.Members)
        {
            var m = kv.Value;
            if (!m.Standard || m.MemberType == "User") continue;
            var g = out_.GetOrAdd((Py.Lower(m.MemberName), m.MemberType), () => new GroupToCreate
                { MemberName = m.MemberName, MemberType = m.MemberType, SearchIn = m.SearchIn });
            g.Safes.Add(kv.Key.Item1);
            g.Roles.Add(string.IsNullOrEmpty(m.Role) ? "UNMAPPED" : m.Role);
            foreach (var n in m.Notes ?? new())
                if (n.StartsWith("CHECK", StringComparison.Ordinal) && !g.Notes.Contains(n)) g.Notes.Add(n);
        }
        return Py.Sorted(out_.Values.ToList(), (a, b) => Py.Cmp(Py.Lower(a.MemberName), Py.Lower(b.MemberName)));
    }

    // ----------------------------------------------------------------- upload files
    // Safes.csv, SafeMembers.csv and Accounts.csv are written exactly as the API should get them,
    // without csvsafe escaping (that would change the data, e.g. a password starting with '-').

    public static (List<string> Files, JObj Counts) WriteUpload(Plan plan, JObj cfg, string outDir, bool includeSecrets)
    {
        var out_ = Path.Combine(outDir, "upload");
        var uploadSafes = plan.Safes.Where(kv => kv.Value.Migrating > 0).Select(kv => kv.Key).ToList();

        var safes = Path.Combine(out_, "Safes.csv");
        var bodies = uploadSafes.Select(name => (name, body: Transform.SafeSettings(name, plan.Safes[name], cfg))).ToList();
        var safeCols = SafeColumns.Concat(SafeOptional.Where(c => bodies.Any(b => IsTrue(b.body.Get(c.Field))))).ToList();
        using (var fh = Open(safes))
        {
            var w = new Csv.Writer(fh);
            w.WriteRow(safeCols.Select(c => (object)c.Col));
            foreach (var (name, body) in bodies)
            {
                object Field(string f)
                {
                    if (f == "safeName") return name;
                    var v = body.Get(f, "");
                    if (f == "location" && Py.Strip(v == null ? "" : Py.Str(v)).Length == 0) return DefaultLocation;
                    return v;
                }
                w.WriteRow(safeCols.Select(c => (object)Bool(Field(c.Field))));
            }
        }

        var members = Path.Combine(out_, "SafeMembers.csv");
        int skippedMembers = 0;
        var roles = Config.AllRoles(cfg);
        var memberRows = new List<(List<object> Row, string SearchIn)>();
        foreach (var kv in plan.Members)
        {
            var m = kv.Value;
            if (m.Role == null || !roles.TryGetValue(m.Role, out var perms))
            {
                skippedMembers++;
                continue;
            }
            var granted = perms.ToHashSet();
            var row = new List<object> { kv.Key.Item1, m.MemberName, m.MemberType };
            row.AddRange(Config.AllPermissions.Select(p => (object)Bool(granted.Contains(p))));
            memberRows.Add((row, m.SearchIn ?? ""));
        }
        bool withSearchIn = memberRows.Any(r => Py.Strip(r.SearchIn).Length > 0);
        using (var fh = Open(members))
        {
            var w = new Csv.Writer(fh);
            w.WriteRow(MemberColumns.Concat(Config.AllPermissions).Concat(withSearchIn ? MemberOptional : Array.Empty<string>())
                .Select(c => (object)c));
            foreach (var (row, searchIn) in memberRows)
                w.WriteRow(withSearchIn ? row.Append(searchIn) : row);
        }

        var propMap = cfg.Obj("account_property_map");
        var acctDefaults = cfg.Obj("account_defaults");
        var auto = acctDefaults.Get("automaticManagementEnabled", false);
        var reason = IsTrue(auto) ? "" : acctDefaults.Get("manualManagementReason", "");
        var accounts = Path.Combine(out_, "Accounts.csv");
        var rows = new List<(AccountPlan P, List<object> Base, Dictionary<string, string> Props)>();
        foreach (var p in plan.Accounts)
        {
            if (!p.Uploadable) continue;
            var r = p.Rec;
            var props = new Dictionary<string, string>(StringComparer.Ordinal);
            var extraLower = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in r.Extra) extraLower[Py.Lower(kv.Key)] = kv.Value;
            foreach (var kv in propMap)
            {
                var val = extraLower.TryGetValue(Py.Lower(kv.Key), out var v) ? v ?? "" : "";
                var dst = Py.Str(kv.Value);
                if (Py.Strip(val).Length > 0 && string.IsNullOrEmpty(props.GetValueOrDefault(dst))) props[dst] = val;
            }
            rows.Add((p, new List<object> { p.AccountName, p.Safe, p.Platform, r.Username, r.Address, r.SecretType,
                includeSecrets ? r.Secret : "", Bool(auto), reason }, props));
        }
        // Property columns only for the platform properties some account has a value for.
        var propCols = propMap.Values.Select(v => Py.Str(v)).Distinct()
            .Where(c => rows.Any(x => !string.IsNullOrEmpty(x.Props.GetValueOrDefault(c)))).ToList();
        var header = new List<string>(AccountColumns);
        header.AddRange(propCols.Select(c => PropertyPrefix + c));
        var usage = new List<Dictionary<string, string>>();
        using (var fh = Open(accounts))
        {
            var w = new Csv.Writer(fh);
            w.WriteRow(header);
            foreach (var (p, baseValues, props) in rows)
            {
                var values = new List<object>(baseValues);
                values.AddRange(propCols.Select(c => (object)props.GetValueOrDefault(c, "")));
                w.WriteRow(values);
                var row = new Dictionary<string, string>(StringComparer.Ordinal);
                for (int i = 0; i < header.Count && i < values.Count; i++) row[header[i]] = values[i] == null ? "None" : Py.Str(values[i]);
                // usage only, never the value
                row["Secret"] = p.Rec.HasSecret == true || Py.Strip(p.Rec.Secret ?? "").Length > 0 ? "x" : "";
                usage.Add(row);
            }
        }
        if (includeSecrets) Restrict(accounts);
        var extraFiles = WriteCategories(out_, header, usage);
        var files = new List<string> { safes, members, accounts };
        files.AddRange(extraFiles);
        return (files, Json.O(("safes", (long)uploadSafes.Count), ("members", (long)(plan.Members.Count - skippedMembers)),
                              ("members_skipped", (long)skippedMembers), ("accounts", (long)rows.Count)));
    }

    /// <summary>inputs: each a JObj, or a (source, path) pair whose file gets a checksum.</summary>
    public static string WriteManifest(string outDir, IEnumerable<object> inputs, IEnumerable<string> files, JObj counts,
                                       bool includeSecrets, string cfgPath)
    {
        var manifest = Json.O(
            ("tool", "Idira Migration Workbench"), ("version", Version),
            ("created_utc", Py.NowUtcIso()),
            ("host", Py.Node()),
            ("includes_secrets", includeSecrets),
            ("config", string.IsNullOrEmpty(cfgPath) ? "(defaults)" : cfgPath),
            ("inputs", inputs.Select(i => i is JObj o ? (object)o
                : i is ValueTuple<string, string> t ? Json.O(("source", t.Item1), ("path", t.Item2), ("sha256", Sha256(t.Item2)))
                : throw new ArgumentException("bad manifest input")).ToList()),
            ("outputs", files.Select(f => (object)Json.O(("path", Path.GetRelativePath(outDir, f)), ("sha256", Sha256(f)))).ToList()),
            ("counts", counts));
        var path = Path.Combine(outDir, "manifest.json");
        PyFile.WriteText(path, Json.Dumps(manifest, 2));
        return path;
    }

    // ----------------------------------------------------------------- naming convention document

    public static readonly string[] ConventionHeader = { "Section", "Item", "Code_Or_Value", "Applies_When", "Notes" };
    static readonly Dictionary<string, string> FieldWords = new()
    {
        ["folder_word"] = "a word in any folder level", ["folder_level"] = "a whole folder level",
        ["folder"] = "the folder path", ["platform"] = "the platform ID", ["username"] = "the username",
        ["address"] = "the address", ["address_domain"] = "the address's domain", ["name"] = "the account name",
        ["type"] = "the record type", ["source"] = "the source", ["env"] = "the {env} code",
        ["tech"] = "the {tech} code", ["flavor"] = "the {flavor} code", ["acct"] = "the {acct} code",
    };

    /// <summary>Python s[a:b] on a string (negative b counts from the end).</summary>
    static string Slice(string s, int a, int b)
    {
        if (b < 0) b = Math.Max(0, s.Length + b);
        b = Math.Min(b, s.Length);
        return a >= b ? "" : s.Substring(a, b - a);
    }

    static string Literal(string t)
    {
        var out_ = new System.Text.StringBuilder();
        int i = 0;
        while (i < t.Length)
        {
            char c = t[i];
            if (c == '\\' && i + 1 < t.Length && !Py.IsAlnum(t[i + 1]))
            {
                out_.Append(t[i + 1]);
                i += 2;
                continue;
            }
            if (".*+?^${}()|[]\\".IndexOf(c) >= 0) return null;
            out_.Append(c);
            i++;
        }
        return out_.ToString();
    }

    /// <summary>A rule pattern in words: ^Boston$ -> 'is Boston', ^svc -> 'starts with svc'.</summary>
    public static string PlainPattern(object pattern)
    {
        var p = PyRe.Sub(@"^\(\?i\)", "", Py.Truthy(pattern) ? Py.Str(pattern) : "");
        var alts = p.Split('|');
        if (alts.Length > 1 && alts.All(a => a.StartsWith('^') && a.EndsWith('$') && !string.IsNullOrEmpty(Literal(Slice(a, 1, -1)))))
        {
            var vals = alts.Select(a => Literal(Slice(a, 1, -1))).ToList();
            return vals.Count > 1 ? "is one of " + string.Join(", ", vals) : $"is {vals[0]}";
        }
        if (p.StartsWith("^(", StringComparison.Ordinal) && p.EndsWith(")$", StringComparison.Ordinal)
            && Slice(p, 2, -2).Split('|').All(a => !string.IsNullOrEmpty(Literal(a))))
        {
            var vals = Slice(p, 2, -2).Split('|').Select(Literal).ToList();
            return vals.Count > 1 ? "is one of " + string.Join(", ", vals) : $"is {vals[0]}";
        }
        foreach (var (test, words, core) in new[]
                 {
                     (p.StartsWith('^') && p.EndsWith('$'), "is", Slice(p, 1, -1)),
                     (p.StartsWith('^'), "starts with", Slice(p, 1, p.Length)),
                     (p.EndsWith('$'), "ends with", Slice(p, 0, -1)),
                     (true, "contains", p),
                 })
        {
            if (test && core.Length > 0 && Literal(core) != null) return $"{words} {Literal(core)}";
        }
        return $"matches the pattern {p}";
    }

    static string N(long n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";

    static string FieldWordsFor(object field)
    {
        var f = field == null ? "None" : Py.Str(field);
        if (f.StartsWith("column:", StringComparison.Ordinal)) return $"the {f.Substring(7)} column";
        return field is string s && FieldWords.TryGetValue(s, out var w) ? w : f;
    }

    static object Or(object a, object b) => Py.Or(a, b);

    /// <summary>Every rule that names Safes (and their standard member groups), in plain words, so the same
    /// convention can name new Safes once Privilege Cloud is live.</summary>
    public static List<List<object>> ConventionRows(Plan plan, JObj cfg, int examples = 25)
    {
        var conv = cfg.Obj("safe_convention") ?? new JObj();
        var sn = cfg.Obj("safe_name");
        var sep = conv.ContainsKey("separator") ? conv["separator"] : "-";
        var sepS = sep == null ? "None" : Py.Str(sep);
        var rep = sn.Get("replacement");
        var repOrDash = Py.Truthy(rep) ? Py.Str(rep) : "-";
        var rows = new List<List<object>>
        {
            new() { "Pattern", "Safes for accounts with folders", Or(conv.Get("template"), "{folder}"),
                "the account is in a folder", "each placeholder becomes a short code; codes are joined with " + Py.Repr(sep) },
            new() { "Pattern", "Safes for accounts without folders", Or(conv.Get("template_no_folders"), ""),
                "the account has no folder", "" },
            new() { "Pattern", "Naming", cfg.Get("fallback_strategy", "convention"), "no exception below applies",
                "convention = the patterns above; folder_leaf / folder_path = the folder name as is; unmapped = UNMAPPED" },
            new() { "Limit", "Maximum length", sn["max_length"], "always",
                "too long: long folder names become initials, then the top folder levels are left out, then the end is cut" },
            new() { "Limit", "Forbidden characters", sn["invalid_chars"], "always", $"each becomes '{(rep == null ? "None" : Py.Str(rep))}'" },
            new() { "Limit", "Prefix", Or(sn.Get("prefix"), "(none)"), "every Safe", "counts toward the maximum length" },
            new() { "Limit", "Accounts per Safe", Or(cfg.Get("safe_max_accounts"), "(no limit)"), "always",
                Py.Truthy(cfg.Get("safe_split_over_max"))
                    ? "over the limit: split into numbered Safes (" + sepS + "01, " + sepS + "02...) by address"
                    : "over the limit: flagged for a look" },
            new() { "Limit", "Same name twice", $"{repOrDash}2, {repOrDash}3...", "two Safes end up with one name",
                "the later Safe gets the suffix, still within the maximum length" },
            new() { "Limit", "Repeated codes", "", "a code already appears earlier in the name", "it is left out the second time" },
            new() { "Placeholder", "{folder}", "", "the account has folders",
                "every folder level, in order, each abbreviated (see Abbreviation rows)" },
            new() { "Placeholder", "{folder_leaf}", "", "the account has folders", "the last folder level only, abbreviated" },
        };
        var src = conv.Get("layers") is JObj lj && lj.Count > 0 ? lj : Naming.DefaultLayers();
        var layers = src.Copy();
        foreach (var kv in Naming.DefaultLayers()) layers.SetDefault(kv.Key, kv.Value);
        foreach (var (name, lo) in layers)
        {
            var layer = lo as JObj ?? new JObj();
            var label = Py.Truthy(layer.Get("label")) ? Py.Str(layer.Get("label")) : name;
            foreach (var ro in layer.List("rules") ?? new List<object>())
            {
                if (ro is not JObj r) continue;
                var when = $"{FieldWordsFor(r.Get("field"))} {PlainPattern(r.Get("pattern"))}";
                if (Py.Truthy(r.Get("field2")))
                    when += $" and {FieldWordsFor(r["field2"])} {PlainPattern(r.Get("pattern2"))}";
                rows.Add(new() { "Placeholder", "{" + name + "}", Or(r.Get("code"), "(left out)"), when, label });
            }
            rows.Add(new() { "Placeholder", "{" + name + "}", Or(layer.Get("default"), "(left out)"), "no row above matches",
                label + ": default" });
        }
        foreach (var ro in cfg.List("folder_rules") ?? new List<object>())
        {
            if (ro is not JObj r) continue;
            rows.Add(new() { "Exception", "Folder \u2192 Safe", r.Get("safe", ""),
                $"the folder is {Py.Str(r.Get("folder_prefix", ""))} or under it", "the most specific folder wins" });
        }
        foreach (var ro in cfg.List("group_rules") ?? new List<object>())
        {
            if (ro is not JObj r) continue;
            var what = Py.Truthy(r.Get("group")) ? $"the access group is {Py.Str(r["group"])}"
                : $"the access group {PlainPattern(r.Get("group_pattern"))}";
            rows.Add(new() { "Exception", "Access group \u2192 Safe", r.Get("safe", ""), what, "first match wins" });
        }
        // Abbreviations: yours first, then the codes the loaded folders got, then the dictionary.
        var namer = new Namer(cfg);
        var userAbbr = conv.Get("abbreviations") as JObj ?? new JObj();
        var yours = userAbbr.Keys.Select(Naming.Norm).ToHashSet(StringComparer.Ordinal);
        foreach (var kv in Py.Sorted(userAbbr.ToList(), (a, b) => Py.Cmp(Py.Lower(a.Key), Py.Lower(b.Key))))
            rows.Add(new() { "Abbreviation", kv.Key, kv.Value, "a folder name or word", "yours" });
        var counts = new OrderedMap<string, long>(StringComparer.Ordinal);
        foreach (var p in plan.Accounts)
            foreach (var level in p.Rec.Folder)
                counts[level] = counts.GetValueOrDefault(level) + 1;
        foreach (var s in namer.Suggest(counts))
        {
            if (Py.Truthy(s["yours"])) continue;
            rows.Add(new() { "Abbreviation", s["folder"], s["code"], "a folder name",
                ((bool)s["automatic"] ? "automatic" : "built-in") + $", used by {N((long)s["accounts"], "account")}" });
        }
        foreach (var kv in Py.Sorted(Naming.DefaultAbbreviations.ToList(), (a, b) => Py.Cmp(a.Key, b.Key)))
            if (!yours.Contains(Naming.Norm(kv.Key)) && kv.Value.Length > 0)
                rows.Add(new() { "Abbreviation", kv.Key, kv.Value, "a folder name or word", "built-in" });
        rows.Add(new() { "Abbreviation", "(any other word)", "", "no abbreviation above",
            "automatic: up to 4 letters, CamelCase and compound words become initials (SharePoint \u2192 SP)" });
        var std = cfg.Obj("standard_members") ?? new JObj();
        if ((Py.Truthy(std.Get("apply_to")) ? Py.Str(std.Get("apply_to")) : "no_source_members") != "off")
        {
            var where = Py.Eq(std.Get("apply_to"), "all") ? "every Safe" : "Safes with no members from the source";
            foreach (var ro in std.List("members") ?? new List<object>())
            {
                if (ro is not JObj r) continue;
                rows.Add(new() { "Member group", r.Get("name", ""), r.Get("role", ""), where,
                    $"{(Py.Truthy(r.Get("member_type")) ? Py.Str(r["member_type"]) : "Group")}; {{safe}} = the Safe's name"
                    + (Py.Truthy(r.Get("search_in")) ? $"; searchIn {Py.Str(r["search_in"])}" : "") });
            }
        }
        int shown = 0;
        foreach (var (name, s) in plan.Safes)
        {
            if (shown >= examples) break;
            var folders = Py.Sorted(s.Folders.Where(f => !string.IsNullOrEmpty(f) && f != "\\"));
            var shownFolders = string.Join("; ", folders.Take(2));
            rows.Add(new() { "Example", name, "", shownFolders.Length > 0 ? shownFolders : "accounts without folders",
                $"{Py.Len(name)} characters, {N(s.Accounts, "account")}" });
            shown++;
        }
        return rows;
    }

    public static string WriteConvention(Plan plan, JObj cfg, string outDir)
    {
        var path = Path.Combine(outDir, "review", "SafeNamingConvention.csv");
        using (var fh = Open(path))
        {
            var w = new CsvSafe.SafeWriter(new Csv.Writer(fh));
            w.WriteRow(ConventionHeader);
            foreach (var row in ConventionRows(plan, cfg)) w.WriteRow(row);
        }
        return path;
    }
}
