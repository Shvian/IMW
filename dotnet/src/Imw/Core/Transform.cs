using System.Text.RegularExpressions;
using Imw.Adapters;

namespace Imw.Core;

// Target rules: Safe mapping, Safe names, platforms, members and validation (port of imw/transform.py).
// Everything here is source-independent; it only sees SourceRecord objects.

public sealed class AccountPlan
{
    public SourceRecord Rec;
    public string Migrate = "Y";
    public string ProposedSafe = "";
    public string Safe = "";
    public bool ValidSafe = true;
    public List<string> SafeIssues = new();
    public string SafeSource = "";
    public string Platform = "";
    public string PlatformSource = "";
    public string AccountName = "";
    public List<Grant> Grants = new();
    public string AccessSource = "";
    public List<string> Warnings = new();
    public List<string> Errors = new();
    public bool InScope = true;          // false when an extract filter leaves the record out
    public string RuleSafe = "";         // the Safe name the rules gave, before you renamed the Safe
    // Notes about the account's Safe rather than the account itself. They show on the Safe.
    public List<string> SafeNotes = new();
    public string Personal = "";        // the person whose personal folder this is, for a personal Safe
    public bool ByConvention;

    public AccountPlan(SourceRecord rec) { Rec = rec; }

    public string Status => Errors.Count > 0 ? "ERROR" : Warnings.Count > 0 ? "REVIEW" : "OK";
    public bool Uploadable => Migrate == "Y" && Errors.Count == 0 && InScope;
}

public sealed class SafeInfo
{
    public HashSet<string> Proposed = new(StringComparer.Ordinal);
    public bool Valid = true;
    public HashSet<string> Issues = new(StringComparer.Ordinal);
    public HashSet<string> Sources = new(StringComparer.Ordinal);
    public int Accounts;
    public int Migrating;
    public HashSet<string> Folders = new(StringComparer.Ordinal);
    public HashSet<string> RuleNames = new(StringComparer.Ordinal);
    public JObj Override;
    internal int NoAccess;
}

public sealed class MemberInfo
{
    public string SourceName = "";
    public string Type = "";
    public string MemberType = "";
    public string Role = "";
    public string Permission = "";
    public int Accounts;
    public HashSet<string> Seen = new(StringComparer.Ordinal);
    public HashSet<AccountPlan> Ids = new(ReferenceEqualityComparer.Instance);
    public string MemberName;
    public string SearchIn = "";
    public string DirectorySource = "";
    public string RuleName = "";
    public List<string> Sources;
    public List<string> Notes;          // null for a member that is only being looked at
    public bool Standard;
    public string Template = "";
    public string FixedSearchIn = "";
}

public sealed class Plan
{
    public List<AccountPlan> Accounts;
    public OrderedMap<string, SafeInfo> Safes;
    public OrderedMap<(string Safe, string Key), MemberInfo> Members;
    public List<JObj> MemberEdits = new();
    public Dictionary<string, JObj> MemberOverrides = new();
    public Dictionary<string, JObj> SafeOverrides = new();
    // Users who may get their access through a group (see Permissions.Users): one row per folder,
    // Safe and user, with your decision ("" = none yet, include, exclude).
    public List<UndecidedUser> Undecided = new();
    public References Refs;
}

public sealed class UndecidedUser
{
    public string Folder = "", Safe = "", Member = "", MemberName = "", Permission = "", Groups = "", Decision = "", Note = "";
    public int Accounts;
}

/// <summary>
/// Permissions file: grants for sources that do not carry them (Delinea, KeePass).
/// CSV with one grant per row. Rows with an ID or name apply to that record; rows with only a
/// folder apply to the folder and its subfolders (nearest folder wins). Record-level rows win.
/// </summary>
public sealed class Permissions
{
    public static readonly string[] FolderColumns = { "Folder Path", "FolderPath", "Folder", "Path", "Folder Name" };
    public static readonly string[] GroupColumns = { "Group", "Group Name", "GroupName", "Principal", "Member", "User/Group",
        "Member Name", "Group Display Name" };
    public static readonly string[] UserColumns = { "User", "User Name", "UserName", "Username", "User Display Name", "Display Name" };
    // For a folder the secret role is what its secrets get, so it comes before the folder role.
    public static readonly string[] RoleColumns = { "Permission", "Secret Permission", "Secret Permissions", "Secret Access Role",
        "Secret Access Role Name", "SecretAccessRoleName", "Secret Role", "Role", "Access",
        "Permissions", "Folder Permission", "Folder Permissions", "Folder Access Role",
        "Folder Access Role Name", "FolderAccessRoleName", "Folder Role" };
    public static readonly string[] TypeColumns = { "Member Type", "Type", "Principal Type" };
    public static readonly string[] DomainColumns = { "Domain", "Domain Name", "DomainName" };
    // Strongest first: a report cell such as "View, Edit, Owner" keeps the strongest right.
    static readonly string[] PermissionOrder = { "owner", "full", "admin", "manage", "edit", "write", "modify", "add secret",
        "approve", "view", "read", "use", "connect", "list" };

    /// <summary>'View, Edit, Owner' (or '/', ';' or '|' between them) -> 'Owner'; a single word stays as is.</summary>
    public static string StrongestPermission(string text)
    {
        var parts = PyRe.Split(@"[,;/|]+", text ?? "").Select(p => Py.Strip(p)).Where(p => p.Length > 0).ToList();
        if (parts.Count <= 1) return Py.Strip(text ?? "");
        int Rank(string p) { int i = Array.IndexOf(PermissionOrder, Py.Lower(p)); return i < 0 ? PermissionOrder.Length : i; }
        var best = parts[0];
        foreach (var p in parts.Skip(1)) if (Rank(p) < Rank(best)) best = p;
        return best;
    }

    public readonly OrderedMap<string, List<Grant>> ById = new(StringComparer.Ordinal);
    public readonly OrderedMap<(string, string), List<Grant>> ByName = new();
    public readonly OrderedMap<string, List<Grant>> ByFolder = new(StringComparer.Ordinal);
    // Users from a report of effective access per folder (no group column), kept apart so each
    // can be checked against the groups on the same folder (see Users).
    public readonly OrderedMap<string, List<Grant>> UsersByFolder = new(StringComparer.Ordinal);
    public bool HasGroupReport;
    public readonly bool Loaded;
    public readonly List<string> Paths;

    public Permissions() : this((IEnumerable<string>)null) { }

    /// <summary>One file or several; grants from several files are merged.</summary>
    public Permissions(IEnumerable<string> paths, string encoding = "utf-8-sig")
    {
        Paths = (paths ?? Array.Empty<string>()).Where(p => !string.IsNullOrEmpty(p)).ToList();
        Loaded = Paths.Count > 0;
        foreach (var one in Paths) Read(one, encoding);
        if (Loaded) LogSummary();
    }

    public Permissions(string path, string encoding = "utf-8-sig") : this(path == null ? null : new[] { path }, encoding) { }

    static void Add(List<Grant> lst, Grant g)
    {
        var key = (Py.Lower(g.Member), Py.Lower(g.Permission));
        if (lst.All(x => (Py.Lower(x.Member), Py.Lower(x.Permission)) != key)) lst.Add(g);
    }

    void Read(string path, string encoding)
    {
        CsvSafe.Reading(path, () =>
        {
            var reader = new Csv.DictReader(Csv.ReadText(path, encoding));
            var cols = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var c in reader.FieldNames) if (!string.IsNullOrEmpty(c)) cols[Py.Strip(Py.Lower(c))] = c;

            string Pick(string[] names)
            {
                foreach (var n in names) if (cols.TryGetValue(Py.Lower(n), out var c)) return c;
                return null;
            }

            string groupCol = Pick(GroupColumns), userCol = Pick(UserColumns);
            var permCols = RoleColumns.Where(n => cols.ContainsKey(Py.Lower(n))).Select(n => cols[Py.Lower(n)]).ToList();
            var typeCol = Pick(TypeColumns);
            var domainCol = Pick(DomainColumns);
            var userReport = userCol != null && groupCol == null;
            if (groupCol != null) HasGroupReport = true;
            if (userReport)
                Log.Warning($"{path} lists each user's access, including access through a group: a user becomes a " +
                            "Safe member only where no group on the folder explains it; the others wait for your decision.");

            string V(Csv.OrderedRow row, string c) => c == null ? "" : Py.Strip(row[c] ?? "");

            string Col(Csv.OrderedRow row, params string[] names)
            {
                foreach (var n in names)
                    if (cols.TryGetValue(Py.Lower(n), out var c) && V(row, c).Length > 0) return V(row, c);
                return "";
            }

            foreach (var row in reader.Rows())
            {
                string member = "", mtype = "";
                // A report row that names both a user and the group the access comes from: the group is the Safe member.
                if (groupCol != null && V(row, groupCol).Length > 0)
                {
                    member = V(row, groupCol);
                    mtype = userCol != null ? "Group" : "";
                }
                else if (userCol != null && V(row, userCol).Length > 0)
                {
                    member = V(row, userCol);
                    mtype = "User";
                }
                var domain = V(row, domainCol);
                if (member.Length > 0 && domain.Length > 0 && !member.Contains('\\')) member = $"{domain}\\{member}";
                var perm = StrongestPermission(permCols.Select(c => V(row, c)).FirstOrDefault(v => v.Length > 0) ?? "");
                if (member.Length == 0 || perm.Length == 0) continue;
                var t = V(row, typeCol);
                var g = new Grant(member, perm, t.Length > 0 ? t : mtype);
                var rid = Col(row, "Secret ID", "SecretId", "ID", "Record ID");
                var name = Col(row, "Secret Name", "SecretName", "Name", "Title");
                var folder = Py.Lower(string.Join("\\", SourceRecord.SplitFolder(Col(row, FolderColumns), "auto")));
                if (rid.Length > 0) Add(ById.GetOrAdd(rid, () => new()), g);
                else if (name.Length > 0) Add(ByName.GetOrAdd((folder, Py.Lower(name)), () => new()), g);
                else if (userReport) Add(UsersByFolder.GetOrAdd(folder, () => new()), g);
                else Add(ByFolder.GetOrAdd(folder, () => new()), g);
            }
            return 0;
        });
    }

    public void LogSummary() =>
        Log.Info($"permissions: {ById.Count + ByName.Count} record-level, " +
                 $"{ByFolder.Keys.Union(UsersByFolder.Keys, StringComparer.Ordinal).Count()} folder-level entries");

    /// <summary>0 = strongest (Owner); unknown wording ranks weakest.</summary>
    public static int PermissionRank(string text)
    {
        int i = Array.IndexOf(PermissionOrder, Py.Lower(Py.Strip(text ?? "")));
        return i < 0 ? PermissionOrder.Length : i;
    }

    static string Nearest(OrderedMap<string, List<Grant>> index, IList<string> folder)
    {
        for (int i = folder.Count; i >= 0; i--)
        {
            var cand = string.Join("\\", folder.Take(i));
            if (index.ContainsKey(cand)) return cand;
        }
        return null;
    }

    public (List<Grant>, string) Resolve(SourceRecord rec)
    {
        if (ById.TryGetValue(rec.SourceId, out var g)) return (g, "record");
        var folder = rec.Folder.Select(Py.Lower).ToList();
        if (ByName.TryGetValue((string.Join("\\", folder), Py.Lower(rec.Name)), out g)) return (g, "record");
        var at = Nearest(ByFolder, folder);
        var groups = at != null ? new List<Grant>(ByFolder[at]) : new List<Grant>();
        var users = Users(folder);
        if (groups.Count > 0 || users.Count > 0) return (groups.Concat(users).ToList(), "folder");
        return (new List<Grant>(), "none");
    }

    /// <summary>Users from an effective-access report for this folder, each marked direct (no group on
    /// the folder gives that much access) or undecided (with the groups that might explain it).</summary>
    List<Grant> Users(IList<string> folder)
    {
        var at = Nearest(UsersByFolder, folder);
        var outList = new List<Grant>();
        if (at == null) return outList;
        // The groups that reach this folder: the nearest folder the group report lists.
        var gAt = Nearest(ByFolder, at.Length > 0 ? at.Split('\\') : Array.Empty<string>());
        var onFolder = gAt != null ? ByFolder[gAt] : new List<Grant>();
        foreach (var u in UsersByFolder[at])
        {
            var rank = PermissionRank(u.Permission);
            var covering = onFolder.Where(x => PermissionRank(x.Permission) <= rank).Select(x => x.Member).ToList();
            string basis, hint;
            if (!HasGroupReport) (basis, hint) = ("undecided", "");
            else if (covering.Count > 0) (basis, hint) = ("undecided", string.Join(", ", covering));
            else (basis, hint) = ("direct", "");
            outList.Add(new Grant(u.Member, u.Permission, u.MemberType, basis, hint));
        }
        return outList;
    }
}

public static class Transform
{
    public const string NoPlatform = "(none)";      // an edit that removes the platform on purpose
    public const string NoName = "(none)";          // an edit that leaves the account name empty
    public const string NoAccessNote = "no access groups found; Safe gets no members from the source";
    public const string PlatformInvalid = @"[^A-Za-z0-9_.\-]";
    // Characters removed from every stored text value: control characters, zero-width and BOM.
    public const string UnsafeText = @"[\x00-\x08\x0B-\x1F\x7F\u200b-\u200f\u2028\u2029\u2060\ufeff]";
    // One-line values you type (Safe settings, member names, searchIn): also no tab or line break.
    public const string UnsafeLine = @"[\x00-\x1F\x7F\u200b-\u200f\u2028\u2029\u2060\ufeff]";
    public const string AccountNameInvalid = @"[\\/:;*?""<>|\t\r\n]";
    public const int AccountNameMax = 128;
    const char Nbsp = '\u00a0';

    static string Sub(string pattern, string repl, string s) => PyRe.Compile(pattern).Replace(s ?? "", repl.Replace("$", "$$"));

    /// <summary>int(value) for a config number.</summary>
    public static long IntOf(object v) => v switch
    {
        null => 0,
        bool b => b ? 1 : 0,
        long l => l,
        int i => i,
        double d => (long)Math.Truncate(d),
        string s => long.TryParse(Py.Strip(s), System.Globalization.NumberStyles.AllowLeadingSign,
            System.Globalization.CultureInfo.InvariantCulture, out var n) ? n
            : throw new ValueError($"invalid literal for int() with base 10: {Py.ReprStr(s)}"),
        _ => throw new ValueError($"int() argument must be a string or a number, not {v.GetType().Name}"),
    };

    static string S(object v) => v == null ? "" : Py.Str(v);

    // ----------------------------------------------------------------- Safe names

    /// <summary>Return (clean_name, valid_as_given, issues).</summary>
    public static (string Name, bool Valid, List<string> Issues) SanitizeSafeName(string name, JObj cfg)
    {
        var sc = cfg.Obj("safe_name");
        var invalid = S(sc.Get("invalid_chars"));
        var rep = S(sc.Get("replacement"));
        int maxLen = (int)IntOf(sc.Get("max_length"));
        var issues = new List<string>();
        var raw = name ?? "";
        var cps = Naming.CodePoints(raw);
        var bad = Py.Sorted(cps.Where(c => invalid.Contains(c, StringComparison.Ordinal)).Distinct());
        if (bad.Count > 0) issues.Add("invalid chars " + string.Join(" ", bad));
        var s = string.Concat(cps.Select(c => invalid.Contains(c, StringComparison.Ordinal) ? rep : c));
        s = Sub(UnsafeLine, "", s.Replace(Nbsp, ' '));
        if (rep.Length > 0) s = PyRe.Sub(PyRe.Escape(rep) + "{2,}", rep, s);
        s = Py.Strip(PyRe.Sub(@"\s+", " ", s));
        if (s != raw && bad.Count == 0) issues.Add("whitespace/control chars");
        if (s.Length == 0)
        {
            s = "UNNAMED";
            issues.Add("empty name");
        }
        if (Py.Len(s) > maxLen)
        {
            issues.Add($"length {Py.Len(s)} > {maxLen}");
            s = Py.RStrip(Py.Head(s, maxLen), " " + rep);
        }
        return (s, issues.Count == 0, issues);
    }

    public static string ApplyPrefix(string name, JObj cfg)
    {
        var p = cfg.Obj("safe_name").Get("prefix");
        var prefix = Py.Truthy(p) ? Py.Str(p) : "";
        return prefix.Length == 0 || name.StartsWith(prefix, StringComparison.Ordinal) ? name : prefix + name;
    }

    /// <summary>Different proposed names may clean up to the same Safe; suffix the later ones.
    /// Returns proposed -> (final, collided_with_or_null).</summary>
    public static Dictionary<string, (string, string)> ResolveCollisions(OrderedMap<string, string> proposedToClean, JObj cfg)
    {
        int maxLen = (int)IntOf(cfg.Obj("safe_name").Get("max_length"));
        var r = cfg.Obj("safe_name").Get("replacement");
        var rep = Py.Truthy(r) ? Py.Str(r) : "-";
        var groups = new OrderedMap<string, List<(string, string)>>(StringComparer.Ordinal);
        foreach (var kv in proposedToClean) groups.GetOrAdd(Py.Lower(kv.Value), () => new()).Add((kv.Key, kv.Value));
        var used = new HashSet<string>(groups.Keys, StringComparer.Ordinal);
        var result = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        foreach (var items in groups.Values)
        {
            var (firstProposed, firstClean) = items[0];
            result[firstProposed] = (firstClean, null);
            int n = 2;
            foreach (var (proposed, clean) in items.Skip(1))
            {
                string cand;
                while (true)
                {
                    var suffix = $"{rep}{n}";
                    cand = Py.RStrip(Py.Head(clean, maxLen - Py.Len(suffix))) + suffix;
                    n++;
                    if (!used.Contains(Py.Lower(cand))) break;
                }
                used.Add(Py.Lower(cand));
                result[proposed] = (cand, firstProposed);
            }
        }
        return result;
    }

    // ----------------------------------------------------------------- rules

    /// <summary>Source permission word -> role name (a preset or custom role; unknown names kept as is).</summary>
    public static string RoleFor(string permission, JObj cfg)
    {
        object mapped = "";
        var want = Py.Lower(Py.Strip(permission ?? ""));
        foreach (var kv in cfg.Obj("permission_map")) if (Py.Lower(kv.Key) == want) mapped = kv.Value;
        var r = Config.ResolveRole(mapped, cfg);
        return r.Length > 0 ? r : (mapped == null ? "" : Py.Str(mapped));
    }

    /// <summary>How strong a role is: the number of permissions it grants (0 if undefined).</summary>
    public static int RoleRank(string role, JObj cfg) =>
        role != null && Config.AllRoles(cfg).TryGetValue(role, out var p) ? p.Count : 0;

    static int MinRank(JObj rule, JObj cfg)
    {
        if (Py.Truthy(rule.Get("min_role"))) return RoleRank(Config.ResolveRole(rule.Get("min_role"), cfg), cfg);
        if (Py.Truthy(rule.Get("min_permission"))) return RoleRank(RoleFor(Py.Str(rule.Get("min_permission")), cfg), cfg);
        return 0;
    }

    public static (string, string) MatchGroupRules(List<Grant> grants, JObj cfg, SourceRecord rec = null, (Namer, string)? ctx = null)
    {
        foreach (var ro in cfg.List("group_rules") ?? new List<object>())
        {
            if (ro is not JObj rule) continue;
            int minRank = MinRank(rule, cfg);
            foreach (var g in grants)
            {
                if (minRank > 0 && RoleRank(RoleFor(g.Permission, cfg), cfg) < minRank) continue;
                if (rule.ContainsKey("group") && Py.Lower(g.Member) == Py.Lower(S(rule["group"])))
                    return (Fill(S(rule["safe"]), rec, ctx), $"group_rule:{S(rule["group"])}");
                if (rule.ContainsKey("group_pattern"))
                {
                    var m = PyRe.Search(S(rule["group_pattern"]), g.Member, ignoreCase: true);
                    if (m != null)
                    {
                        var safe = S(rule["safe"]);
                        var groups = PyRe.Groups(m);
                        for (int i = 0; i < groups.Count; i++) safe = safe.Replace("{" + (i + 1) + "}", groups[i] ?? "");
                        return (Fill(safe, rec, ctx), $"group_pattern:{S(rule["group_pattern"])}");
                    }
                }
            }
        }
        return (null, null);
    }

    public static readonly string[] ConventionKeys = { "{convention}", "{folder_abbrev}", "{env}", "{tech}", "{flavor}", "{acct}", "{type}" };

    /// <summary>Expand placeholders in a rule's Safe name. {folder_leaf} {folder_path}: raw folder text.
    /// {convention}: the full naming-convention name. {folder_abbrev} {env} {tech} {flavor} {acct} {type}:
    /// single convention layers, e.g. "APP-{1}-{env}-{flavor}".</summary>
    public static string Fill(string safe, SourceRecord rec, (Namer, string)? ctx = null)
    {
        if (rec == null || !safe.Contains('{')) return safe;
        if (ctx != null && ConventionKeys.Any(k => safe.Contains(k, StringComparison.Ordinal)))
        {
            var (namer, platform) = ctx.Value;
            var (name, notes) = Py.Strip(safe) == "{convention}"
                ? namer.Build(rec, platform)
                : namer.Build(rec, platform, template: safe.Replace("{folder_abbrev}", "{folder}"));
            namer.LastNotes = notes;
            namer.Used = true;
            return name;
        }
        var leaf = rec.Folder.Count > 0 ? rec.Folder[^1] : "";
        return safe.Replace("{folder_leaf}", leaf).Replace("{folder_path}", string.Join("-", rec.Folder));
    }

    public static (string, string) MatchFolderRules(SourceRecord rec, JObj cfg, (Namer, string)? ctx = null)
    {
        var folder = rec.Folder.Select(Py.Lower).ToList();
        (List<string> Prefix, string Safe, string Raw)? best = null;
        foreach (var ro in cfg.List("folder_rules") ?? new List<object>())
        {
            if (ro is not JObj rule) continue;
            var raw = S(rule["folder_prefix"]);
            var prefix = SourceRecord.SplitFolder(raw, "\\").Select(Py.Lower).ToList();
            if (folder.Take(prefix.Count).SequenceEqual(prefix) && folder.Count >= prefix.Count
                && (best == null || prefix.Count > best.Value.Prefix.Count))
                best = (prefix, S(rule["safe"]), raw);
        }
        if (best != null) return (Fill(best.Value.Safe, rec, ctx), "folder_rule:" + best.Value.Raw);
        return (null, null);
    }

    /// <summary>(person, folder rule) when the record is in a personal folder, else (null, null).
    /// The most specific folder wins.</summary>
    public static (string, string) PersonalFolder(SourceRecord rec, JObj cfg)
    {
        var folder = rec.Folder.Select(Py.Lower).ToList();
        (int Len, string Person, string Raw)? best = null;
        foreach (var ro in cfg.Obj("personal_safes")?.List("folders") ?? new List<object>())
        {
            if (ro is not JObj row) continue;
            var raw = S(row.Get("folder"));
            var prefix = SourceRecord.SplitFolder(raw, "auto").Select(Py.Lower).ToList();
            if (prefix.Count == 0 || folder.Count < prefix.Count || !folder.Take(prefix.Count).SequenceEqual(prefix)) continue;
            var person = Py.Strip(S(row.Get("person")));
            if (person.Length == 0)
            {
                if (rec.Folder.Count <= prefix.Count) continue;   // a secret in the parent folder itself is nobody's
                person = rec.Folder[prefix.Count];
            }
            if (best == null || prefix.Count > best.Value.Len) best = (prefix.Count, person, raw);
        }
        return best != null ? (best.Value.Person, best.Value.Raw) : (null, null);
    }

    /// <summary>(first, last) from "Jane Smith" or "Smith, Jane".</summary>
    public static (string, string) SplitPerson(string name)
    {
        name = string.Join(" ", Py.SplitWs(name ?? ""));
        if (name.Contains(','))
        {
            var i = name.IndexOf(',');
            string last = Py.Strip(name.Substring(0, i)), first = Py.Strip(name.Substring(i + 1));
            return (first.Length > 0 ? first.Split(' ')[0] : "", last);
        }
        var words = name.Split(' ');
        return (words[0], words.Length > 1 ? words[^1] : "");
    }

    /// <summary>"Smith, Jane" -> "Jane Smith"; other names as they are (spaces tidied).</summary>
    static string NaturalOrder(string name)
    {
        name = string.Join(" ", Py.SplitWs(name ?? ""));
        if (!name.Contains(',')) return name;
        var i = name.IndexOf(',');
        string last = Py.Strip(name.Substring(0, i)), rest = Py.Strip(name.Substring(i + 1));
        return string.Join(" ", new[] { rest, last }.Where(x => x.Length > 0));
    }

    /// <summary>(UPN or "", note, the name the users list knows) for the person a personal folder is
    /// named after ("Smith, Jane" is found as "Jane Smith").</summary>
    public static (string, string, string) PersonUpn(string person, References refs)
    {
        if (person.Contains('@')) return (person, "", person);
        if (refs == null) return ("", "", person);
        var (found, why) = refs.UpnFor(person);
        if (string.IsNullOrEmpty(found) && person.Contains(','))
        {
            var (found2, why2) = refs.UpnFor(NaturalOrder(person));
            if (!string.IsNullOrEmpty(found2)) return (found2, "", NaturalOrder(person));
            if ((why2 ?? "").Contains("pick the right one")) why = why2;
        }
        return (found ?? "", string.IsNullOrEmpty(found) ? why ?? "" : "", person);
    }

    /// <summary>(Safe name, notes) for a person's personal Safe, from personal_safes.template.</summary>
    public static (string, List<string>) PersonalSafe(string person, JObj cfg, References refs = null)
    {
        var notes = new List<string>();
        var (upn, why, _) = PersonUpn(person, refs);
        if (upn.Length == 0)
        {
            if (why.Length > 0)
                notes.Add($"CHECK: {person} is " + (why.Contains("pick the right one") ? "in the users list more than once"
                          : "not in the users list") + ", so the personal Safe is named from the folder name");
        }
        if (refs != null && !refs.HasUsers && upn.Length == 0)
            notes.Add($"personal Safe of {person}: load the users list to name it after the username");
        var user = upn.Length > 0 ? upn.Split('@', 2)[0] : NaturalOrder(person.Split('\\')[^1]).Replace(" ", "");
        var (first, last) = SplitPerson(person.Contains('@') ? user.Replace(".", " ") : person);
        var tmpl = S(cfg.Obj("personal_safes")?.Get("template"));
        if (tmpl.Length == 0) tmpl = "P-{user}";
        var name = tmpl.Replace("{user}", user).Replace("{upn}", upn.Length > 0 ? upn : user).Replace("{first}", first)
                       .Replace("{last}", last).Replace("{name}", person);
        return (name, notes);
    }

    /// <summary>The person a personal Safe belongs to is a member with at least the owner role. seen: the
    /// members the folder reports already gave for this person on this account.</summary>
    static void AddOwner(OrderedMap<(string, string), MemberInfo> members, Dictionary<MemberInfo, List<string>> why,
        AccountPlan p, string owner, List<MemberInfo> seen, string role, JObj cfg)
    {
        List<string> Why(MemberInfo m) => why.TryGetValue(m, out var l) ? l : why[m] = new List<string>();
        foreach (var m in seen)
        {
            if (RoleRank(role, cfg) > RoleRank(m.Role, cfg))
            {
                m.Role = role;
                var note = $"role raised to {role}: owner of this personal Safe";
                if (!Why(m).Contains(note)) Why(m).Add(note);
            }
        }
        if (seen.Count > 0) return;
        var mm = members.GetOrAdd((p.Safe, Py.Lower(owner)), () => new MemberInfo
            { SourceName = owner, Type = "User", Role = role, Permission = "" });
        if (mm.Ids.Add(p)) mm.Accounts++;
        if (RoleRank(role, cfg) > RoleRank(mm.Role, cfg)) mm.Role = role;
        var folder = p.Rec.FolderPath;
        var n = p.Grants.Count > 0
            ? $"owner of this personal Safe: added by the Workbench. CHECK: the folder permissions for {folder} don't include this person"
            : $"owner of this personal Safe: added by the Workbench (the source has no permissions for {folder})";
        if (!Why(mm).Contains(n)) Why(mm).Add(n);
    }

    public static (string, string) FallbackSafe(SourceRecord rec, JObj cfg, (Namer, string)? ctx = null)
    {
        var strategy = S(cfg.Get("fallback_strategy"));
        if (strategy == "convention" && ctx != null)
        {
            var name = Fill("{convention}", rec, ctx);
            return (string.IsNullOrEmpty(name) ? "UNMAPPED" : name, "fallback:convention");
        }
        if (strategy == "unmapped" || rec.Folder.Count == 0) return ("UNMAPPED", "fallback:unmapped");
        if (strategy == "folder_path") return (string.Join("-", rec.Folder), "fallback:folder_path");
        return (rec.Folder[^1], "fallback:folder_leaf");
    }

    static string RuleField(SourceRecord rec, string name)
    {
        switch (name)
        {
            case "type": return rec.Type;
            case "folder": return rec.FolderPath;
            case "name": return rec.Name;
            case "address": return rec.Address;
            case "username": return rec.Username;
        }
        var want = Py.Lower(name);
        foreach (var kv in rec.Extra) if (Py.Lower(kv.Key) == want) return kv.Value;
        return "";
    }

    public static (string, string) ResolvePlatform(SourceRecord rec, JObj cfg)
    {
        if (!string.IsNullOrEmpty(rec.TargetPlatform)) return (rec.TargetPlatform, "source");
        foreach (var ro in cfg.List("platform_rules") ?? new List<object>())
        {
            if (ro is not JObj rule) continue;
            var field = rule.ContainsKey("field") ? S(rule["field"]) : "type";
            // Case-insensitive, like every other pattern in the rules.
            if (PyRe.Search(S(rule["pattern"]), RuleField(rec, field), ignoreCase: true) != null)
                return (S(rule["platform"]), $"platform_rule:{field}");
        }
        object hit = null;
        bool found = false;
        var t = Py.Lower(rec.Type);
        foreach (var kv in cfg.Obj("platform_map")) if (Py.Lower(kv.Key) == t) { hit = kv.Value; found = true; }
        if (found) return (S(hit), "platform_map");
        var d = cfg.Get("default_platform");
        return (Py.Truthy(d) ? Py.Str(d) : "", "default");
    }

    public static (string Domain, string Short) SplitMember(string name)
    {
        int at = name.LastIndexOf('\\');
        string domain = at >= 0 ? name.Substring(0, at) : "", shortName = at >= 0 ? name.Substring(at + 1) : name;
        if (domain.Length == 0 && name.Contains('@'))
        {
            int a = name.IndexOf('@');
            shortName = name.Substring(0, a);
            domain = name.Substring(a + 1);
        }
        return (domain, shortName);
    }

    static string FirstLabel(string d) => d.Split('.')[0];

    static bool SourceMatches(JObj src, string name, string domain, string memberType)
    {
        // Group sources also take roles: like groups, they are named without a domain.
        var kind = Py.Lower(Py.Truthy(src.Get("members")) ? Py.Str(src.Get("members")) : "both");
        var mt = Py.Lower(memberType ?? "");
        if ((kind == "groups" && mt == "user") || (kind == "users" && mt != "user")) return false;
        var match = Py.Strip(Py.Truthy(src.Get("match")) ? Py.Str(src.Get("match")) : "*");
        if (match == "*") return true;
        if (Py.Lower(match).StartsWith("re:", StringComparison.Ordinal))
            return PyRe.Search(match.Substring(3), name, ignoreCase: true) != null;
        var m = Py.Lower(match);
        var d = Py.Lower(domain);
        return d.Length > 0 && (d == m || FirstLabel(d) == m || FirstLabel(m) == d);
    }

    /// <summary>spec: one or more domains separated by , or ; (CORP, corp.example.com) or * for every member.</summary>
    public static bool DomainMatches(string spec, string domain)
    {
        var d = Py.Lower(domain ?? "");
        foreach (var part in PyRe.Split(@"[,;]+", spec ?? ""))
        {
            var m = Py.LStrip(Py.Lower(Py.Strip(part)), "@");
            if (m.Length == 0) continue;
            if (m == "*") return true;
            if (d.Length > 0 && (d == m || FirstLabel(d) == m || FirstLabel(m) == d)) return true;
        }
        return false;
    }

    public static readonly string[] DomainMapKinds = { "users", "groups", "roles" };

    /// <summary>'users', 'groups', 'roles' or a combination joined with + ('users+groups'); 'both' or
    /// 'all' = every kind. Empty = users.</summary>
    public static HashSet<string> DomainMapKindsOf(object value)
    {
        var v = Py.Lower(Py.Strip(Py.Truthy(value) ? Py.Str(value) : "users"));
        if (v == "both" || v == "all") return new HashSet<string>(DomainMapKinds);
        var set = PyRe.Split(@"[+,\s]+", v).Where(k => DomainMapKinds.Contains(k)).ToHashSet();
        return set.Count > 0 ? set : new HashSet<string> { "users" };
    }

    /// <summary>The domain conversion rows (domain_map), checked top to bottom: the first whose "from"
    /// domains and member kind fit gives the name with the domain dropped or in UPN form (short@to),
    /// and a label for the row. (null, "") when no row fits.</summary>
    public static (string, string) ConvertDomain(JObj cfg, string domain, string shortName, string memberType)
    {
        var mt = Py.Lower(NormalizeMemberType(memberType, "Group")) + "s";
        foreach (var ro in cfg.List("domain_map") ?? new List<object>())
        {
            if (ro is not JObj row) continue;
            if (!DomainMapKindsOf(row.Get("members")).Contains(mt)) continue;
            if (DomainMatches(row.Get("from") as string, domain))
            {
                var to = Py.LStrip(Py.Strip(Py.Truthy(row.Get("to")) ? Py.Str(row.Get("to")) : ""), "@");
                return (to.Length > 0 ? $"{shortName}@{to}" : shortName, $"domain conversion {Py.Strip(S(row.Get("from", "")))}");
            }
        }
        return (null, "");
    }

    static string ConvertMemberName(JObj src, string name, string domain, string shortName, string mapped)
    {
        string out_;
        if (mapped != null) out_ = mapped;
        else out_ = domain.Length > 0 && Py.Truthy(src.Get("strip_domain", true)) ? shortName : name;
        if (Py.Truthy(src.Get("find")))
            out_ = PyRe.Sub(Py.Str(src.Get("find")), S(src.Get("replace", "")), out_, ignoreCase: true);
        out_ = $"{S(src.Get("add_prefix", ""))}{out_}{S(src.Get("add_suffix", ""))}";
        var c = Py.Lower(Py.Truthy(src.Get("case")) ? Py.Str(src.Get("case")) : "keep");
        return c == "lower" ? Py.Lower(out_) : c == "upper" ? Py.Upper(out_) : out_;
    }

    public static readonly string[] MemberTypes = { "User", "Group", "Role" };

    /// <summary>'group', 'USER', 'role' -> Group / User / Role; anything else -> default.</summary>
    public static string NormalizeMemberType(object value, string dflt = "Group")
    {
        var v = Py.Lower(Py.Strip(Py.Truthy(value) ? Py.Str(value) : ""));
        foreach (var t in MemberTypes)
            if (v == Py.Lower(t) || v == Py.Lower(t) + "s") return t;
        return MemberTypes.Contains(dflt) ? dflt : "Group";
    }

    /// <summary>'CORP\Group' -> (memberName, searchIn, source name) using domain_map, directory_sources,
    /// then directory_map.</summary>
    public static (string Name, string SearchIn, string Source) MemberTarget(string name, JObj cfg, string memberType = "")
    {
        var (domain, shortName) = SplitMember(name);
        if (string.IsNullOrEmpty(memberType)) memberType = S(cfg.Get("default_member_type", "Group"));
        // Domain conversion comes first; a directory source's find/replace, added text and case then work on its result.
        var (mapped, mappedBy) = ConvertDomain(cfg, domain, shortName, memberType);
        foreach (var so in cfg.List("directory_sources") ?? new List<object>())
        {
            if (so is not JObj src) continue;
            if (SourceMatches(src, name, domain, memberType))
            {
                var label = Py.Truthy(src.Get("name")) ? Py.Str(src.Get("name")) : Py.Truthy(src.Get("match")) ? Py.Str(src.Get("match")) : "";
                return (ConvertMemberName(src, name, domain, shortName, mapped),
                        Py.Truthy(src.Get("search_in")) ? Py.Str(src.Get("search_in")) : "", label);
            }
        }
        var dmap = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var kv in cfg.Obj("directory_map")) dmap[Py.Lower(kv.Key)] = kv.Value;
        object Get(string k) => dmap.TryGetValue(k, out var v) ? v : null;
        object star = dmap.TryGetValue("*", out var sv) ? sv : "";
        object searchIn;
        if (domain.Length > 0)
        {
            searchIn = Get(Py.Lower(domain));
            if (!Py.Truthy(searchIn)) searchIn = Get(Py.Lower(FirstLabel(domain)));
            if (!Py.Truthy(searchIn)) searchIn = star;
        }
        else searchIn = star;
        var si = S(searchIn);
        if (mapped != null) return (mapped, si, mappedBy);
        var member = domain.Length > 0 && Py.Truthy(cfg.Get("strip_domain_prefix")) ? shortName : name;
        return (member, si, "");
    }

    // ----------------------------------------------------------------- overrides

    /// <summary>Read an edited Accounts_Review.csv. Returns Record_ID -> {column: value}.</summary>
    public static Dictionary<string, Dictionary<string, string>> LoadOverrides(string path, string encoding = "utf-8-sig")
    {
        var out_ = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        CsvSafe.Reading(path, () =>
        {
            var reader = new Csv.DictReader(Csv.ReadText(path, encoding));
            foreach (var row in reader.Rows())
            {
                var rid = Py.Strip(CsvSafe.Unescape(Py.Strip(row["Record_ID"] ?? "")));
                if (rid.Length == 0) continue;
                var d = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var kv in row)
                    if (!string.IsNullOrEmpty(kv.Key)) d[kv.Key] = Py.Strip(CsvSafe.Unescape(Py.Strip(kv.Value ?? "")));
                out_[rid] = d;
            }
            return 0;
        });
        Log.Info($"overrides: {out_.Count} rows from {path}");
        return out_;
    }

    /// <summary>True when a review-file value was edited (ignores the -N/_N suffixes this tool adds).</summary>
    public static bool Changed(string edited, string computed)
    {
        if (string.IsNullOrEmpty(edited)) return false;
        string e = Py.Lower(Py.Strip(edited)), c = Py.Lower(Py.Strip(computed ?? ""));
        if (e == c) return false;
        var m = PyRe.MatchStart(@"^(.*)([-_]\d+)$", e);
        if (m == null) return true;
        string stem = m.Groups[1].Value, suffix = m.Groups[2].Value;
        // The suffix may have been added after cutting the name to fit a length limit.
        int sl = Py.Len(suffix);
        foreach (var limit in new[] { Py.Len(c) + sl, 28, AccountNameMax })
            if (stem == Py.RStrip(Py.Head(c, limit - sl), " -_")) return false;
        return true;
    }

    static bool ExplicitChanged(string edited, string computed) =>
        !string.IsNullOrEmpty(edited) && Py.Lower(Py.Strip(edited)) != Py.Lower(Py.Strip(computed ?? ""));

    /// <summary>Recompute Safe and member totals after in_scope or migrate changed.</summary>
    public static Plan RebuildTotals(Plan plan, JObj cfg)
    {
        plan.Safes = BuildSafes(plan.Accounts, cfg, plan.SafeOverrides);
        plan.Undecided = new List<UndecidedUser>();
        plan.Members = BuildMembers(plan.Accounts, cfg, plan.MemberEdits, plan.MemberOverrides, plan.Refs, plan.Undecided);
        FlagSafesWithoutFullMember(plan.Safes, plan.Members, cfg);
        return plan;
    }

    static string OvGet(Dictionary<string, string> ov, string k) => ov.TryGetValue(k, out var v) ? v : null;

    /// <summary>explicit=true: overrides are deliberate edits (database), not a re-fed review file.
    /// safeOverrides: lower Safe name as the rules give it -> {"new_name": ..., settings...}.</summary>
    public static Plan BuildPlan(IEnumerable<SourceRecord> records, JObj cfg, Permissions perms = null,
        Dictionary<string, Dictionary<string, string>> overrides = null, bool @explicit = false,
        List<JObj> memberEdits = null, Dictionary<string, JObj> memberOverrides = null,
        Dictionary<string, JObj> safeOverrides = null, References refs = null)
    {
        safeOverrides ??= new Dictionary<string, JObj>(StringComparer.Ordinal);
        Func<string, string, bool> changed = @explicit ? ExplicitChanged : Changed;
        perms ??= new Permissions();
        overrides ??= new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        var plans = new List<AccountPlan>();
        var recs = records.ToList();
        var allIds = recs.Select(r => r.RecordId).ToHashSet(StringComparer.Ordinal);
        var usedIds = new HashSet<string>(StringComparer.Ordinal);
        var dupCount = new Dictionary<string, int>(StringComparer.Ordinal);
        var namer = new Namer(cfg);
        var conventionFolders = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var empty = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var rec in recs)
        {
            var p = new AccountPlan(rec);
            p.Warnings.AddRange(rec.Notes.Where(n => !n.StartsWith(SourceRecord.ErrorNote, StringComparison.Ordinal)));
            p.Errors.AddRange(rec.Notes.Where(n => n.StartsWith(SourceRecord.ErrorNote, StringComparison.Ordinal))
                                       .Select(n => n.Substring(SourceRecord.ErrorNote.Length)));
            // A secrets export without a template column: the template list gives it.
            if (refs != null && string.IsNullOrEmpty(rec.Type))
            {
                var (tmpl, why) = refs.TemplateFor(rec.Name, rec.Folder);
                rec.Type = tmpl;
                if (why.Length > 0) p.Warnings.Add(why);
            }
            // Access (looked up by the source's own id, before a duplicate id is suffixed)
            if (rec.Grants != null)
            {
                p.Grants = rec.Grants.ToList();
                p.AccessSource = string.IsNullOrEmpty(rec.AccessSource) ? "source" : rec.AccessSource;
            }
            else if (perms.Loaded)
            {
                var (g, how) = perms.Resolve(rec);
                p.Grants = g.ToList();
                p.AccessSource = how;
            }
            else p.AccessSource = "none";
            // Only a real duplicate in this run is suffixed.
            if (usedIds.Contains(rec.RecordId))
            {
                var bas = rec.SourceId;
                int n = (dupCount.TryGetValue(rec.RecordId, out var dc) ? dc : 1) + 1;
                rec.SourceId = $"{bas}#{n}";
                while (usedIds.Contains(rec.RecordId) || allIds.Contains(rec.RecordId))
                {
                    n++;
                    rec.SourceId = $"{bas}#{n}";
                }
                dupCount[$"{rec.Source}:{rec.SourceFile}:{bas}"] = n;
                p.Warnings.Add("duplicate id in the source; suffixed in Record_ID");
            }
            usedIds.Add(rec.RecordId);
            // Address first, so platform and Safe rules, the account name template and the output all see the same value.
            if (Py.Truthy(cfg.Get("url_address_to_host")) && rec.Address.Contains("://"))
                rec.Address = Adapter.AddressFromUrl(rec.Address);
            var ov = overrides.TryGetValue(rec.RecordId, out var o) ? o : empty;
            if (p.Grants.Count == 0) p.SafeNotes.Add(NoAccessNote);

            // Platform
            (p.Platform, p.PlatformSource) = ResolvePlatform(rec, cfg);
            if (OvGet(ov, "Platform_ID") == NoPlatform)
            {
                (p.Platform, p.PlatformSource) = ("", "override");
                p.Errors.Add("no platform: removed by you");
            }
            else if (changed(OvGet(ov, "Platform_ID"), p.Platform))
                (p.Platform, p.PlatformSource) = (ov["Platform_ID"], "override");
            p.Platform = Sub(UnsafeLine, "", p.Platform ?? "");
            if (p.Platform.Length > 0 && PyRe.Search(PlatformInvalid, p.Platform) != null)
            {
                var bad = string.Join(" ", Py.Sorted(PyRe.FindAll(PlatformInvalid, p.Platform)
                    .Select(c => c != " " ? ReprInner(c) : "space").Distinct()));
                var clean = Sub(PlatformInvalid, "_", p.Platform);
                p.Warnings.Add($"forbidden characters in platform ID '{p.Platform}' ({bad}); changed to " +
                               $"'{clean}', check that platform exists");
                p.Platform = clean;
            }
            if (p.Platform.Length == 0 && p.PlatformSource != "override")
                p.Errors.Add($"no platform for type '{rec.Type}'; add it to platform_map");

            // Safe
            (Namer, string)? ctx = (namer, p.Platform);
            namer.LastNotes = new List<string>();
            namer.Used = false;
            string safe = null, src = null;
            if (!string.IsNullOrEmpty(rec.TargetSafe)) (safe, src) = (rec.TargetSafe, "source");
            if (string.IsNullOrEmpty(safe))
            {
                var (person, pfolder) = PersonalFolder(rec, cfg);
                if (person != null)
                {
                    var (pname, why) = PersonalSafe(person, cfg, refs);
                    (safe, src) = (pname, "personal:" + pfolder);
                    p.Personal = person;
                    p.SafeNotes.Add($"personal Safe of {person}");
                    p.SafeNotes.AddRange(why);
                }
            }
            var rules = new List<Func<(string, string)>>
            {
                () => MatchFolderRules(rec, cfg, ctx),
                () => MatchGroupRules(p.Grants, cfg, rec, ctx),
            };
            if (Py.Truthy(cfg.Get("group_rules_first"))) rules.Reverse();
            foreach (var rule in rules)
                if (string.IsNullOrEmpty(safe)) (safe, src) = rule();
            bool fellBack = string.IsNullOrEmpty(safe);
            if (string.IsNullOrEmpty(safe)) (safe, src) = FallbackSafe(rec, cfg, ctx);
            safe = src == "source" ? safe : ApplyPrefix(safe, cfg);
            // An edited review file repeats every value; only a changed one is an override.
            if (changed(OvGet(ov, "Target_Safe"), SanitizeSafeName(safe, cfg).Name))
                (safe, src, fellBack) = (ov["Target_Safe"], "override", false);
            if (fellBack && src == "fallback:unmapped")
                p.Warnings.Add("no Safe: no rule matched and no folder to name it from");
            p.ProposedSafe = safe;
            p.SafeSource = src;
            if (src != "override" && namer.LastNotes.Count > 0)
                p.SafeNotes.AddRange(namer.LastNotes.Select(n => "Safe name: " + n));
            p.ByConvention = (namer.Used || src.StartsWith("fallback:folder", StringComparison.Ordinal)) && src != "override";
            if (p.ByConvention)
            {
                var key = Py.Lower(safe);
                if (!conventionFolders.TryGetValue(key, out var set)) conventionFolders[key] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(rec.FolderPath);
            }

            // Account name
            var name = AccountNameFor(rec, p, cfg);
            if (changed(OvGet(ov, "Account_Name"), Py.Strip(Sub(AccountNameInvalid, "_", name))))
                name = ov["Account_Name"];
            if (Py.Lower(Py.Strip(name)) == NoName) name = "";   // left empty on purpose: Privilege Cloud generates one
            var unsafe_ = Sub(UnsafeText, "", name);
            if (unsafe_ != name)
            {
                p.Warnings.Add("invisible or control characters removed from the account name");
                name = unsafe_;
            }
            var cleanName = Py.Strip(Sub(AccountNameInvalid, "_", name));
            if (Py.Len(cleanName) > AccountNameMax)
            {
                cleanName = Py.Head(cleanName, AccountNameMax);
                p.Warnings.Add($"account name cut to {AccountNameMax} characters");
            }
            if (cleanName != name && Py.Len(name) <= AccountNameMax)
            {
                var bad = string.Join(" ", Py.Sorted(PyRe.FindAll(AccountNameInvalid, name).Select(ReprInner).Distinct()));
                p.Warnings.Add($"forbidden characters in account name ({bad}) replaced with _");
            }
            p.AccountName = cleanName;

            if (string.IsNullOrEmpty(rec.Username)) p.Errors.Add("no username");
            if (string.IsNullOrEmpty(rec.Address)) p.Warnings.Add("no address");

            var mig = Py.Upper(string.IsNullOrEmpty(OvGet(ov, "Migrate")) ? "Y" : ov["Migrate"]);
            p.Migrate = mig is "N" or "NO" or "FALSE" or "0" ? "N" : "Y";
            plans.Add(p);
        }

        foreach (var p in plans)
        {
            var n = conventionFolders.TryGetValue(Py.Lower(p.ProposedSafe), out var f) ? f.Count : 0;
            if (p.ByConvention && n > 1)
                p.SafeNotes.Add($"Safe shared by {n} source folders; check least privilege");
        }

        if (Py.Truthy(cfg.Get("safe_split_over_max"))) SplitLargeSafes(plans, cfg);

        // Clean Safe names and resolve collisions across the whole run.
        var cleaned = new OrderedMap<string, (string Name, bool Valid, List<string> Issues)>(StringComparer.Ordinal);
        foreach (var p in plans)
            if (!cleaned.ContainsKey(p.ProposedSafe)) cleaned[p.ProposedSafe] = SanitizeSafeName(p.ProposedSafe, cfg);
        var toClean = new OrderedMap<string, string>(StringComparer.Ordinal);
        foreach (var kv in cleaned) toClean[kv.Key] = kv.Value.Name;
        var final_ = ResolveCollisions(toClean, cfg);

        // Safe names compare without case in Privilege Cloud: a rename onto an existing Safe in another
        // case joins it, spelled as that Safe is.
        var spelling = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in toClean.Keys) { var nm = final_[k].Item1; spelling[Py.Lower(nm)] = nm; }
        var dupes = new OrderedMap<(string, string), List<AccountPlan>>();
        foreach (var p in plans)
        {
            var (_, valid, issues) = cleaned[p.ProposedSafe];
            var (fin, collided) = final_[p.ProposedSafe];
            p.Safe = fin;
            p.SafeIssues = issues.ToList();
            if (collided != null)
            {
                p.SafeIssues.Add($"same name as '{collided}' after cleanup; suffixed");
                valid = false;
            }
            p.ValidSafe = valid;
            p.RuleSafe = p.Safe;
            var newName = safeOverrides.TryGetValue(Py.Lower(p.Safe), out var so) && so != null ? so.Get("new_name") : null;
            if (Py.Truthy(newName))
            {
                // You renamed this whole Safe: its accounts follow, whatever the rules gave.
                var (sn, sv, si) = SanitizeSafeName(Py.Str(newName), cfg);
                (p.Safe, p.ValidSafe, p.SafeIssues) = (sn, sv, si);
                var low = Py.Lower(p.Safe);
                if (spelling.TryGetValue(low, out var sp)) p.Safe = sp; else spelling[low] = p.Safe;
                p.SafeSource = "Safe renamed by you";
            }
            // Same username and address (trimmed, any case) is a possible duplicate wherever it is.
            string user = Py.Lower(Py.Strip(p.Rec.Username)), addr = Py.Lower(Py.Strip(p.Rec.Address));
            if (p.Migrate == "Y" && p.InScope && user.Length > 0 && addr.Length > 0)
                dupes.GetOrAdd((user, addr), () => new()).Add(p);
        }
        UniqueAccountNames(plans);
        FlagDuplicates(dupes.Values);

        // A Safe you renamed onto a name another Safe already has: both now share one Safe.
        var fromRules = plans.Where(p => p.RuleSafe == p.Safe).Select(p => Py.Lower(p.Safe)).ToHashSet(StringComparer.Ordinal);
        foreach (var p in plans)
            if (p.RuleSafe != p.Safe && fromRules.Contains(Py.Lower(p.Safe)))
                p.SafeNotes.Add($"Safe '{p.RuleSafe}' renamed by you to '{p.Safe}', which another Safe " +
                                "already has: their accounts are now in one Safe");

        var safes = BuildSafes(plans, cfg, safeOverrides);
        var undecided = new List<UndecidedUser>();
        var members = BuildMembers(plans, cfg, memberEdits, memberOverrides, refs, undecided);
        FlagSafesWithoutFullMember(safes, members, cfg);
        return new Plan
        {
            Accounts = plans, Safes = safes, Members = members, Undecided = undecided, Refs = refs,
            MemberEdits = (memberEdits ?? new List<JObj>()).ToList(),
            MemberOverrides = new Dictionary<string, JObj>(memberOverrides ?? new Dictionary<string, JObj>(), StringComparer.Ordinal),
            SafeOverrides = new Dictionary<string, JObj>(safeOverrides, StringComparer.Ordinal),
        };
    }

    /// <summary>repr(c)[1:-1]</summary>
    static string ReprInner(string c)
    {
        var r = Py.ReprStr(c);
        return r.Substring(1, r.Length - 2);
    }

    static readonly string[] SplitNotFor = { "source", "override" };     // a Safe the source or you named is never split

    /// <summary>Spread the accounts of a Safe over the account limit over numbered Safes (NAME-01, NAME-02...),
    /// of about the same size, sorted by address then username so one server's accounts stay together.</summary>
    public static void SplitLargeSafes(List<AccountPlan> plans, JObj cfg)
    {
        long limit = IntOf(Py.Or(cfg.Get("safe_max_accounts"), 0L));
        if (limit <= 0) return;
        var conv = cfg.Obj("safe_convention");
        var sepObj = conv == null || !conv.ContainsKey("separator") ? "-" : conv["separator"];
        var sep = Py.Truthy(sepObj) ? Py.Str(sepObj) : "-";
        int maxLen = (int)IntOf(cfg.Obj("safe_name").Get("max_length"));
        var groups = new OrderedMap<string, List<AccountPlan>>(StringComparer.Ordinal);
        foreach (var p in plans)
            if (!SplitNotFor.Contains(p.SafeSource)) groups.GetOrAdd(p.ProposedSafe, () => new()).Add(p);
        foreach (var (bas, items0) in groups)
        {
            int migrating = items0.Count(p => p.Migrate == "Y");
            if (migrating <= limit) continue;
            long parts = (migrating + limit - 1) / limit;
            long per = (migrating + parts - 1) / parts;
            var items = Py.Sorted(items0, (a, b) =>
            {
                int c = Py.Cmp(Py.Lower(Py.Strip(a.Rec.Address)), Py.Lower(Py.Strip(b.Rec.Address)));
                if (c == 0) c = Py.Cmp(Py.Lower(Py.Strip(a.Rec.Username)), Py.Lower(Py.Strip(b.Rec.Username)));
                if (c == 0) c = Py.Cmp(a.Rec.RecordId, b.Rec.RecordId);
                return c;
            });
            int digits = Math.Max(2, parts.ToString(System.Globalization.CultureInfo.InvariantCulture).Length);
            long part = 1, filled = 0;
            foreach (var p in items)
            {
                if (p.Migrate == "Y")
                {
                    if (filled == per && part < parts) { part++; filled = 0; }
                    filled++;
                }
                var suffix = sep + part.ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(digits, '0');
                p.ProposedSafe = Py.RStrip(Py.Head(bas, maxLen - Py.Len(suffix)), " " + sep) + suffix;
                p.SafeNotes.Add($"Safe split: '{bas}' would hold {migrating} accounts, over the {limit} " +
                                $"per Safe, so its accounts are spread over {parts} Safes by address " +
                                $"(part {part} of {parts})");
            }
        }
    }

    public const string DuplicateNote = "possible duplicate";

    /// <summary>How another copy y differs from account x, so the note says where to look.</summary>
    static string Describe(AccountPlan y, AccountPlan x)
    {
        var where = new List<string>();
        if (y.Rec.SourceFile != x.Rec.SourceFile || y.Rec.Source != x.Rec.Source) where.Add($"file {y.Rec.SourceFile}");
        where.Add(Py.Lower(y.Safe) == Py.Lower(x.Safe) ? "same Safe" : $"Safe {y.Safe}");
        var label = string.IsNullOrEmpty(y.Rec.Name) ? "" : $"'{y.Rec.Name}' ";
        return $"{label}{y.Rec.RecordId} ({string.Join(", ", where)})";
    }

    /// <summary>Note every account that shares its username and address with another account.</summary>
    public static void FlagDuplicates(IEnumerable<List<AccountPlan>> groups)
    {
        foreach (var group in groups)
        {
            if (group.Count < 2) continue;
            foreach (var x in group)
            {
                var others = group.Where(y => !ReferenceEquals(y, x)).ToList();
                var more = others.Count > 3 ? $" and {others.Count - 3} more" : "";
                bool sameSafeNoName = string.IsNullOrEmpty(x.AccountName) && others.Any(y =>
                    Py.Lower(y.Safe) == Py.Lower(x.Safe) && y.Rec.SecretType == x.Rec.SecretType && string.IsNullOrEmpty(y.AccountName));
                x.Warnings.Add($"{DuplicateNote}: same username and address as "
                               + string.Join("; ", others.Take(3).Select(y => Describe(y, x))) + more
                               + (sameSafeNoName ? ". With no account name Privilege Cloud gives both the same " +
                                                   "name and rejects the second"
                                                 : ". Keep one, or set the others to not migrate"));
            }
        }
    }

    /// <summary>Account names must be unique within a Safe. The first account keeps its name; later
    /// duplicates get _2, _3, ... skipping any name already used (or still to come) in that Safe.</summary>
    static void UniqueAccountNames(List<AccountPlan> plans)
    {
        var taken = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        HashSet<string> Set(Dictionary<string, HashSet<string>> d, string k)
        {
            if (!d.TryGetValue(k, out var s)) d[k] = s = new HashSet<string>(StringComparer.Ordinal);
            return s;
        }
        foreach (var p in plans)
            if (p.Uploadable) Set(taken, Py.Lower(p.Safe)).Add(Py.Lower(p.AccountName));
        var claimed = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var p in plans)
        {
            if (!p.Uploadable) continue;
            var safe = Py.Lower(p.Safe);
            if (string.IsNullOrEmpty(p.AccountName)) continue;   // Privilege Cloud names it
            var cl = Set(claimed, safe);
            if (!cl.Contains(Py.Lower(p.AccountName)))
            {
                cl.Add(Py.Lower(p.AccountName));
                continue;
            }
            var tk = Set(taken, safe);
            int n = 2;
            string cand;
            while (true)
            {
                var suffix = $"_{n}";
                cand = Py.Head(p.AccountName, AccountNameMax - suffix.Length) + suffix;
                if (!tk.Contains(Py.Lower(cand)) && !cl.Contains(Py.Lower(cand))) break;
                n++;
            }
            cl.Add(Py.Lower(cand));
            p.AccountName = cand;
            p.Warnings.Add("duplicate account name in Safe; suffixed");
        }
    }

    /// <summary>Account name from account_name.template, else account_name.fallback; empty when
    /// account_name.mode is "none" (Privilege Cloud then generates a name).</summary>
    public static string AccountNameFor(SourceRecord rec, AccountPlan p, JObj cfg)
    {
        var an = cfg.Obj("account_name") ?? new JObj();
        if (Py.Lower(Py.Truthy(an.Get("mode")) ? Py.Str(an.Get("mode")) : "") == "none") return "";
        var vals = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["name"] = rec.Name, ["address"] = rec.Address, ["username"] = rec.Username, ["platform"] = p.Platform,
            ["safe"] = p.ProposedSafe, ["folder_leaf"] = rec.Folder.Count > 0 ? rec.Folder[^1] : "",
            ["type"] = rec.Type, ["source_id"] = rec.SourceId,
        };
        string Fill(object t) =>
            Py.Strip(PyRe.Sub(@"\{(\w+)\}", m => vals.TryGetValue(m.Groups[1].Value, out var v) && v != null ? v : "",
                              Py.Truthy(t) ? Py.Str(t) : ""), "-_. ");
        var r = Fill(Py.Truthy(an.Get("template")) ? an.Get("template") : "{name}");
        return r.Length > 0 ? r : Fill(Py.Truthy(an.Get("fallback")) ? an.Get("fallback") : "{address}-{username}");
    }

    public static readonly string[] SafeOverrideKeys = { "description", "location", "managingCPM", "numberOfVersionsRetention",
        "numberOfDaysRetention", "olacEnabled", "autoPurgeEnabled" };

    public static JObj SafeSettings(string name, SafeInfo info, JObj cfg, bool withOverride = true) =>
        SafeSettings(name, withOverride ? info?.Override : null, info?.Folders, cfg);

    /// <summary>Body fields for one Safe: safe_defaults, then the first matching safe_rules entry, then
    /// your own changes to this Safe (override), which always win.</summary>
    public static JObj SafeSettings(string name, JObj ov, IEnumerable<string> folderSet, JObj cfg)
    {
        var body = cfg.Obj("safe_defaults").Copy();
        foreach (var ro in cfg.List("safe_rules") ?? new List<object>())
        {
            if (ro is not JObj rule) continue;
            var pat = Py.Truthy(rule.Get("safe_pattern")) ? Py.Str(rule.Get("safe_pattern")) : "";
            if (pat.Length > 0 && PyRe.Search(pat, name, ignoreCase: true) != null)
            {
                foreach (var k in new[] { "managingCPM", "description", "numberOfVersionsRetention", "numberOfDaysRetention" })
                    if (Py.Strip(Py.Str(rule.Get(k, ""))) != "") body[k] = rule[k];
                if (Py.Strip(Py.Str(rule.Get("numberOfVersionsRetention", ""))).Length > 0) body["numberOfDaysRetention"] = "";
                else if (Py.Strip(Py.Str(rule.Get("numberOfDaysRetention", ""))).Length > 0) body["numberOfVersionsRetention"] = "";
                break;
            }
        }
        foreach (var k in SafeOverrideKeys)
        {
            var v = ov?.Get(k);
            if (v == null || Py.Strip(Py.Str(v)) == "") continue;
            body[k] = v;
            if (k == "numberOfVersionsRetention") body["numberOfDaysRetention"] = "";
            else if (k == "numberOfDaysRetention") body["numberOfVersionsRetention"] = "";
        }
        var folders = Py.Sorted(folderSet ?? Array.Empty<string>());
        if (Py.Truthy(body.Get("description")) && Py.Str(body["description"]).Contains('{'))
            body["description"] = Py.Head(Py.Str(body["description"]).Replace("{folder}", folders.Count > 0 ? folders[0] : "")
                .Replace("{safe}", name), 100);
        foreach (var k in new[] { "description", "location", "managingCPM" })
            if (body.Get(k) is string s) body[k] = CleanLine(s);     // also covers config.json edited by hand
        body["safeName"] = name;
        return body;
    }

    /// <summary>Every name a per-Safe edit may use for a member: its target name, the name the rules gave
    /// it before you renamed it, and each source member name.</summary>
    static HashSet<string> MemberNames(MemberInfo m)
    {
        var names = new List<string> { m.MemberName ?? "", m.RuleName ?? "" };
        names.AddRange(m.Sources is { Count: > 0 } ? m.Sources : new List<string> { m.SourceName ?? "" });
        return names.Where(n => !string.IsNullOrEmpty(n)).Select(Py.Lower).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>Your member changes on the Safes page: remove a member from a Safe, or add one. Adding a member
    /// that is already on the Safe changes its role (and its type or searchIn when the change gives one).</summary>
    public static OrderedMap<(string, string), MemberInfo> ApplyMemberEdits(OrderedMap<(string, string), MemberInfo> members,
        List<AccountPlan> plans, List<JObj> edits)
    {
        if (edits == null || edits.Count == 0) return members;
        var uploading = new Dictionary<string, int>(StringComparer.Ordinal);
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in plans)
        {
            if (!p.Uploadable) continue;
            var l = Py.Lower(p.Safe);
            uploading[l] = uploading.GetValueOrDefault(l) + 1;
            names[l] = p.Safe;
        }
        foreach (var e0 in edits)
        {
            var e = e0.Copy();
            e["member_name"] = CleanLine(S(e0.Get("member_name")));
            e["search_in"] = CleanLine(Py.Truthy(e0.Get("search_in")) ? Py.Str(e0.Get("search_in")) : "");
            string safeL = Py.Lower(S(e["safe_name"])), nameL = Py.Lower(S(e["member_name"]));
            var found = members.Where(kv => Py.Lower(kv.Key.Item1) == safeL && MemberNames(kv.Value).Contains(nameL))
                               .Select(kv => kv.Key).ToList();
            var why = Py.Truthy(e.Get("reason")) ? $": {Py.Str(e["reason"])}" : "";
            var action = S(e.Get("action"));
            if (action == "add" && found.Count > 0)
            {
                foreach (var key in found.Skip(1)) members.Remove(key);
                var m = members[found[0]];
                if (Py.Truthy(e.Get("role"))) m.Role = Py.Str(e["role"]);
                var mt = Py.Truthy(e.Get("member_type")) ? Py.Str(e["member_type"]) : "";
                if (Py.Strip(mt).Length > 0) m.MemberType = m.Type = NormalizeMemberType(mt, m.MemberType);
                var si = S(e["search_in"]);
                if (Py.Strip(si).Length > 0) m.SearchIn = Py.Strip(si);
                m.Notes = (m.Notes ?? new List<string>()).ToList();
                m.Notes.Add("role changed by you" + why);
                continue;
            }
            foreach (var key in found) members.Remove(key);
            if (action == "add" && uploading.ContainsKey(safeL))
            {
                var mn = S(e["member_name"]);
                members[(names[safeL], "edit:" + nameL)] = new MemberInfo
                {
                    SourceName = mn, Type = NormalizeMemberType(e.Get("member_type")),
                    MemberType = NormalizeMemberType(e.Get("member_type")),
                    Role = Py.Truthy(e.Get("role")) ? Py.Str(e["role"]) : "",
                    Permission = "(added by you)", Accounts = uploading[safeL],
                    MemberName = mn, SearchIn = S(e["search_in"]), DirectorySource = "added by you", RuleName = "",
                    Sources = new List<string> { mn }, Notes = new List<string> { "added by you" + why },
                };
            }
        }
        return members;
    }

    /// <summary>Your change to one member everywhere (its memberName, memberType or searchIn). A null value
    /// keeps what the rules give; searchIn may be set to empty on purpose.</summary>
    public static MemberInfo ApplyMemberOverride(MemberInfo m, JObj ov)
    {
        if (ov == null || ov.Count == 0) return m;
        var changed = new List<string>();
        var mn = ov.Get("member_name");
        if (Py.Truthy(CleanLineObj(mn)))
        {
            m.MemberName = CleanLine(Py.Str(mn));
            changed.Add("name");
        }
        if (Py.Truthy(ov.Get("member_type")))
        {
            m.MemberType = m.Type = NormalizeMemberType(ov["member_type"], string.IsNullOrEmpty(m.MemberType) ? "Group" : m.MemberType);
            changed.Add("type");
        }
        if (ov.Get("search_in") != null)
        {
            m.SearchIn = S(CleanLineObj(ov["search_in"]));
            changed.Add("searchIn");
        }
        if (changed.Count > 0)
        {
            m.DirectorySource = "edited by you";
            if (m.Notes != null)
                m.Notes = m.Notes.Concat(new[] { "edited by you (" + string.Join(", ", changed) + ")"
                    + (Py.Truthy(ov.Get("reason")) ? $": {Py.Str(ov["reason"])}" : "") }).ToList();
        }
        return m;
    }

    public static void ApplyMemberOverrides(OrderedMap<(string, string), MemberInfo> members, Dictionary<string, JObj> overrides)
    {
        if (overrides == null || overrides.Count == 0) return;
        foreach (var m in members.Values)
            ApplyMemberOverride(m, overrides.TryGetValue(Py.Lower(m.SourceName), out var o) ? o : null);
    }

    /// <summary>A one-line text value without control or invisible characters, trimmed.</summary>
    public static string CleanLine(string v) => v == null ? null : Py.Strip(Sub(UnsafeLine, "", v.Replace(Nbsp, ' ')));

    /// <summary>clean_line for any value: non-text values come back unchanged.</summary>
    public static object CleanLineObj(object v) => v is string s ? CleanLine(s) : v;

    /// <summary>Remove control and invisible characters from every text value (not the secret).
    /// Returns the names of the fields that changed and notes them on the record.</summary>
    public static List<string> SanitizeRecord(SourceRecord rec)
    {
        var changed = new List<string>();
        string Clean(string v)
        {
            if (v == null) return null;
            var out_ = Sub(UnsafeText, "", v.Replace(Nbsp, ' '));
            return out_ != v ? Py.Strip(out_) : v;
        }
        string c;
        if ((c = Clean(rec.Name)) != rec.Name) { rec.Name = c; changed.Add("name"); }
        if ((c = Clean(rec.Type)) != rec.Type) { rec.Type = c; changed.Add("type"); }
        if ((c = Clean(rec.Address)) != rec.Address) { rec.Address = c; changed.Add("address"); }
        if ((c = Clean(rec.Username)) != rec.Username) { rec.Username = c; changed.Add("username"); }
        if ((c = Clean(rec.SourceRef)) != rec.SourceRef) { rec.SourceRef = c; changed.Add("source_ref"); }
        var folder = rec.Folder.Select(Clean).Where(x => !string.IsNullOrEmpty(x)).ToList();
        if (!folder.SequenceEqual(rec.Folder))
        {
            rec.Folder = folder;
            changed.Add("folder");
        }
        foreach (var k in rec.Extra.Keys.ToList())
        {
            c = Clean(rec.Extra[k]);
            if (c != rec.Extra[k])
            {
                rec.Extra[k] = c;
                changed.Add(k);
            }
        }
        foreach (var g in rec.Grants ?? new List<Grant>())
        {
            c = Clean(g.Member);
            if (c != g.Member)
            {
                g.Member = c;
                changed.Add("access group");
            }
        }
        if (changed.Count > 0)
            rec.Notes.Add("forbidden characters (control or invisible) removed from: " + string.Join(", ", changed));
        return changed;
    }

    public static OrderedMap<string, SafeInfo> BuildSafes(List<AccountPlan> plans, JObj cfg, Dictionary<string, JObj> safeOverrides = null)
    {
        var safes = new OrderedMap<string, SafeInfo>(StringComparer.Ordinal);
        var limitObj = Py.Or(cfg?.Get("safe_max_accounts"), 0L);
        safeOverrides ??= new Dictionary<string, JObj>();
        JObj OvFor(string k) => safeOverrides.TryGetValue(k, out var v) ? v : null;
        foreach (var p in plans)
        {
            var s = safes.GetOrAdd(p.Safe, () => new SafeInfo());
            s.Folders.Add(p.Rec.FolderPath);
            var ruleName = string.IsNullOrEmpty(p.RuleSafe) ? p.Safe : p.RuleSafe;
            s.RuleNames.Add(ruleName);
            if (s.Override == null && Py.Truthy(OvFor(Py.Lower(ruleName)))) s.Override = OvFor(Py.Lower(ruleName));
            s.Proposed.Add(p.ProposedSafe);
            s.Valid &= p.ValidSafe;
            s.Issues.UnionWith(p.SafeIssues);
            s.Issues.UnionWith(p.SafeNotes.Where(n => n != NoAccessNote));
            s.NoAccess += p.SafeNotes.Contains(NoAccessNote) ? 1 : 0;
            s.Sources.Add(p.SafeSource);
            s.Accounts++;
            s.Migrating += p.Uploadable ? 1 : 0;
        }
        foreach (var (name, s) in safes)
        {
            // A Safe that other Safes were renamed into keeps its own settings.
            if (s.RuleNames.Any(n => Py.Lower(n) == Py.Lower(name))) s.Override = OvFor(Py.Lower(name));
        }
        bool standard = StandardMemberRows(cfg ?? new JObj()).Count > 0;     // those Safes get the standard members
        foreach (var s in safes.Values)
        {
            int n = s.NoAccess;
            s.NoAccess = 0;
            if (n > 0 && n < s.Accounts) s.Issues.Add($"{n} of its accounts have no access groups in the source");
            else if (n > 0 && !standard)
                s.Issues.Add("no access groups in the source for any of its accounts; " +
                             "Standard member groups (4. Members · Roles) can give it members");
        }
        if (Py.Truthy(limitObj))
        {
            double limit = limitObj switch { long l => l, int i => i, double d => d, _ => IntOf(limitObj) };
            foreach (var s in safes.Values)
                if (s.Accounts > limit) s.Issues.Add($"{s.Accounts} accounts; over the {Py.Str(limitObj)} recommended per Safe");
        }
        return safes;
    }

    public const string NoFullMemberNote = "no member with full permissions: no user, group or role from your source can manage " +
        "this Safe or its members (only the user who uploads it and the Privilege Cloud " +
        "administrators can). Give one member the Full role, or a custom role with every Full permission";

    /// <summary>Role names that grant every permission of the Full preset (case-insensitive).</summary>
    public static HashSet<string> FullRoles(JObj cfg)
    {
        var full = Config.PermissionPresets["Full"];
        return Config.AllRoles(cfg).Where(kv => full.All(kv.Value.Contains)).Select(kv => Py.Lower(kv.Key)).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>A Safe that will be uploaded needs at least one member who can fully manage it.</summary>
    public static void FlagSafesWithoutFullMember(OrderedMap<string, SafeInfo> safes, OrderedMap<(string, string), MemberInfo> members, JObj cfg)
    {
        var full = FullRoles(cfg);
        var managed = members.Where(kv => full.Contains(Py.Lower(kv.Value.Role ?? ""))).Select(kv => Py.Lower(kv.Key.Item1))
                             .ToHashSet(StringComparer.Ordinal);
        foreach (var (name, s) in safes)
            if (s.Migrating > 0 && !managed.Contains(Py.Lower(name))) s.Issues.Add(NoFullMemberNote);
    }

    /// <summary>Strongest role per (Safe, member) over the accounts that migrate. The rules give each source
    /// member its target name, your member changes rename it everywhere, rows that now share a target name on
    /// one Safe merge, and last your per-Safe edits apply.</summary>
    /// <summary>A user's memberName, searchIn and source: the users list turns a full name into the UPN, which
    /// is the name Privilege Cloud needs, so the member rules only give its searchIn. Also a note when the name
    /// can't be turned.</summary>
    public static (string Name, string SearchIn, string Source, string Note) UserTarget(string name, JObj cfg, References refs)
    {
        var (upn, note) = refs != null ? refs.UpnFor(name) : (null, "");
        if (!string.IsNullOrEmpty(upn))
        {
            var (_, si, _) = MemberTarget(upn, cfg, "User");
            return (upn, si, "users list", "");
        }
        if (note.Length > 0 && (name.Contains('\\') || name.Contains('@'))) note = "";  // a domain or UPN name
        var (n, searchIn, src) = MemberTarget(name, cfg, "User");
        return (n, searchIn, src, note);
    }

    /// <summary>MemberTarget, with the users list for users (full name -> UPN).</summary>
    public static (string Name, string SearchIn, string Source) TargetFor(string name, JObj cfg, string memberType, References refs = null)
    {
        if (NormalizeMemberType(memberType, "") == "User")
        {
            var (n, si, src, _) = UserTarget(name, cfg, refs);
            return (n, si, src);
        }
        return MemberTarget(name, cfg, memberType);
    }

    public static OrderedMap<(string, string), MemberInfo> BuildMembers(List<AccountPlan> plans, JObj cfg,
        List<JObj> edits = null, Dictionary<string, JObj> overrides = null, References refs = null,
        List<UndecidedUser> undecided = null)
    {
        var members = new OrderedMap<(string, string), MemberInfo>();
        var held = new OrderedMap<(string, string, string), UndecidedUser>();
        var why = new Dictionary<MemberInfo, List<string>>(ReferenceEqualityComparer.Instance);
        var ownerRole = Transform.CleanLine(S(cfg.Obj("personal_safes")?.Get("owner_role"))) ?? "";
        foreach (var p in plans)
        {
            if (!p.Uploadable) continue;
            var owner = p.Personal;
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (owner.Length > 0)
            {
                names.Add(Py.Lower(owner));
                var upn = PersonUpn(owner, refs).Item1;
                if (upn.Length > 0) names.Add(Py.Lower(upn));
            }
            var ownerSeen = new List<MemberInfo>();
            foreach (var g in p.Grants)
            {
                var reason = "";
                bool isOwner = owner.Length > 0 && names.Contains(Py.Lower(g.Member));
                if (isOwner)
                    reason = $"owner of this personal Safe; the folder report gives it {(string.IsNullOrEmpty(g.Permission) ? "(blank)" : g.Permission)}";
                else if (g.Basis == "undecided")
                {
                    var decision = refs != null ? refs.Decision(p.Rec.Folder, g.Member) : "";
                    var h = held.GetOrAdd((Py.Lower(p.Rec.FolderPath), p.Safe, Py.Lower(g.Member)), () => new UndecidedUser
                    {
                        Folder = p.Rec.FolderPath, Safe = p.Safe, Member = g.Member, Permission = g.Permission,
                        Groups = g.Hint, Decision = decision,
                    });
                    h.Accounts++;
                    if (decision != "include") continue;
                    reason = "included by you" + (g.Hint.Length > 0 ? $"; it may also get this access through {g.Hint}" : "");
                }
                else if (g.Basis == "direct") reason = "direct access: no group on the folder gives this much access";
                var role = RoleFor(g.Permission, cfg);
                var m = members.GetOrAdd((p.Safe, Py.Lower(g.Member)), () => new MemberInfo
                    { SourceName = g.Member, Type = g.MemberType, Role = role, Permission = g.Permission });
                if (m.Ids.Add(p)) m.Accounts++;
                m.Seen.Add(string.IsNullOrEmpty(g.Permission) ? "(blank)" : g.Permission);
                if (reason.Length > 0)
                {
                    var lst = why.TryGetValue(m, out var l) ? l : why[m] = new List<string>();
                    if (!lst.Contains(reason)) lst.Add(reason);
                }
                if (RoleRank(role, cfg) > RoleRank(m.Role, cfg)) (m.Role, m.Permission) = (role, g.Permission);
                if (isOwner && !ownerSeen.Contains(m)) ownerSeen.Add(m);
            }
            if (owner.Length > 0 && ownerRole.Length > 0)
                AddOwner(members, why, p, PersonUpn(owner, refs).Item3, ownerSeen, ownerRole, cfg);
        }
        var defaultType = NormalizeMemberType(cfg.Get("default_member_type"));
        foreach (var m in members.Values)
        {
            m.MemberType = NormalizeMemberType(m.Type, defaultType);
            m.Notes = why.TryGetValue(m, out var w) ? w.ToList() : new List<string>();
            if (m.MemberType == "User")
            {
                var (n, si, src, note) = UserTarget(m.SourceName, cfg, refs);
                (m.MemberName, m.SearchIn, m.DirectorySource) = (n, si, src);
                if (note.Length > 0) m.Notes.Add(note);
            }
            else (m.MemberName, m.SearchIn, m.DirectorySource) = MemberTarget(m.SourceName, cfg, m.MemberType);
            m.RuleName = m.MemberName;
            m.Sources = new List<string> { m.SourceName };
        }
        AddStandardMembers(members, plans, cfg);
        foreach (var m in members.Values)
        {
            if (!m.Standard) continue;
            var (n, searchIn, src) = MemberTarget(m.SourceName, cfg, m.MemberType);
            m.MemberName = n;
            m.SearchIn = !string.IsNullOrEmpty(m.FixedSearchIn) ? m.FixedSearchIn : searchIn;
            m.DirectorySource = string.IsNullOrEmpty(src) ? StandardSource : src;
            m.RuleName = m.MemberName;
        }
        ApplyMemberOverrides(members, overrides);
        members = MergeMembers(members, cfg);
        var roles = Config.AllRoles(cfg);
        foreach (var m in members.Values)
        {
            var notes = new List<string>();
            if (m.Seen.Count > 1)
                notes.Add("mixed source permissions " + string.Join("/", Py.Sorted(m.Seen)) +
                          "; strongest used, Safe-level access widens it");
            if (string.IsNullOrEmpty(m.Role) && m.Standard) notes.Add("no role chosen for this standard member group");
            else if (string.IsNullOrEmpty(m.Role)) notes.Add($"no role for permission '{m.Permission}'; add it to permission_map");
            else if (!roles.ContainsKey(m.Role)) notes.Add($"role '{m.Role}' is not a preset or custom role");
            if (m.Standard) notes.AddRange(StandardMemberNotes(m.MemberName, m.MemberType));
            m.Notes = notes.Concat(m.Notes).ToList();
        }
        ApplyMemberEdits(members, plans, edits);
        if (undecided != null)
            foreach (var h in held.Values)
            {
                var (n, _, _, note) = UserTarget(h.Member, cfg, refs);
                (h.MemberName, h.Note) = (n, note);
                undecided.Add(h);
            }
        return members;
    }

    public const string StandardSource = "standard member groups";
    public static readonly Dictionary<string, string> StandardNote = new()
    {
        ["Group"] = "standard member group: create the group in your directory before the upload",
        ["Role"] = "standard member group: create the role in CyberArk Identity before the upload",
    };
    // Characters Active Directory does not allow in a group's pre-Windows 2000 name.
    public const string AdGroupInvalid = @"[""/\[\]:;|=,+*?<>]";
    public const int AdGroupMax = 64;

    public static List<JObj> StandardMemberRows(JObj cfg)
    {
        var std = cfg.Obj("standard_members") ?? new JObj();
        if ((Py.Truthy(std.Get("apply_to")) ? Py.Str(std.Get("apply_to")) : "no_source_members") == "off") return new List<JObj>();
        return (std.List("members") ?? new List<object>()).OfType<JObj>().Where(r => Py.Truthy(CleanLineObj(r.Get("name")))).ToList();
    }

    public static string ExpandMemberTemplate(object template, string safe) => CleanLine(Py.Str(template).Replace("{safe}", safe));

    public static List<string> StandardMemberNotes(string name, string memberType)
    {
        var notes = StandardNote.TryGetValue(memberType ?? "", out var n) ? new List<string> { n } : new List<string>();
        var shortName = name.Substring(name.LastIndexOf('\\') + 1);
        int at = shortName.IndexOf('@');
        if (at >= 0) shortName = shortName.Substring(0, at);
        if (memberType == "Group")
        {
            var bad = Py.Sorted(PyRe.FindAll(AdGroupInvalid, shortName).Distinct());
            if (bad.Count > 0) notes.Add("CHECK: Active Directory does not allow " + string.Join(" ", bad) + " in group names");
            if (Py.Len(shortName) > AdGroupMax)
                notes.Add($"CHECK: {Py.Len(shortName)} characters; Active Directory group names are at most {AdGroupMax}");
        }
        return notes;
    }

    /// <summary>The standard member groups (standard_members) for each Safe that gets accounts.</summary>
    static void AddStandardMembers(OrderedMap<(string, string), MemberInfo> members, List<AccountPlan> plans, JObj cfg)
    {
        var rows = StandardMemberRows(cfg);
        if (rows.Count == 0) return;
        bool every = Py.Eq((cfg.Obj("standard_members") ?? new JObj()).Get("apply_to"), "all");
        var fromSource = members.Keys.Select(k => Py.Lower(k.Item1)).ToHashSet(StringComparer.Ordinal);
        var bySafe = new OrderedMap<string, HashSet<AccountPlan>>(StringComparer.Ordinal);
        foreach (var p in plans)
            if (p.Uploadable) bySafe.GetOrAdd(p.Safe, () => new HashSet<AccountPlan>(ReferenceEqualityComparer.Instance)).Add(p);
        foreach (var (safe, ids) in bySafe)
        {
            if (!every && fromSource.Contains(Py.Lower(safe))) continue;
            foreach (var r in rows)
            {
                var name = ExpandMemberTemplate(r["name"], safe);
                var key = (safe, "std:" + Py.Lower(name));
                if (members.ContainsKey(key)) continue;
                var mtype = NormalizeMemberType(r.Get("member_type"), "Group");
                var role = Config.ResolveRole(r.Get("role"), cfg);
                if (role.Length == 0) role = S(CleanLineObj(r.Get("role")));
                members[key] = new MemberInfo
                {
                    SourceName = name, Type = mtype, MemberType = mtype, Role = role, Permission = "",
                    Accounts = ids.Count, Ids = new HashSet<AccountPlan>(ids, ReferenceEqualityComparer.Instance),
                    Standard = true, Template = Py.Str(r["name"]), Sources = new List<string> { name },
                    Notes = new List<string>(), FixedSearchIn = S(CleanLineObj(r.Get("search_in"))),
                };
            }
        }
    }

    /// <summary>One row per (Safe, target member name). Two source members can end up with the same name;
    /// the merged row keeps the strongest role and lists every source member (joined with ' | ').</summary>
    static OrderedMap<(string, string), MemberInfo> MergeMembers(OrderedMap<(string, string), MemberInfo> members, JObj cfg)
    {
        var out_ = new OrderedMap<(string, string), MemberInfo>();
        foreach (var kv in members)
        {
            var m = kv.Value;
            var key = (kv.Key.Item1, Py.Lower(string.IsNullOrEmpty(m.MemberName) ? m.SourceName : m.MemberName));
            if (!out_.TryGetValue(key, out var cur))
            {
                out_[key] = m;
                continue;
            }
            // Only a member none of the source's members already is needs creating.
            cur.Standard = cur.Standard && m.Standard;
            cur.Sources.AddRange(m.Sources);
            cur.SourceName = string.Join(" | ", cur.Sources);
            var newIds = m.Ids.Where(i => !cur.Ids.Contains(i)).ToList();
            cur.Ids.UnionWith(newIds);
            cur.Accounts += newIds.Count;
            cur.Seen.UnionWith(m.Seen);
            if (RoleRank(m.Role, cfg) > RoleRank(cur.Role, cfg)) (cur.Role, cur.Permission) = (m.Role, m.Permission);
            var note = "merged source members " + string.Join(", ", cur.Sources) + " (same target name on this Safe)";
            if ((m.SearchIn ?? "") != (cur.SearchIn ?? ""))
                note += $"; CHECK: they point at different directories ('{(string.IsNullOrEmpty(cur.SearchIn) ? "any" : cur.SearchIn)}' and " +
                        $"'{(string.IsNullOrEmpty(m.SearchIn) ? "any" : m.SearchIn)}'), so they may be different groups. The first is used";
            if (m.MemberType != cur.MemberType)
                note += $"; member types differ ({cur.MemberType}/{m.MemberType}), {cur.MemberType} used";
            cur.Notes = cur.Notes.Where(n => !n.StartsWith("merged source members", StringComparison.Ordinal)).ToList();
            cur.Notes.Add(note);
            foreach (var n in m.Notes) if (!cur.Notes.Contains(n)) cur.Notes.Add(n);
        }
        return out_;
    }
}
