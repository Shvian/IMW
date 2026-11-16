namespace Imw.Core;

/// <summary>One principal's access to a record, as the source expressed it.</summary>
public sealed class Grant
{
    public string Member;
    public string Permission;          // source wording: Owner, Edit, View, Read, Full...
    public string MemberType;          // User, Group or Role; blank -> config default_member_type
    // A user from a report of effective access ("What folders can all users see?"), which lists
    // access a user gets through a group too: "direct" when no group explains it, "undecided"
    // when a group on the same folder gives the same or stronger access (Hint: those groups).
    public string Basis;
    public string Hint;

    public Grant(string member, string permission, string memberType = "", string basis = "", string hint = "")
    {
        Member = member;
        Permission = permission;
        MemberType = memberType ?? "";
        Basis = basis ?? "";
        Hint = hint ?? "";
    }
}

/// <summary>Insertion-ordered string -> string map (Python OrderedDict of source columns).</summary>
public sealed class StrDict : IEnumerable<KeyValuePair<string, string>>
{
    readonly List<string> _keys = new();
    readonly Dictionary<string, string> _map = new(StringComparer.Ordinal);

    public string this[string key]
    {
        get => _map.TryGetValue(key, out var v) ? v : null;
        set { if (!_map.ContainsKey(key)) _keys.Add(key); _map[key] = value; }
    }

    public int Count => _keys.Count;
    public IReadOnlyList<string> Keys => _keys;
    public bool ContainsKey(string key) => _map.ContainsKey(key);
    public string Get(string key, string dflt = null) => _map.TryGetValue(key, out var v) ? v : dflt;

    public string Pop(string key)
    {
        if (!_map.TryGetValue(key, out var v)) return null;
        _map.Remove(key);
        _keys.Remove(key);
        return v;
    }

    public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
    {
        foreach (var k in _keys.ToList()) yield return new(k, _map[k]);
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

    public JObj ToJObj() => new(this.Select(kv => new KeyValuePair<string, object>(kv.Key, kv.Value)));
}

/// <summary>One credential from any source, before any target rules are applied.</summary>
public sealed class SourceRecord
{
    public const string ErrorNote = "ERROR: ";

    public string Source;              // adapter name
    public string SourceFile;          // file stem, used in Record_ID
    public string SourceId;            // id unique within the file (Secret ID, UUID, row number)
    public string SourceRef;           // human pointer, e.g. "line 12" or "Sheet1!row 7"
    public string Name = "";
    public List<string> Folder = new();
    public string Type = "";           // template / account type, drives platform mapping
    public string Address = "";
    public string Username = "";
    public string Secret = "";
    public string SecretType = "password";   // password | key
    public bool? HasSecret;            // set when loaded from the database without the secret
    // null = the source has no access data for this record (use --permissions); empty = nobody.
    public List<Grant> Grants;
    public string AccessSource = "";   // where grants came from: source, record, folder, none
    public string TargetSafe = "";
    public string TargetPlatform = "";
    public StrDict Extra = new();      // non-secret source columns
    public List<string> Notes = new();

    public SourceRecord(string source, string sourceFile, string sourceId, string sourceRef)
    {
        Source = source;
        SourceFile = sourceFile;
        SourceId = sourceId;
        SourceRef = sourceRef;
    }

    public string RecordId => $"{Source}:{SourceFile}:{SourceId}";

    public string FolderPath => Folder.Count > 0 ? "\\" + string.Join("\\", Folder) : "\\";

    /// <summary>Split a folder path into clean levels. separator "auto" picks \ if present, else /.</summary>
    public static List<string> SplitFolder(string path, string separator = "\\")
    {
        path = Py.Strip(path ?? "");
        if (separator == "auto") separator = path.Contains('\\') ? "\\" : "/";
        return path.Split(separator).Select(Py.Strip).Where(p => p.Length > 0).ToList();
    }
}
