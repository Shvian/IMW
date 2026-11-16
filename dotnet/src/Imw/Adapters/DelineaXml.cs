using System.Xml.Linq;
using Imw.Core;

namespace Imw.Adapters;

/// <summary>
/// Delinea (Thycotic) Secret Server XML export / import file (&lt;ImportFile&gt; with Folders,
/// SecretTemplates, Secrets and Groups). Which fields are secrets comes from the template's field
/// flags (ispassword), plus the usual secret-name patterns as a safety net. File fields (isfile)
/// are attachments and are not migrated.
///
/// Permissions follow Secret Server's inheritance: a secret with an empty &lt;Permissions&gt; takes the
/// permissions of its folder, and a folder with an empty &lt;Permissions&gt; takes those of its parent
/// folder. Element names are matched without regard to case or XML namespace.
/// </summary>
public static class DelineaXml
{
    const string RootTag = "importfile";
    static readonly string[] SecretRoleTags = { "secretaccessrolename", "accessrolename", "rolename", "role", "permission",
                                                "permissionname", "folderaccessrolename" };
    static readonly (string, string)[] FlagRoles = { ("owner", "Owner"), ("edit", "Edit"), ("view", "View"), ("list", "List") };
    static readonly string[] True = { "true", "1", "yes" };

    static string Tag(XElement el) => Py.Lower(el.Name.LocalName);

    static XElement Child(XElement el, params string[] names)
    {
        if (el == null) return null;
        foreach (var c in el.Elements())
            if (names.Contains(Tag(c))) return c;
        return null;
    }

    static List<XElement> Children(XElement el, string name) =>
        el == null ? new List<XElement>() : el.Elements().Where(c => Tag(c) == name).ToList();

    static string Text(XElement el, params string[] names)
    {
        var c = Child(el, names);
        var t = c == null ? null : SafeXml.Text(c);
        return string.IsNullOrEmpty(t) ? "" : Py.Strip(t);
    }

    static bool Flag(XElement el, string name) => True.Contains(Py.Lower(Text(el, name)));

    static (string, string) Member(XElement perm, HashSet<string> knownGroups)
    {
        var domain = Text(perm, "domainname", "domain");
        string name = null, mtype = null;
        foreach (var (tag, mt) in new[] { ("groupname", "Group"), ("username", "User"), ("name", ""), ("principalname", ""), ("usergroupname", "") })
        {
            name = Text(perm, tag);
            mtype = mt;
            if (name.Length > 0) break;
        }
        if (string.IsNullOrEmpty(name)) return ("", "");
        var full = domain.Length == 0 || name.Contains('\\') ? name : $"{domain}\\{name}";
        if (mtype.Length == 0 && (knownGroups.Contains(Py.Lower(full)) || knownGroups.Contains(Py.Lower(name)))) mtype = "Group";
        return (full, mtype);
    }

    /// <summary>Grants from a &lt;Permissions&gt; element (empty when it lists none).</summary>
    public static List<Grant> ParsePermissions(XElement block, HashSet<string> knownGroups)
    {
        var grants = new List<Grant>();
        foreach (var perm in Children(block, "permission"))
        {
            var (member, mtype) = Member(perm, knownGroups);
            if (member.Length == 0) continue;
            var role = SecretRoleTags.Select(t => Text(perm, t)).FirstOrDefault(v => v.Length > 0) ?? "";
            if (role.Length == 0) role = FlagRoles.Where(fr => Flag(perm, fr.Item1)).Select(fr => fr.Item2).FirstOrDefault() ?? "";
            var key = (Py.Lower(member), Py.Lower(role));
            if (grants.All(g => (Py.Lower(g.Member), Py.Lower(g.Permission)) != key))
                grants.Add(new Grant(member, role, mtype));
        }
        return grants;
    }

    static Dictionary<string, Dictionary<string, Dictionary<string, bool>>> Templates(XElement root)
    {
        var out_ = new Dictionary<string, Dictionary<string, Dictionary<string, bool>>>();
        var block = Child(root, "secrettemplates");
        foreach (var st in block?.Elements() ?? Enumerable.Empty<XElement>())
        {
            var name = Text(st, "name", "secrettemplatename");
            var fields = new Dictionary<string, Dictionary<string, bool>>();
            foreach (var f in Children(Child(st, "fields"), "field"))
            {
                var info = new[] { "ispassword", "isnotes", "isurl", "isfile" }.ToDictionary(k => k, k => Flag(f, k));
                foreach (var key in new[] { Text(f, "name"), Text(f, "displayname"), Text(f, "fieldslugname") })
                    if (key.Length > 0) fields[Py.Lower(key)] = info;
            }
            if (name.Length > 0) out_[Py.Lower(name)] = fields;
        }
        return out_;
    }

    static Dictionary<string, List<Grant>> Folders(XElement root, HashSet<string> knownGroups)
    {
        var out_ = new Dictionary<string, List<Grant>>();
        void Walk(XElement block, List<string> parent)
        {
            foreach (var f in Children(block, "folder"))
            {
                var path = SourceRecord.SplitFolder(Text(f, "folderpath"), "\\");
                var name = Text(f, "foldername");
                if (path.Count == 0 && name.Length > 0) path = parent.Append(name).ToList();
                var grants = ParsePermissions(Child(f, "permissions"), knownGroups);
                if (path.Count > 0 && grants.Count > 0) out_[Py.Lower(string.Join("\\", path))] = grants;
                Walk(Child(f, "folders"), path.Count > 0 ? path : parent);
            }
        }
        Walk(Child(root, "folders"), new List<string>());
        return out_;
    }

    static HashSet<string> Groups(XElement root)
    {
        var names = new HashSet<string>();
        foreach (var g in Children(Child(root, "groups"), "group"))
        {
            var name = Text(g, "name", "groupname");
            var domain = Text(g, "domainname", "domain");
            if (name.Length > 0)
            {
                names.Add(Py.Lower(name));
                if (domain.Length > 0) names.Add(Py.Lower($"{domain}\\{name}"));
            }
        }
        return names;
    }

    /// <summary>Nearest folder (itself, then each parent) that lists permissions.</summary>
    public static List<Grant> FolderGrants(List<string> folder, Dictionary<string, List<Grant>> folders)
    {
        var levels = folder.Select(Py.Lower).ToList();
        for (int i = levels.Count; i > 0; i--)
            if (folders.TryGetValue(string.Join("\\", levels.Take(i)), out var hit)) return hit.ToList();
        return null;
    }

    public static int Sniff(string head) => Py.Lower(head).Contains("<importfile") ? 95 : 0;

    public static List<SourceRecord> Read(string adapterName, string path, JObj cfg)
    {
        var stem = Adapter.FileStem(path);
        XElement root;
        try { root = SafeXml.Parse(path); }
        catch (ValueError exc) when (exc is UnsafeXmlError or XmlParseError) { throw new AdapterError($"{path}: {exc.Message}"); }
        if (Tag(root) != RootTag) throw new AdapterError($"{path} is not a Delinea Secret Server XML export (no <ImportFile>)");
        var knownGroups = Groups(root);
        var templates = Templates(root);
        var folders = Folders(root, knownGroups);
        var keyAliases = (cfg.Obj("field_aliases").List("private_key") ?? new List<object>()).Select(a => Py.Lower(Py.Str(a))).ToList();
        var out_ = new List<SourceRecord>();
        int n = 0;
        foreach (var sec in Children(Child(root, "secrets"), "secret"))
        {
            n++;
            out_.Add(Record(adapterName, sec, n, stem, cfg, templates, folders, knownGroups, keyAliases));
        }
        return out_;
    }

    static SourceRecord Record(string adapterName, XElement sec, int n, string stem, JObj cfg,
        Dictionary<string, Dictionary<string, Dictionary<string, bool>>> templates, Dictionary<string, List<Grant>> folders,
        HashSet<string> knownGroups, List<string> keyAliases)
    {
        var tname = Text(sec, "secrettemplatename", "templatename");
        var tfields = templates.GetValueOrDefault(Py.Lower(tname)) ?? new();
        var folderPath = Text(sec, "folderpath");

        var items = new StrDict();
        foreach (var it in Children(Child(sec, "secretitems"), "secretitem"))
        {
            var fname = Text(it, "fieldname", "name", "slug");
            if (fname.Length == 0) continue;
            var v = Child(it, "value");
            var vt = v == null ? null : SafeXml.Text(v);
            var val = string.IsNullOrEmpty(vt) ? "" : vt;
            while (items.ContainsKey(fname)) fname += "_2";
            items[fname] = val;
        }

        bool Flags(string fname, string flag) => tfields.TryGetValue(Py.Lower(fname), out var f) && f.GetValueOrDefault(flag);

        var secretFields = items.Keys.Where(f => Flags(f, "ispassword") || Adapter.IsSecretColumn(f, cfg)).ToList();
        var fileFields = items.Keys.Where(f => Flags(f, "isfile")).ToList();
        var urlFields = items.Keys.Where(f => Flags(f, "isurl")).ToList();
        var keyField = secretFields.FirstOrDefault(f => keyAliases.Contains(Py.Lower(f)) && Py.Strip(items[f]).Length > 0) ?? "";
        var pwField = secretFields.FirstOrDefault(f => f != keyField && !Py.Lower(f).Contains("passphrase") && Py.Strip(items[f]).Length > 0);
        if (string.IsNullOrEmpty(pwField))
            pwField = secretFields.FirstOrDefault(f => f != keyField && !Py.Lower(f).Contains("passphrase")) ?? "";

        var row = new StrDict();
        row["Secret Name"] = Text(sec, "secretname", "name");
        row["Folder Path"] = folderPath;
        row["Secret Template"] = tname;
        var sid = Text(sec, "secretid", "id");
        if (sid.Length > 0) row["Secret ID"] = sid;
        foreach (var kv in items)
        {
            var f = kv.Key;
            if (new[] { "secret name", "folder path", "secret template", "secret id" }.Contains(Py.Lower(f))) f = $"{f} (field)";
            row[f] = kv.Value;
        }
        var columns = new Dictionary<string, string>
        {
            ["id"] = sid.Length > 0 ? "Secret ID" : "", ["name"] = "Secret Name", ["folder"] = "Folder Path",
            ["type"] = "Secret Template", ["password"] = pwField, ["private_key"] = keyField,
        };
        // Template-flagged secrets are secrets whatever their name.
        var one = cfg.Copy();
        var patterns = (cfg.List("secret_column_patterns") ?? new List<object>()).ToList();
        patterns.AddRange(secretFields.Select(f => (object)$"^{PyRe.Escape(f)}$"));
        one["secret_column_patterns"] = patterns;
        var rec = Rows.RecordFromRow(row, one, adapterName, stem, $"secret {n} {Py.ReprStr(row["Secret Name"])}", n,
            typeHint: tname, columns: columns, folderSeparator: "\\");
        if (sid.Length == 0) rec.SourceId = $"secret{n}";
        rec.Folder = SourceRecord.SplitFolder(folderPath, "\\");

        foreach (var f in fileFields)
            if (rec.Extra.Pop(f) != null && Py.Strip(items[f]).Length > 0) rec.Notes.Add($"attachment field '{f}' not migrated");
        if (string.IsNullOrEmpty(rec.Address))
            foreach (var f in urlFields)
                if (Py.Strip(items[f]).Length > 0) { rec.Address = Py.Strip(items[f]); break; }

        var deps = Child(sec, "secretdependencies");
        int nd = deps?.Elements().Count() ?? 0;
        if (nd > 0) rec.Notes.Add($"{nd} secret dependenc{(nd == 1 ? "y" : "ies")} not migrated");

        var own = ParsePermissions(Child(sec, "permissions"), knownGroups);
        if (own.Count > 0) { rec.Grants = own; rec.AccessSource = "record"; }
        else
        {
            var inherited = FolderGrants(rec.Folder, folders);
            if (inherited != null) { rec.Grants = inherited; rec.AccessSource = "folder"; }
        }
        return rec;
    }
}
