using System.Text;

namespace Imw.Core;

/// <summary>
/// Reference files: exports and reports that hold no accounts but help map them (see imw/reference.py).
/// templates: "allsecrets.csv" (Name, Secret template, Folder): each secret's template, matched on its name.
/// users: "lauserslist.csv" (Username, Display name, ...): full name -> Username (the UPN).
/// template_list, groups, roles: recognised so they are not read as accounts; not needed.
/// </summary>
public static class Reference
{
    public static readonly string[] TemplateNameColumns = { "Name", "Secret Name", "SecretName" };
    public static readonly string[] TemplateColumns = { "Secret template", "Secret Template Name", "Template", "Template Name" };
    public static readonly string[] TemplateFolderColumns = { "Folder", "Folder Path", "FolderPath" };
    public static readonly string[] UserDisplayColumns = { "Display name", "DisplayName", "Full name", "Full Name" };
    public static readonly string[] UserNameColumns = { "Username", "User name", "UserName", "UPN", "User Principal Name" };
    public static readonly string[] UserEmailColumns = { "Email address", "Email", "E-mail", "Mail" };

    public static readonly OrderedMap<string, string> Kinds = MakeKinds();

    static OrderedMap<string, string> MakeKinds()
    {
        var k = new OrderedMap<string, string>(StringComparer.Ordinal);
        k["templates"] = "Template for each secret";
        k["users"] = "Users list (full name to UPN)";
        k["template_list"] = "List of secret templates (not needed)";
        k["groups"] = "List of groups (not needed)";
        k["roles"] = "Secret Server role report (not needed)";
        return k;
    }

    public static readonly Dictionary<string, string> KindHelp = new(StringComparer.Ordinal)
    {
        ["templates"] = "Gives each secret its template, which picks its platform. Needed when the secrets " +
                        "export has no template column.",
        ["users"] = "Turns the full names in the folder reports into UPNs, so users are uploaded with " +
                    "the name Privilege Cloud needs.",
        ["template_list"] = "Lists every template with its count. The Workbench takes templates from the " +
                            "secrets themselves, so this file is not needed.",
        ["groups"] = "Lists the groups. Groups come from the folder-permission report, so this file is " +
                     "not needed.",
        ["roles"] = "Who may administer Secret Server itself (its own roles), not who may use secrets. " +
                    "Not used.",
    };

    public static readonly string[] UsedKinds = { "templates", "users" };

    /// <summary>The first non-empty row of a CSV, stripped; empty for anything else.</summary>
    public static List<string> ReadHeader(string path, string encoding = "utf-8-sig")
    {
        if (Py.Lower(Path.GetExtension(path)) != ".csv") return new List<string>();
        try
        {
            string text;
            var name = (encoding ?? "utf-8-sig").Trim().ToLowerInvariant().Replace('_', '-');
            if (name is "utf-8-sig" or "utf8-sig" or "utf-8" or "utf8")
            {
                text = new UTF8Encoding(false, false).GetString(File.ReadAllBytes(path));
                if (text.StartsWith('﻿') && name.EndsWith("sig")) text = text.Substring(1);
            }
            else text = Csv.ReadText(path, encoding);
            foreach (var row in new Csv.Reader(text).Rows())
                if (row.Any(c => Py.Strip(c).Length > 0)) return row.Select(c => Py.Strip(c)).ToList();
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or CsvError or ValueError) { }
        return new List<string>();
    }

    static bool Has(HashSet<string> h, string[] names) => names.Any(n => h.Contains(Py.Lower(n)));

    /// <summary>'templates', 'users', 'template_list', 'groups', 'roles' or '' (not a reference file).</summary>
    public static string Kind(string path, string encoding = "utf-8-sig")
    {
        var h = ReadHeader(path, encoding).Select(Py.Lower).ToHashSet(StringComparer.Ordinal);
        if (h.Count == 0) return "";
        bool password = h.Any(c => c.Contains("password"));
        bool secrets = password || Has(h, new[] { "Username", "User Name", "Secret Name" });
        if (h.Contains("permission from")) return "roles";
        if (h.Contains("secret templates") && (h.Contains("total secrets") || h.Contains("enabled"))) return "template_list";
        if (Has(h, UserDisplayColumns) && Has(h, UserNameColumns) && !password) return "users";
        if (Has(h, TemplateColumns) && Has(h, TemplateNameColumns) && !secrets) return "templates";
        if (h.Count == 2 && h.Contains("name") && h.Contains("description")) return "groups";
        return "";
    }

    static (Dictionary<string, string> Cols, List<Csv.OrderedRow> Rows) ReadRows(string path, string encoding) =>
        CsvSafe.Reading(path, () =>
        {
            var reader = new Csv.DictReader(Csv.ReadText(path, encoding));
            var cols = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var c in reader.FieldNames) if (!string.IsNullOrEmpty(c)) cols[Py.Lower(Py.Strip(c))] = c;
            return (cols, reader.Rows().ToList());
        });

    static string Pick(Dictionary<string, string> cols, string[] names)
    {
        foreach (var n in names) if (cols.TryGetValue(Py.Lower(n), out var c)) return c;
        return null;
    }

    static string Val(Csv.OrderedRow row, string col) => col == null ? "" : Py.Strip(row[col] ?? "");

    /// <summary>(name, folder, template) from an "all secrets with their template" report.</summary>
    public static List<(string, string, string)> ReadTemplates(string path, string encoding = "utf-8-sig")
    {
        var (cols, rows) = ReadRows(path, encoding);
        string nameC = Pick(cols, TemplateNameColumns), tmplC = Pick(cols, TemplateColumns), folderC = Pick(cols, TemplateFolderColumns);
        if (nameC == null || tmplC == null) throw new ValueError($"{path}: needs a Name and a Secret template column");
        var outList = new List<(string, string, string)>();
        foreach (var r in rows)
        {
            string name = Val(r, nameC), tmpl = Val(r, tmplC);
            if (name.Length > 0 && tmpl.Length > 0) outList.Add((name, Val(r, folderC), tmpl));
        }
        return outList;
    }

    /// <summary>(display name, username, email) from a users list.</summary>
    public static List<(string, string, string)> ReadUsers(string path, string encoding = "utf-8-sig")
    {
        var (cols, rows) = ReadRows(path, encoding);
        string dispC = Pick(cols, UserDisplayColumns), userC = Pick(cols, UserNameColumns), mailC = Pick(cols, UserEmailColumns);
        if (dispC == null || userC == null) throw new ValueError($"{path}: needs a Display name and a Username column");
        var outList = new List<(string, string, string)>();
        foreach (var r in rows)
        {
            string disp = Val(r, dispC), user = Val(r, userC);
            if (disp.Length > 0 && user.Length > 0) outList.Add((disp, user, Val(r, mailC)));
        }
        return outList;
    }

    public static string FolderKey(IEnumerable<string> folder) => string.Join("\\", folder.Select(Py.Lower));
    public static string FolderKey(string folder) => Py.Lower(string.Join("\\", SourceRecord.SplitFolder(folder ?? "", "auto")));
}

/// <summary>Templates, users and your decisions on users who may get their access through a group,
/// applied when the rules run (so the order the files are loaded in doesn't matter).</summary>
public sealed class References
{
    public readonly OrderedMap<string, List<(string Folder, string Template)>> Templates = new(StringComparer.Ordinal);
    public readonly OrderedMap<string, List<string>> Users = new(StringComparer.Ordinal);
    public readonly HashSet<string> Usernames = new(StringComparer.Ordinal);
    public readonly Dictionary<(string, string), string> Decisions = new();

    public References(IEnumerable<(string, string, string)> templates = null, IEnumerable<(string, string, string)> users = null,
        Dictionary<(string, string), string> decisions = null)
    {
        foreach (var (name, folder, tmpl) in templates ?? Array.Empty<(string, string, string)>())
            Templates.GetOrAdd(Py.Lower(name), () => new()).Add((Reference.FolderKey(folder), tmpl));
        foreach (var (disp, user, _) in users ?? Array.Empty<(string, string, string)>())
        {
            var lst = Users.GetOrAdd(Py.Lower(disp), () => new());
            if (!lst.Any(u => Py.Lower(u) == Py.Lower(user))) lst.Add(user);
            Usernames.Add(Py.Lower(user));
        }
        if (decisions != null) foreach (var kv in decisions) Decisions[kv.Key] = kv.Value;
    }

    public bool HasUsers => Users.Count > 0;

    /// <summary>(template, note). An empty template with a note when the name is missing or the same name has
    /// several templates that the folder doesn't settle.</summary>
    public (string, string) TemplateFor(string name, IEnumerable<string> folder)
    {
        if (Templates.Count == 0) return ("", "");
        if (!Templates.TryGetValue(Py.Lower(name ?? ""), out var hits) || hits.Count == 0)
            return ("", "not in the template list (allsecrets.csv): no template, so no platform");
        var tmpls = hits.Select(h => h.Template).Distinct(StringComparer.Ordinal).ToList();
        if (tmpls.Count == 1) return (tmpls[0], "");
        var key = Reference.FolderKey(folder);
        var inFolder = hits.Where(h => h.Folder == key).Select(h => h.Template).Distinct(StringComparer.Ordinal).ToList();
        if (inFolder.Count == 1) return (inFolder[0], "");
        return ("", "CHECK: the template list has " + tmpls.Count + " secrets with this name and " +
                    "different templates (" + string.Join(", ", tmpls) + "), and the folder doesn't settle it");
    }

    /// <summary>(username, note) for a user's full name. (null, note) when it can't be found or is not unique;
    /// (null, "") when there is no users list or the name already is a username.</summary>
    public (string, string) UpnFor(string name)
    {
        if (Users.Count == 0 || string.IsNullOrEmpty(name) || Usernames.Contains(Py.Lower(name))) return (null, "");
        if (!Users.TryGetValue(Py.Lower(name), out var hits))
            return (null, "CHECK: not in the users list, so the full name is uploaded; give it the UPN");
        if (hits.Count > 1)
            return (null, "CHECK: " + hits.Count + " users in the users list have this full name (" +
                          string.Join(", ", hits) + "); pick the right one");
        return (hits[0], "");
    }

    public string Decision(IEnumerable<string> folder, string member) =>
        Decisions.TryGetValue((Reference.FolderKey(folder), Py.Lower(member ?? "")), out var d) ? d : "";
}
