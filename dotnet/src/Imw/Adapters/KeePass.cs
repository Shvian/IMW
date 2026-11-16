using System.Xml.Linq;
using Imw.Core;

namespace Imw.Adapters;

/// <summary>
/// KeePass exports: the KeePass 2.x XML export (keeps the group tree, custom fields and entry
/// UUIDs), and the KeePass / KeePassXC CSV export. Encrypted .kdbx files are not read directly;
/// export to XML from KeePass first.
/// </summary>
public sealed class KeePassAdapter : Adapter
{
    public override string Name => "keepass";
    public override string Description => "KeePass 2.x XML export, or KeePass/KeePassXC CSV export";
    static readonly HashSet<string> Standard = new() { "Title", "UserName", "Password", "URL", "Notes" };

    public override int Sniff(string path)
    {
        var p = path.ToLowerInvariant();
        if (p.EndsWith(".kdbx")) return 90;
        var head = p.EndsWith(".xml") ? SafeXml.ReadHeadText(path, 4096) : ReadHead(path, 4096);
        if (p.EndsWith(".xml") && head.Contains("<KeePassFile")) return 95;
        if (p.EndsWith(".csv"))
        {
            var first = head.Length > 0 ? Py.Lower(SplitLines(head).FirstOrDefault() ?? "") : "";
            if (first.Contains("\"title\"") && (first.Contains("\"group\"") || first.Contains("\"url\""))) return 70;
            if (first.Contains("\"account\",\"login name\",\"password\",\"web site\"")) return 70;
        }
        return 0;
    }

    /// <summary>str.splitlines()</summary>
    static IEnumerable<string> SplitLines(string s)
    {
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '\n' or '\r' or '\x0b' or '\x0c' or '\x1c' or '\x1d' or '\x1e' or '\x85' or '\u2028' or '\u2029')
            {
                yield return s.Substring(start, i - start);
                if (c == '\r' && i + 1 < s.Length && s[i + 1] == '\n') i++;
                start = i + 1;
            }
        }
        if (start < s.Length) yield return s.Substring(start);
    }

    public override List<SourceRecord> Read(string path, JObj cfg, string encoding = "utf-8-sig")
    {
        var p = path.ToLowerInvariant();
        if (p.EndsWith(".kdbx"))
            throw new AdapterError($"{path} is an encrypted KeePass database. In KeePass use " +
                                   "File > Export > KeePass XML (2.x) and convert that file instead.");
        return p.EndsWith(".xml") ? ReadXml(path, cfg) : ReadCsv(path, cfg, encoding);
    }

    // ------------------------------------------------------------------ XML

    List<SourceRecord> ReadXml(string path, JObj cfg)
    {
        var kcfg = cfg.Obj("sources").Obj("keepass");
        var skip = kcfg.List("skip_groups").Select(g => Py.Lower(Py.Str(g))).ToHashSet();
        var stem = FileStem(path);
        XElement root;
        try { root = SafeXml.Parse(path); }
        catch (ValueError exc) when (exc is UnsafeXmlError or XmlParseError) { throw new AdapterError($"{path}: {exc.Message}"); }
        if (SafeXml.Tag(root) != "KeePassFile") throw new AdapterError($"{path} is not a KeePass XML export");
        var recycle = Py.Strip(SafeXml.FindText(root, "Meta/RecycleBinUUID") ?? "");
        var top = SafeXml.Find(root, "Root/Group");
        var out_ = new List<SourceRecord>();
        if (top == null) return out_;

        void Walk(XElement group, List<string> trail)
        {
            var name = Py.Strip(SafeXml.FindText(group, "Name") ?? "");
            var uuid = Py.Strip(SafeXml.FindText(group, "UUID") ?? "");
            if (skip.Contains(Py.Lower(name)) || (recycle.Length > 0 && uuid == recycle)) return;
            var here = name.Length > 0 ? trail.Append(name).ToList() : trail;
            foreach (var entry in SafeXml.FindAll(group, "Entry"))
                out_.Add(Entry(entry, here, stem, cfg, out_.Count + 1));
            foreach (var sub in SafeXml.FindAll(group, "Group"))
                Walk(sub, here);
        }

        Walk(top, new List<string>());
        if (Py.Truthy(kcfg["drop_root_group"]))
            foreach (var rec in out_) rec.Folder = rec.Folder.Skip(1).ToList();
        return out_;
    }

    SourceRecord Entry(XElement entry, List<string> folder, string stem, JObj cfg, int idx)
    {
        var kcfg = cfg.Obj("sources").Obj("keepass");
        var fields = new StrDict();
        var protectedKeys = new HashSet<string>();
        foreach (var s in SafeXml.FindAll(entry, "String"))
        {
            var key = Py.Strip(SafeXml.FindText(s, "Key") ?? "");
            var fv = SafeXml.FindText(s, "Value");
            fields[key] = string.IsNullOrEmpty(fv) ? "" : fv;
            var v = SafeXml.Find(s, "Value");
            if (v != null && new[] { "ProtectInMemory", "Protected" }.Any(a => Py.Lower(SafeXml.Attr(v, a) ?? "") == "true"))
                protectedKeys.Add(key);
        }
        var uuid = Py.Strip(SafeXml.FindText(entry, "UUID") ?? "");
        var rec = new SourceRecord(Name, stem, uuid.Length > 0 ? uuid : $"entry{idx}",
                                   $"entry {Py.ReprStr(fields.Get("Title", ""))}");
        rec.Name = Py.Strip(fields.Get("Title", ""));
        rec.Folder = folder.ToList();
        rec.Username = Py.Strip(fields.Get("UserName", ""));
        rec.Address = Py.Strip(fields.Get("URL", ""));
        rec.Secret = fields.Get("Password", "");
        rec.Type = Py.Str(kcfg["type_from"]) == "group" ? string.Join("\\", folder) : Py.Str(kcfg["fixed_type"]);
        var otp = OtpFields(fields.Where(kv => !Standard.Contains(kv.Key) || kv.Key == "URL"));
        if (otp.Count > 0) rec.Notes.Add(OtpNote(otp));
        foreach (var kv in fields)
        {
            var k = kv.Key;
            var v = kv.Value;
            if (otp.Contains(k) && (protectedKeys.Contains(k) || IsSecretColumn(k, cfg) || IsOtpValue(v)))
            {
                if (k == "URL") rec.Address = "";
                continue;
            }
            if (Standard.Contains(k))
            {
                if (k is "URL" or "Notes") rec.Extra[k] = v;
                continue;
            }
            if (protectedKeys.Contains(k) || IsSecretColumn(k, cfg))
            {
                var kl = Py.Lower(k);
                if (kl.Contains("private") && kl.Contains("key") && Py.Strip(v).Length > 0) { rec.Secret = v; rec.SecretType = "key"; }
                else if (Py.Strip(v).Length > 0)
                    rec.Notes.Add($"secret field '{k}' is not migrated (an account takes one secret) and is left out of the review files");
                continue;
            }
            rec.Extra[k] = v;
        }
        foreach (var b in SafeXml.FindAll(entry, "Binary"))
            rec.Notes.Add($"attachment '{(SafeXml.FindText(b, "Key") is { Length: > 0 } bk ? bk : "")}' not migrated");
        if (Py.Strip(rec.Secret).Length == 0) rec.Notes.Add("secret is empty in the source");
        if (uuid.Length == 0) rec.Notes.Add("entry has no UUID");
        return rec;
    }

    // ------------------------------------------------------------------ CSV

    List<SourceRecord> ReadCsv(string path, JObj cfg, string encoding)
    {
        var kcfg = cfg.Obj("sources").Obj("keepass");
        var skip = kcfg.List("skip_groups").Select(g => Py.Lower(Py.Str(g))).ToHashSet();
        var stem = FileStem(path);
        return CsvSafe.Reading(path, () =>
        {
            var out_ = new List<SourceRecord>();
            var reader = new Csv.DictReader(Csv.ReadText(path, encoding), restKey: "_extra");
            int n = 0;
            foreach (var raw in reader.Rows())
            {
                n++;
                var row = new StrDict();
                int i = 0;
                foreach (var kv in raw)
                {
                    row[string.IsNullOrEmpty(kv.Key) ? $"Unnamed_{i}" : kv.Key] = kv.Value ?? "";
                    i++;
                }
                if (raw.Rest != null)
                    for (int j = 0; j < raw.Rest.Count; j++) row[$"Extra_{j + 1}"] = raw.Rest[j] ?? "";
                var cols = new Dictionary<string, string>
                {
                    ["name"] = row.ContainsKey("Title") ? "Title" : "Account",
                    ["username"] = row.ContainsKey("Username") ? "Username" : "Login Name",
                    ["password"] = "Password",
                    ["address"] = row.ContainsKey("URL") ? "URL" : "Web Site",
                    ["folder"] = row.ContainsKey("Group") ? "Group" : "",
                };
                var rec = Rows.RecordFromRow(row, cfg, Name, stem, $"row {n + 1}", n, columns: cols, folderSeparator: "/", fromCsv: true);
                if (rec.Folder.Any(g => skip.Contains(Py.Lower(g)))) continue;
                if (Py.Truthy(kcfg["drop_root_group"])) rec.Folder = rec.Folder.Skip(1).ToList();
                rec.Type = Py.Str(kcfg["type_from"]) == "group" ? string.Join("\\", rec.Folder) : Py.Str(kcfg["fixed_type"]);
                out_.Add(rec);
            }
            return out_;
        });
    }
}
