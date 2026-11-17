using System.Security.Cryptography;
using System.Text;
using Imw.Adapters;

namespace Imw.Core;

/// <summary>
/// Local staging database (SQLite), with the same tables as the earlier Python version, so a database made by
/// that version still opens.
///
///   ingest   load exports into the database once (secrets encrypted with DPAPI)
///   map      apply the config rules; results go into plan_* tables you can query
///   set      record deliberate changes (Migrate, Safe, platform, account name)
///   query    read-only SQL or built-in reports
///   extract  write review and upload CSVs, optionally for a subset (a wave)
///
/// Secrets live only in records.secret_enc, encrypted. Queries can never read secret_enc: the
/// read-only connection returns NULL for it.
/// </summary>
public class StoreError : Exception
{
    public StoreError(string message) : base(message) { }
}

public sealed class Store : IDisposable
{
    public const string SchemaVersion = "1";

    public const string Schema = @"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS inputs (
  id INTEGER PRIMARY KEY, source TEXT, path TEXT, sha256 TEXT, records INTEGER,
  permissions_path TEXT, permissions_sha256 TEXT, loaded_utc TEXT, loaded_by TEXT);
CREATE TABLE IF NOT EXISTS records (
  record_id TEXT PRIMARY KEY, input_id INTEGER, source TEXT, source_file TEXT, source_id TEXT,
  source_ref TEXT, name TEXT, folder TEXT, folder_json TEXT, type TEXT, address TEXT,
  username TEXT, secret_type TEXT, has_secret INTEGER, secret_enc TEXT, has_grants INTEGER,
  access_source TEXT, target_safe TEXT, target_platform TEXT, extra_json TEXT, notes_json TEXT);
CREATE TABLE IF NOT EXISTS grants (record_id TEXT, member TEXT, permission TEXT, member_type TEXT,
  basis TEXT DEFAULT '', hint TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS grants_record ON grants(record_id);
CREATE TABLE IF NOT EXISTS edits (
  record_id TEXT, field TEXT, value TEXT, changed_utc TEXT, changed_by TEXT, reason TEXT,
  PRIMARY KEY (record_id, field));
CREATE TABLE IF NOT EXISTS plan_accounts (
  record_id TEXT PRIMARY KEY, migrate TEXT, status TEXT, notes TEXT, target_safe TEXT,
  proposed_safe TEXT, valid_safe_name TEXT, safe_name_issues TEXT, safe_mapping_source TEXT,
  platform_id TEXT, platform_source TEXT, account_name TEXT, address TEXT, username TEXT,
  secret_type TEXT, has_secret TEXT, source TEXT, source_ref TEXT, source_type TEXT, folder TEXT,
  access_groups TEXT, access_source TEXT, approved TEXT);
CREATE TABLE IF NOT EXISTS plan_safes (
  safe_name TEXT PRIMARY KEY, length INTEGER, valid_safe_name TEXT, proposed_names TEXT,
  issues TEXT, mapping_sources TEXT, accounts INTEGER, accounts_to_upload INTEGER,
  managing_cpm TEXT, description TEXT, retention TEXT, location TEXT, olac_enabled TEXT,
  auto_purge TEXT, rule_names TEXT, override_json TEXT, rules_json TEXT);
CREATE TABLE IF NOT EXISTS plan_members (
  safe_name TEXT, source_member TEXT, member_name TEXT, search_in TEXT, member_type TEXT,
  source_permission TEXT, role TEXT, accounts INTEGER, notes TEXT, directory_source TEXT);
CREATE TABLE IF NOT EXISTS member_edits (
  safe_name TEXT, member_name TEXT, action TEXT, search_in TEXT, member_type TEXT, role TEXT,
  changed_utc TEXT, changed_by TEXT, reason TEXT, PRIMARY KEY (safe_name, member_name));
CREATE TABLE IF NOT EXISTS member_overrides (
  member_key TEXT PRIMARY KEY, member_name TEXT, member_type TEXT, search_in TEXT,
  changed_utc TEXT, changed_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS safe_overrides (
  safe_key TEXT PRIMARY KEY, settings_json TEXT, changed_utc TEXT, changed_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS approvals (
  record_id TEXT PRIMARY KEY, fingerprint TEXT, approved_utc TEXT, approved_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS ref_templates (input_id INTEGER, name TEXT, folder TEXT, template TEXT);
CREATE TABLE IF NOT EXISTS ref_users (input_id INTEGER, display_name TEXT, username TEXT, email TEXT);
CREATE TABLE IF NOT EXISTS member_decisions (
  folder TEXT, member TEXT, decision TEXT, changed_utc TEXT, changed_by TEXT, reason TEXT,
  PRIMARY KEY (folder, member));
CREATE TABLE IF NOT EXISTS plan_undecided (
  folder TEXT, safe_name TEXT, member TEXT, member_name TEXT, permission TEXT, groups TEXT,
  accounts INTEGER, decision TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts TEXT, user TEXT, host TEXT, action TEXT, detail TEXT);
CREATE VIEW IF NOT EXISTS accounts AS SELECT * FROM plan_accounts;
";

    public static readonly OrderedPairs EditFields = new()
    {
        { "migrate", "Migrate" }, { "target_safe", "Target_Safe" }, { "platform_id", "Platform_ID" }, { "account_name", "Account_Name" },
    };

    public static readonly OrderedPairs Reports = new()
    {
        { "summary", "SELECT status, migrate, COUNT(*) AS accounts FROM accounts GROUP BY status, migrate ORDER BY status, migrate" },
        { "inputs", "SELECT id, source, path, records, loaded_utc, loaded_by, sha256 FROM inputs ORDER BY id" },
        { "safes", "SELECT * FROM plan_safes ORDER BY safe_name" },
        { "invalid-safes", "SELECT * FROM plan_safes WHERE valid_safe_name = 'FALSE' ORDER BY safe_name" },
        { "errors", "SELECT record_id, notes, target_safe, platform_id, account_name, source_ref FROM accounts WHERE status = 'ERROR' ORDER BY record_id" },
        { "review", "SELECT record_id, notes, target_safe, platform_id, account_name, source_ref FROM accounts WHERE status = 'REVIEW' ORDER BY record_id" },
        { "no-access", "SELECT record_id, folder, target_safe, account_name FROM accounts WHERE access_groups = '' ORDER BY folder" },
        { "members", "SELECT * FROM plan_members ORDER BY safe_name, member_name" },
        { "platforms", "SELECT platform_id, source_type, COUNT(*) AS accounts FROM accounts GROUP BY platform_id, source_type ORDER BY platform_id" },
        { "edits", "SELECT * FROM edits ORDER BY changed_utc" },
        { "audit", "SELECT * FROM audit ORDER BY id" },
    };

    // What an approval covers: everything the review shows about one account.
    public static readonly string[] FingerprintFields = { "migrate", "status", "notes", "target_safe", "platform_id", "account_name",
        "address", "username", "secret_type", "has_secret", "source_type", "folder", "source_ref", "source_name" };

    public static string Now() => Py.NowUtcIso();

    public static string User()
    {
        try { return Py.GetUser(); }
        catch (Exception) { return "unknown"; }
    }

    public static string Sha256File(string path) => Writers.Sha256(path);

    public readonly string Path_;
    public Db Db;
    IProtector _protector;
    public int LastSanitized;

    public string FullPath => Path.GetFullPath(Path_);

    public Store(string path, bool create = false, string protector = null)
    {
        Path_ = path;
        if (!File.Exists(path) && !create) throw new StoreError($"database {path} does not exist; run 'ingest' first");
        bool isNew = !File.Exists(path);
        Identity me;
        try { me = Owner.CurrentIdentity(); }
        catch (OwnerError exc) { throw new StoreError(exc.Message); }
        try
        {
            Db = Db.Open(path);
            Db.Query("SELECT 1 FROM sqlite_master LIMIT 1");
        }
        catch (DbError exc)
        {
            Db?.Close();
            if (!isNew)
                throw new StoreError($"Can't open {path} ({exc.Message}). It probably belongs to another Windows user: " +
                                     "only the user who created a database can open it.");
            throw new StoreError(exc.Message);
        }
        Db.Execute("PRAGMA foreign_keys = ON");
        // Plan tables are rebuilt by every map, so an older layout is simply recreated.
        foreach (var (table, column) in new[] { ("plan_safes", "managing_cpm"), ("plan_safes", "rules_json"), ("plan_members", "directory_source") })
        {
            var cols = Db.Query($"PRAGMA table_info({table})").Select(r => r[1] as string).ToList();
            if (cols.Count > 0 && !cols.Contains(column)) Db.Execute($"DROP TABLE {table}");
        }
        Db.ExecuteScript(Schema);
        if (!Db.Query("PRAGMA table_info(plan_accounts)").Select(r => r[1] as string).Contains("approved"))
            Db.Execute("ALTER TABLE plan_accounts ADD COLUMN approved TEXT DEFAULT ''");
        var grantCols = Db.Query("PRAGMA table_info(grants)").Select(r => r[1] as string).ToList();
        foreach (var column in new[] { "basis", "hint" })
            if (!grantCols.Contains(column)) Db.Execute($"ALTER TABLE grants ADD COLUMN {column} TEXT DEFAULT ''");
        if (isNew)
        {
            SetMeta("schema_version", SchemaVersion);
            SetMeta("created_utc", Now());
            SetMeta("created_by", $"{User()}@{Py.Node()}");
            SetMeta("salt", Convert.ToBase64String(Protectors.NewSalt()));
            SetMeta("protector", protector ?? "dpapi");
            SetMeta("owner_sid", me.Sid);
            SetMeta("owner_name", me.Display);
            Db.Commit();
            try { Owner.Restrict(path, me.Sid); }
            catch (OwnerError exc)
            {
                Db.Close();
                File.Delete(path);
                throw new StoreError(exc.Message);
            }
        }
        else CheckOwner(me);
    }

    /// <summary>Only the Windows user who created the database may open it (see Owner).</summary>
    void CheckOwner(Identity me)
    {
        var owner = Meta("owner_sid");
        if (owner == null)
        {
            // made before owners were recorded: the creator's name decides
            var cb = Meta("created_by") ?? "";
            int at = cb.LastIndexOf('@');
            var creator = at >= 0 ? cb.Substring(0, at) : cb;
            if (Py.Lower(creator) != Py.Lower(me.User ?? ""))
            {
                Db.Close();
                throw new StoreError($"This database was created by {creator}. You are signed in to Windows as " +
                                     $"{me.Display}, so it stays closed.");
            }
            SetMeta("owner_sid", me.Sid);
            SetMeta("owner_name", me.Display);
            Db.Commit();
            Owner.Restrict(Path_, me.Sid);
        }
        else if (owner != me.Sid)
        {
            var name = Meta("owner_name") ?? owner;
            Db.Close();
            throw new StoreError($"This database belongs to {name}. You are signed in to Windows as " +
                                 $"{me.Display}, so it stays closed. Only the user who created a database can open it.");
        }
    }

    // -- meta / audit -----------------------------------------------------

    public void SetMeta(string key, string value) => Db.Execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", key, value);

    public string Meta(string key, string dflt = null)
    {
        var row = Db.One("SELECT value FROM meta WHERE key = ?", key);
        return row != null ? row[0] as string : dflt;
    }

    public void Audit(string action, JObj detail = null) =>
        Db.Execute("INSERT INTO audit(ts, user, host, action, detail) VALUES (?,?,?,?,?)",
                   Now(), User(), Py.Node(), action, Json.Dumps(detail ?? new JObj()));

    public IProtector Protector
    {
        get
        {
            if (_protector == null)
            {
                var name = Meta("protector");
                if (name == "none") throw new StoreError("this database was created with --no-secrets and holds no secrets");
                _protector = Protectors.Get(name, Convert.FromBase64String(Meta("salt")));
            }
            return _protector;
        }
    }

    // -- ingest -----------------------------------------------------------

    public (int, int) Ingest(string source, string path, List<SourceRecord> records, Permissions perms = null, IEnumerable<string> permsPath = null)
    {
        var permsPaths = (permsPath ?? Array.Empty<string>()).Where(p => !string.IsNullOrEmpty(p)).ToList();
        bool storeSecrets = Meta("protector") != "none";
        var pp = string.Join(" | ", permsPaths.Select(Path.GetFullPath));
        var ps = string.Join(" | ", permsPaths.Select(Sha256File));
        Db.Execute("INSERT INTO inputs(source, path, sha256, records, permissions_path, permissions_sha256, " +
                   "loaded_utc, loaded_by) VALUES (?,?,?,?,?,?,?,?)",
                   source, Path.GetFullPath(path), Sha256File(path), (long)records.Count,
                   pp.Length > 0 ? pp : null, ps.Length > 0 ? ps : null, Now(), User());
        long inputId = Db.LastInsertRowId;
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        int replaced = 0;
        LastSanitized = 0;
        foreach (var rec in records)
        {
            if (Transform.SanitizeRecord(rec).Count > 0) LastSanitized++;
            // Permissions are looked up by the id as written in the source, so resolve them before a
            // duplicate id gets its #N suffix.
            if (rec.Grants == null && perms != null)
            {
                var (grants, how) = perms.Resolve(rec);
                rec.AccessSource = how;
                rec.Grants = grants.ToList();
            }
            else if (rec.Grants != null)
                rec.AccessSource = string.IsNullOrEmpty(rec.AccessSource) ? "source" : rec.AccessSource;
            var bas = rec.RecordId;
            seen[bas] = seen.GetValueOrDefault(bas) + 1;
            if (seen[bas] > 1)
            {
                rec.SourceId = $"{rec.SourceId}#{seen[bas]}";
                rec.Notes.Add("duplicate id in the source; suffixed in Record_ID");
            }
            string secretEnc = null;
            if (!string.IsNullOrEmpty(rec.Secret) && storeSecrets) secretEnc = Protector.Protect(rec.Secret, rec.RecordId);
            var rid = rec.RecordId;
            if (Db.One("SELECT 1 FROM records WHERE record_id = ?", rid) != null) replaced++;
            Db.Execute("DELETE FROM grants WHERE record_id = ?", rid);
            Db.Execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rid, inputId, rec.Source, rec.SourceFile, rec.SourceId, rec.SourceRef, rec.Name,
                rec.FolderPath, Json.Dumps(rec.Folder.Cast<object>().ToList()), rec.Type, rec.Address, rec.Username,
                rec.SecretType, Py.Strip(rec.Secret ?? "").Length > 0 ? 1L : 0L, secretEnc,
                rec.Grants == null ? 0L : 1L, string.IsNullOrEmpty(rec.AccessSource) ? "none" : rec.AccessSource, rec.TargetSafe,
                rec.TargetPlatform, Json.Dumps(rec.Extra.ToJObj()), Json.Dumps(rec.Notes.Cast<object>().ToList()));
            foreach (var g in rec.Grants ?? new List<Grant>())
                Db.Execute("INSERT INTO grants(record_id, member, permission, member_type, basis, hint) VALUES (?,?,?,?,?,?)",
                           rid, g.Member, g.Permission, g.MemberType, g.Basis, g.Hint);
            rec.Secret = "";   // drop the plaintext as soon as it is stored
        }
        Audit("ingest", Json.O(("source", source), ("path", path), ("records", (long)records.Count), ("replaced", (long)replaced),
            ("sanitized", (long)LastSanitized), ("permissions", string.Join(" | ", permsPaths)), ("secrets_stored", storeSecrets)));
        Db.Commit();
        return (records.Count, replaced);
    }

    /// <summary>A reference file (Reference.cs): templates by secret name, or the users list. Loading a file
    /// with the same name and kind again replaces what it gave before.</summary>
    public int IngestReference(string kind, string path, List<(string, string, string)> rows)
    {
        var name = Py.Lower(Path.GetFileName(path));
        foreach (var old in Db.Query("SELECT id, path FROM inputs WHERE source = ?", kind))
        {
            var op = Str(old["path"]) ?? "";
            if (Py.Lower(Path.GetFileName(op)) == name || Py.Lower(Path.GetFileName(op.Replace('\\', '/'))) == name)
                foreach (var table in new[] { "ref_templates", "ref_users" })
                    Db.Execute($"DELETE FROM {table} WHERE input_id = ?", old["id"]);
        }
        Db.Execute("INSERT INTO inputs(source, path, sha256, records, loaded_utc, loaded_by) VALUES (?,?,?,?,?,?)",
                   kind, Path.GetFullPath(path), Sha256File(path), (long)rows.Count, Now(), User());
        long inputId = Db.LastInsertRowId;
        var tbl = kind == "templates" ? "ref_templates" : kind == "users" ? "ref_users" : throw new StoreError($"unknown reference '{kind}'");
        foreach (var (a, b, c) in rows) Db.Execute($"INSERT INTO {tbl} VALUES (?,?,?,?)", inputId, a, b, c);
        Audit("ingest", Json.O(("source", kind), ("path", path), ("records", (long)rows.Count)));
        Db.Commit();
        return rows.Count;
    }

    public References References()
    {
        var templates = Db.Query("SELECT name, folder, template FROM ref_templates ORDER BY input_id, rowid")
                          .Select(r => (Str(r[0]), Str(r[1]), Str(r[2]))).ToList();
        var users = Db.Query("SELECT display_name, username, email FROM ref_users ORDER BY input_id, rowid")
                      .Select(r => (Str(r[0]), Str(r[1]), Str(r[2]))).ToList();
        var decisions = new Dictionary<(string, string), string>();
        foreach (var r in Db.Query("SELECT folder, member, decision FROM member_decisions"))
            decisions[(Str(r["folder"]), Str(r["member"]))] = Str(r["decision"]);
        return new References(templates, users, decisions);
    }

    /// <summary>Include or exclude users who may get their access through a group, per folder; decision ""
    /// takes the decision back.</summary>
    public int SetDecisions(IEnumerable<(string Folder, string Member)> items, string decision, string reason = "")
    {
        if (decision is not ("include" or "exclude" or "")) throw new StoreError($"unknown decision '{decision}'");
        int done = 0;
        foreach (var (folder, member) in items)
        {
            var key = (Reference.FolderKey(folder ?? ""), Py.Lower(Py.Strip(member ?? "")));
            if (key.Item2.Length == 0) continue;
            Db.Execute("DELETE FROM member_decisions WHERE folder = ? AND member = ?", key.Item1, key.Item2);
            if (decision.Length > 0)
                Db.Execute("INSERT INTO member_decisions VALUES (?,?,?,?,?,?)", key.Item1, key.Item2, decision, Now(), User(), reason);
            done++;
        }
        Audit("decide", Json.O(("decision", decision.Length > 0 ? decision : "undo"), ("users", (long)done), ("reason", reason)));
        Db.Commit();
        return done;
    }

    // -- load -------------------------------------------------------------

    static string Str(object v) => v as string ?? (v == null ? null : Py.Str(v));

    public List<SourceRecord> LoadRecords(bool withSecrets = false)
    {
        var grants = new Dictionary<string, List<Grant>>(StringComparer.Ordinal);
        foreach (var g in Db.Query("SELECT * FROM grants"))
        {
            var rid = Str(g["record_id"]);
            if (!grants.TryGetValue(rid, out var l)) grants[rid] = l = new List<Grant>();
            l.Add(new Grant(Str(g["member"]), Str(g["permission"]), Str(g["member_type"]), Str(g["basis"]) ?? "", Str(g["hint"]) ?? ""));
        }
        var out_ = new List<SourceRecord>();
        foreach (var r in Db.Query("SELECT * FROM records ORDER BY input_id, rowid"))
        {
            bool hasGrants = Py.Truthy(r["has_grants"]);
            var extra = new StrDict();
            foreach (var kv in Json.ParseObj(Str(r["extra_json"]))) extra[kv.Key] = Str(kv.Value);
            var rec = new SourceRecord(Str(r["source"]), Str(r["source_file"]), Str(r["source_id"]), Str(r["source_ref"]))
            {
                Name = Str(r["name"]),
                Folder = ((List<object>)Json.Parse(Str(r["folder_json"]))).Select(Str).ToList(),
                Type = Str(r["type"]),
                Address = Str(r["address"]),
                Username = Str(r["username"]),
                SecretType = Str(r["secret_type"]),
                HasSecret = Py.Truthy(r["has_secret"]),
                Grants = hasGrants ? (grants.TryGetValue(Str(r["record_id"]), out var gl) ? gl : new List<Grant>()) : null,
                AccessSource = hasGrants ? Str(r["access_source"]) : "",
                TargetSafe = Str(r["target_safe"]),
                TargetPlatform = Str(r["target_platform"]),
                Extra = extra,
                Notes = ((List<object>)Json.Parse(Str(r["notes_json"]))).Select(Str).ToList(),
            };
            if (withSecrets && Py.Truthy(r["secret_enc"])) rec.Secret = Protector.Unprotect(Str(r["secret_enc"]), Str(r["record_id"]));
            out_.Add(rec);
        }
        return out_;
    }

    public Dictionary<string, Dictionary<string, string>> Overrides()
    {
        var ov = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        foreach (var e in Db.Query("SELECT record_id, field, value FROM edits"))
        {
            var rid = Str(e["record_id"]);
            if (!ov.TryGetValue(rid, out var d)) ov[rid] = d = new Dictionary<string, string>(StringComparer.Ordinal);
            var col = EditFields[Str(e["field"])] ?? throw new KeyError(Str(e["field"]));
            d[col] = Str(e["value"]);
        }
        return ov;
    }

    // -- map --------------------------------------------------------------

    public JObj StoredConfig()
    {
        var text = Meta("config");
        if (text == null) throw new StoreError("no config stored yet; run 'map' first");
        return Json.ParseObj(text);
    }

    public List<JObj> MemberEdits() => Db.Query("SELECT * FROM member_edits ORDER BY changed_utc").Select(r => r.ToJObj()).ToList();

    /// <summary>action: add | remove | undo, for each Safe in safes.</summary>
    public int SetMemberEdits(List<string> safes, string memberName, string action, string searchIn = "", string memberType = "",
                              string role = "", string reason = "")
    {
        if (action is not ("add" or "remove" or "undo")) throw new StoreError("action must be add, remove or undo");
        foreach (var safe in safes)
        {
            Db.Execute("DELETE FROM member_edits WHERE lower(safe_name) = lower(?) AND lower(member_name) = lower(?)", safe, memberName);
            if (action != "undo")
                Db.Execute("INSERT INTO member_edits VALUES (?,?,?,?,?,?,?,?,?)",
                           safe, memberName, action, searchIn, memberType, role, Now(), User(), reason);
        }
        Audit("member_" + action, Json.O(("safes", safes.Cast<object>().ToList()), ("member", memberName), ("role", role),
            ("search_in", searchIn), ("reason", reason)));
        Db.Commit();
        return safes.Count;
    }

    /// <summary>lower source member name -> {member_name, member_type, search_in, ...}; null = not changed.</summary>
    public Dictionary<string, JObj> MemberOverrides() =>
        Db.Query("SELECT * FROM member_overrides").ToDictionary(r => Str(r["member_key"]), r => r.ToJObj(), StringComparer.Ordinal);

    /// <summary>Change one member everywhere it appears. undo=true puts the rules' values back.</summary>
    public void SetMemberOverride(string memberKey, string memberName = null, string memberType = null, string searchIn = null,
                                  string reason = "", bool undo = false)
    {
        var key = Py.Lower(Py.Strip(memberKey ?? ""));
        if (key.Length == 0) throw new StoreError("name the member to change");
        Db.Execute("DELETE FROM member_overrides WHERE member_key = ?", key);
        if (!undo && (memberName != null || memberType != null || searchIn != null))
            Db.Execute("INSERT INTO member_overrides VALUES (?,?,?,?,?,?,?)",
                       key, string.IsNullOrEmpty(memberName) ? null : memberName, string.IsNullOrEmpty(memberType) ? null : memberType,
                       searchIn, Now(), User(), reason);
        Audit(undo ? "member_undo" : "member_change", Json.O(("member", memberKey), ("member_name", memberName),
            ("member_type", memberType), ("search_in", searchIn), ("reason", reason)));
        Db.Commit();
    }

    /// <summary>lower Safe name as the rules give it -> {"new_name", "description", ..., "key", "changed_utc",
    /// "changed_by", "reason"}: your direct changes to whole Safes.</summary>
    public Dictionary<string, JObj> SafeOverrides()
    {
        var out_ = new Dictionary<string, JObj>(StringComparer.Ordinal);
        foreach (var r in Db.Query("SELECT * FROM safe_overrides"))
        {
            var d = Json.ParseObj(Py.Truthy(r["settings_json"]) ? Str(r["settings_json"]) : "{}");
            d["key"] = r["safe_key"];
            d["changed_utc"] = r["changed_utc"];
            d["changed_by"] = r["changed_by"];
            d["reason"] = r["reason"];
            out_[Str(r["safe_key"])] = d;
        }
        return out_;
    }

    /// <summary>Rename one Safe or change its settings, kept across re-mapping. safeKey is the Safe's name as the
    /// rules give it. Per-Safe member changes follow a rename (oldName -> newName).</summary>
    public void SetSafeOverride(string safeKey, JObj settings, string reason = "", bool undo = false, string oldName = null, string newName = null)
    {
        var key = Py.Lower(Py.Strip(safeKey ?? ""));
        if (key.Length == 0) throw new StoreError("name the Safe to change");
        var row = Db.One("SELECT settings_json FROM safe_overrides WHERE safe_key = ?", key);
        var moved = new List<string>();
        if (row != null)
        {
            var prev = Json.ParseObj(Py.Truthy(row["settings_json"]) ? Str(row["settings_json"]) : "{}");
            moved = (prev.Get("moved_edits") as List<object> ?? new List<object>()).Select(Str).ToList();
        }
        Db.Execute("DELETE FROM safe_overrides WHERE safe_key = ?", key);
        var clean = new JObj();
        foreach (var kv in settings ?? new JObj())
            if (kv.Value != null && !(kv.Value is string s && s.Length == 0) && kv.Key != "moved_edits") clean[kv.Key] = kv.Value;
        if (!string.IsNullOrEmpty(oldName) && !string.IsNullOrEmpty(newName) && Py.Lower(oldName) != Py.Lower(newName))
            moved = MoveMemberEdits(key, oldName, newName, moved);
        if (!undo && clean.Count > 0)
        {
            if (moved.Count > 0) clean["moved_edits"] = moved.Cast<object>().ToList();
            Db.Execute("INSERT INTO safe_overrides VALUES (?,?,?,?,?)", key, Json.Dumps(clean), Now(), User(), reason);
        }
        Audit(undo ? "safe_undo" : "safe_change", Json.O(("safe", safeKey), ("settings", clean), ("reason", reason)));
        Db.Commit();
    }

    List<string> MoveMemberEdits(string key, string oldName, string newName, List<string> moved)
    {
        var held = Db.One("SELECT rule_names FROM plan_safes WHERE lower(safe_name) = lower(?)", oldName);
        var holders = held == null ? new HashSet<string>()
            : (Str(held["rule_names"]) ?? "").Split(" | ").Select(n => Py.Lower(Py.Strip(n))).Where(n => n.Length > 0).ToHashSet();
        var rows = Db.Query("SELECT * FROM member_edits WHERE lower(safe_name) = lower(?)", oldName);
        if (holders.Any(h => h != key))
        {
            var mine = moved.Select(Py.Lower).ToHashSet();
            if (Py.Lower(oldName) == key)
            {
                var claimed = new HashSet<string>();
                foreach (var (otherKey, ov) in SafeOverrides())
                    if (otherKey != key && holders.Contains(otherKey))
                        foreach (var m in ov.Get("moved_edits") as List<object> ?? new List<object>()) claimed.Add(Py.Lower(Str(m)));
                rows = rows.Where(r => mine.Contains(Py.Lower(Str(r["member_name"]))) || !claimed.Contains(Py.Lower(Str(r["member_name"])))).ToList();
            }
            else rows = rows.Where(r => mine.Contains(Py.Lower(Str(r["member_name"])))).ToList();
        }
        var out_ = new List<string>();
        foreach (var r in rows)
        {
            var there = Db.Query("SELECT changed_utc FROM member_edits WHERE lower(safe_name) = lower(?) AND lower(member_name) = lower(?)",
                                 newName, r["member_name"]);
            Db.Execute("DELETE FROM member_edits WHERE safe_name = ? AND member_name = ?", r["safe_name"], r["member_name"]);
            if (there.Any(t => Py.Cmp(Str(t["changed_utc"]) ?? "", Str(r["changed_utc"]) ?? "") > 0)) continue;   // newer change stays
            Db.Execute("DELETE FROM member_edits WHERE lower(safe_name) = lower(?) AND lower(member_name) = lower(?)", newName, r["member_name"]);
            Db.Execute("INSERT INTO member_edits VALUES (?,?,?,?,?,?,?,?,?)",
                       newName, r["member_name"], r["action"], r["search_in"], r["member_type"], r["role"],
                       r["changed_utc"], r["changed_by"], r["reason"]);
            out_.Add(Str(r["member_name"]));
        }
        return out_;
    }

    public Plan Plan(JObj cfg, bool withSecrets = false) =>
        Transform.BuildPlan(LoadRecords(withSecrets), cfg, null, Overrides(), @explicit: true,
                            memberEdits: MemberEdits(), memberOverrides: MemberOverrides(), safeOverrides: SafeOverrides(),
                            refs: References());

    static string YesNo(object v) =>
        v == null || (v is string s && s.Length == 0) ? "" : (Py.Lower(Py.Str(v)) is "true" or "1" or "yes" ? "Yes" : "No");

    public Plan Map(JObj cfg, string cfgPath = null)
    {
        var plan = Plan(cfg);
        Db.Execute("DELETE FROM plan_accounts");
        Db.Execute("DELETE FROM plan_safes");
        Db.Execute("DELETE FROM plan_members");
        Db.Execute("DELETE FROM plan_undecided");
        foreach (var h in plan.Undecided)
            Db.Execute("INSERT INTO plan_undecided VALUES (?,?,?,?,?,?,?,?,?)",
                       h.Folder, h.Safe, h.Member, h.MemberName, h.Permission, h.Groups, (long)h.Accounts, h.Decision, h.Note);
        foreach (var p in plan.Accounts)
        {
            var r = p.Rec;
            Db.Execute("INSERT INTO plan_accounts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                r.RecordId, p.Migrate, p.Status, string.Join("; ", p.Errors.Concat(p.Warnings)), p.Safe,
                p.ProposedSafe, p.ValidSafe ? "TRUE" : "FALSE", string.Join("; ", p.SafeIssues),
                p.SafeSource, p.Platform, p.PlatformSource, p.AccountName, r.Address, r.Username,
                r.SecretType, r.HasSecret == true ? "Y" : "N", r.Source, r.SourceRef, r.Type,
                r.FolderPath, string.Join("; ", p.Grants.Select(g => $"{g.Member}={g.Permission}")),
                p.AccessSource, "");
        }
        foreach (var (name, s) in plan.Safes)
        {
            var body = Transform.SafeSettings(name, s, cfg);
            string retention;
            if (Py.Strip(Py.Str(body.Get("numberOfVersionsRetention", ""))).Length > 0)
                retention = $"{Py.Str(body["numberOfVersionsRetention"])} versions";
            else if (Py.Strip(Py.Str(body.Get("numberOfDaysRetention", ""))).Length > 0)
                retention = $"{Py.Str(body["numberOfDaysRetention"])} days";
            else retention = "";
            var rules = Transform.SafeSettings(name, s, cfg, withOverride: false);
            var rulesJson = new JObj();
            foreach (var k in Transform.SafeOverrideKeys) rulesJson[k] = rules.Get(k, "");
            Db.Execute("INSERT INTO plan_safes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                name, (long)Py.Len(name), s.Valid ? "TRUE" : "FALSE",
                string.Join(" | ", Py.Sorted(s.Proposed)), string.Join(" | ", Py.Sorted(s.Issues)),
                string.Join(" | ", Py.Sorted(s.Sources)), (long)s.Accounts, (long)s.Migrating,
                DbValue(body.Get("managingCPM", "")), DbValue(body.Get("description", "")), retention,
                DbValue(body.Get("location", "")), YesNo(body.Get("olacEnabled")),
                YesNo(body.Get("autoPurgeEnabled")), string.Join(" | ", Py.Sorted(s.RuleNames)),
                Py.Truthy(s.Override) ? Json.Dumps(s.Override) : "",
                Json.Dumps(rulesJson));
        }
        foreach (var kv in plan.Members)
        {
            var m = kv.Value;
            Db.Execute("INSERT INTO plan_members VALUES (?,?,?,?,?,?,?,?,?,?)",
                kv.Key.Item1, m.SourceName, m.MemberName, m.SearchIn, m.MemberType,
                m.Permission, string.IsNullOrEmpty(m.Role) ? "UNMAPPED" : m.Role, (long)m.Accounts, string.Join("; ", m.Notes ?? new()),
                m.DirectorySource ?? "");
        }
        CheckApprovals();
        SetMeta("config", Json.Dumps(cfg));
        SetMeta("config_path", string.IsNullOrEmpty(cfgPath) ? "(defaults)" : cfgPath);
        SetMeta("mapped_utc", Now());
        Audit("map", Json.O(("config", string.IsNullOrEmpty(cfgPath) ? "(defaults)" : cfgPath), ("accounts", (long)plan.Accounts.Count)));
        Db.Commit();
        return plan;
    }

    /// <summary>A JSON value as sqlite3 would store it (bool -> 1/0, lists and objects refused like Python).</summary>
    static object DbValue(object v) => v switch
    {
        JObj or List<object> => throw new StoreError($"Error binding parameter - probably unsupported type: {Py.Repr(v)}"),
        _ => v,
    };

    // -- approvals ----------------------------------------------------------

    List<DbRow> FingerprintRows(IEnumerable<string> ids = null)
    {
        const string sql = "SELECT p.*, r.name AS source_name FROM plan_accounts p JOIN records r USING (record_id)";
        if (ids == null) return Db.Query(sql);
        var list = ids.ToList();
        var out_ = new List<DbRow>();
        for (int i = 0; i < list.Count; i += 500)
        {
            var chunk = list.Skip(i).Take(500).Cast<object>().ToList();
            out_.AddRange(Db.QueryList(sql + $" WHERE p.record_id IN ({string.Join(",", chunk.Select(_ => "?"))})", chunk));
        }
        return out_;
    }

    public static string AccountFingerprint(DbRow row)
    {
        var data = Json.Dumps(FingerprintFields.Select(k => (object)(row[k] == null ? "" : Py.Str(row[k]))).ToList());
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(data)));
    }

    /// <summary>Mark the accounts whose approval still holds; drop the others.</summary>
    int CheckApprovals()
    {
        var approvals = new OrderedMap<string, string>(StringComparer.Ordinal);
        foreach (var r in Db.Query("SELECT record_id, fingerprint FROM approvals")) approvals[Str(r[0])] = Str(r[1]);
        if (approvals.Count == 0) return 0;
        var keep = new List<object>();
        var dropped = new List<object>();
        foreach (var row in FingerprintRows())
        {
            var rid = Str(row["record_id"]);
            if (!approvals.TryGetValue(rid, out var fp)) continue;
            approvals.Remove(rid);
            if (Str(row["status"]) == "REVIEW" && fp == AccountFingerprint(row)) keep.Add(rid);
            else dropped.Add(rid);
        }
        dropped.AddRange(approvals.Keys);     // records that are gone
        for (int i = 0; i < keep.Count; i += 500)
        {
            var chunk = keep.Skip(i).Take(500).ToList();
            Db.Execute($"UPDATE plan_accounts SET approved = 'Y' WHERE record_id IN ({string.Join(",", chunk.Select(_ => "?"))})", chunk.ToArray());
        }
        for (int i = 0; i < dropped.Count; i += 500)
        {
            var chunk = dropped.Skip(i).Take(500).ToList();
            Db.Execute($"DELETE FROM approvals WHERE record_id IN ({string.Join(",", chunk.Select(_ => "?"))})", chunk.ToArray());
        }
        if (dropped.Count > 0) Audit("approval_cleared", Json.O(("records", (long)dropped.Count)));
        return dropped.Count;
    }

    /// <summary>Approve accounts that need a look (or take the approval back). Returns how many changed.</summary>
    public int Approve(IEnumerable<string> ids, bool approve = true, string reason = "")
    {
        int n = 0;
        foreach (var row in FingerprintRows(ids))
        {
            var rid = Str(row["record_id"]);
            if (approve)
            {
                if (Str(row["status"]) != "REVIEW") continue;
                Db.Execute("INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?)", rid, AccountFingerprint(row), Now(), User(), reason);
                Db.Execute("UPDATE plan_accounts SET approved = 'Y' WHERE record_id = ?", rid);
                n++;
            }
            else if (Db.Execute("DELETE FROM approvals WHERE record_id = ?", rid) > 0)
            {
                Db.Execute("UPDATE plan_accounts SET approved = '' WHERE record_id = ?", rid);
                n++;
            }
        }
        if (n > 0) Audit(approve ? "approve" : "unapprove", Json.O(("records", (long)n), ("reason", reason)));
        Db.Commit();
        return n;
    }

    // -- edits ------------------------------------------------------------

    /// <summary>Record ids from the accounts view matching a WHERE clause, read-only.</summary>
    public List<string> SelectIds(string where, IReadOnlyList<object> args = null)
    {
        using var ro = ReadOnly();
        try { return ro.QueryList($"SELECT record_id FROM accounts WHERE {where}", args ?? Array.Empty<object>()).Select(r => Str(r[0])).ToList(); }
        catch (DbError exc) { throw new StoreError($"bad --where clause: {exc.Message}"); }
    }

    public int SetEdits(List<string> ids, OrderedPairs values, string reason = "")
    {
        var known = Db.Query("SELECT record_id FROM records").Select(r => Str(r[0])).ToHashSet(StringComparer.Ordinal);
        var missing = ids.Where(i => !known.Contains(i)).ToList();
        if (missing.Count > 0) throw new StoreError($"unknown record id(s): {string.Join(", ", missing.Take(5))}");
        int n = 0;
        foreach (var rid in ids)
        {
            foreach (var kv in values)
            {
                if (kv.Value == null) continue;
                if (kv.Value == "") Db.Execute("DELETE FROM edits WHERE record_id = ? AND field = ?", rid, kv.Key);
                else Db.Execute("INSERT OR REPLACE INTO edits VALUES (?,?,?,?,?,?)", rid, kv.Key, kv.Value, Now(), User(), reason);
                n++;
            }
        }
        var vals = new JObj();
        foreach (var kv in values) vals[kv.Key] = kv.Value;
        Audit("set", Json.O(("records", (long)ids.Count), ("values", vals), ("reason", reason)));
        Db.Commit();
        return n;
    }

    /// <summary>Take changed values from an edited Accounts_Review.csv as edits.</summary>
    public int ImportReview(string path, string encoding = "utf-8-sig")
    {
        var current = new Dictionary<string, DbRow>(StringComparer.Ordinal);
        foreach (var r in Db.Query("SELECT * FROM plan_accounts")) current[Str(r["record_id"])] = r;
        var cols = new OrderedPairs { { "Migrate", "migrate" }, { "Target_Safe", "target_safe" }, { "Platform_ID", "platform_id" }, { "Account_Name", "account_name" } };
        int count = 0;
        CsvSafe.Reading(path, () =>
        {
            var reader = new Csv.DictReader(Csv.ReadText(path, encoding));
            foreach (var row in reader.Rows())
            {
                var rid = Py.Strip(CsvSafe.Unescape(Py.Strip(row["Record_ID"] ?? "")));
                if (!current.TryGetValue(rid, out var cur)) continue;
                var vals = new OrderedPairs();
                foreach (var (col, fld) in cols)
                {
                    var nv = Py.Strip(CsvSafe.Unescape(Py.Strip(row[col] ?? "")));
                    if (fld == "migrate")
                    {
                        if (nv.Length > 0 && Py.Upper(nv) != Py.Upper(Str(cur[fld]))) vals[fld] = Py.Upper(nv);
                    }
                    else if (Transform.Changed(nv, Str(cur[fld]))) vals[fld] = nv;
                }
                if (vals.Count > 0)
                {
                    SetEdits(new List<string> { rid }, vals, reason: $"imported from {Path.GetFileName(path)}");
                    count++;
                }
            }
            return 0;
        });
        return count;
    }

    // -- query ------------------------------------------------------------

    const int SqliteDeny = 1, SqliteIgnore = 2, SqliteAttach = 24, SqliteRead = 20;

    /// <summary>A read-only connection: records.secret_enc reads as NULL and ATTACH is refused.</summary>
    public Db ReadOnly()
    {
        var con = Db.Open(Path.GetFullPath(Path_), readOnly: true);
        SQLitePCL.raw.sqlite3_set_authorizer(con.Conn.Handle, (SQLitePCL.strdelegate_authorizer)((_, action, arg1, arg2, _, _) =>
        {
            if (action == SqliteAttach) return SqliteDeny;      // no writing into other database files
            if (action == SqliteRead && arg1 == "records" && arg2 == "secret_enc") return SqliteIgnore;   // reads as NULL
            return 0;
        }), null);
        return con;
    }

    public (List<string>, List<object[]>) Query(string sql, IReadOnlyList<object> args = null)
    {
        using var con = ReadOnly();
        try { return con.QueryTable(sql, args); }
        catch (DbError exc) { throw new StoreError(exc.Message); }
    }

    public List<object> InputsForManifest() =>
        Db.Query("SELECT * FROM inputs").Select(r => (object)Json.O(("source", r["source"]), ("path", r["path"]),
            ("sha256", r["sha256"]), ("loaded_utc", r["loaded_utc"]))).ToList();

    public void Close() => Db?.Close();
    public void Dispose() => Close();

    // -- extract ----------------------------------------------------------

    public static (Plan, JObj) ExtractPlan(Store store, string where = null, bool includeSecrets = false, IReadOnlyList<object> args = null)
    {
        var cfg = store.StoredConfig();
        if (includeSecrets && store.Meta("protector") == "none")
            throw new StoreError("this database was created with --no-secrets, so it has no secrets to " +
                                 "extract; ingest into a new database without --no-secrets");
        Plan plan;
        if (includeSecrets)
        {
            try { plan = store.Plan(cfg, withSecrets: true); }
            catch (ProtectError exc) { throw new StoreError(exc.Message); }
        }
        else plan = store.Plan(cfg);
        if (!string.IsNullOrEmpty(where))
        {
            var keep = store.SelectIds(where, args).ToHashSet(StringComparer.Ordinal);
            foreach (var p in plan.Accounts) p.InScope = keep.Contains(p.Rec.RecordId);
            Transform.RebuildTotals(plan, cfg);
        }
        return (plan, cfg);
    }

    /// <summary>Write review + upload files and the manifest. Returns (plan, counts, files).</summary>
    public static (Plan, JObj, List<string>) RunExtract(Store store, string outDir, string where = null, bool includeSecrets = false,
                                                        IReadOnlyList<object> args = null, string label = "")
    {
        var (plan, cfg) = ExtractPlan(store, where, includeSecrets, args);
        Directory.CreateDirectory(outDir);
        var files = Writers.WriteReview(plan, outDir);
        files.Add(Writers.WriteConvention(plan, cfg, outDir));
        var (uploadFiles, counts) = Writers.WriteUpload(plan, cfg, outDir, includeSecrets);
        files.AddRange(uploadFiles);
        var filter = !string.IsNullOrEmpty(label) ? label : where ?? "";
        counts["records"] = (long)plan.Accounts.Count;
        counts["filter"] = filter;
        counts["database"] = store.FullPath;
        Writers.WriteManifest(outDir, store.InputsForManifest(), files, counts, includeSecrets, store.Meta("config_path"));
        store.Audit("extract", Json.O(("output", Path.GetFullPath(outDir)), ("where", filter),
            ("include_secrets", includeSecrets), ("accounts", counts["accounts"])));
        store.Db.Commit();
        return (plan, counts, files);
    }

    public static void PrintTable(List<string> cols, List<object[]> rows, TextWriter out_ = null, int maxWidth = 60)
    {
        out_ ??= Console.Out;
        if (cols.Count == 0)
        {
            out_.WriteLine("(no columns)");
            return;
        }
        var text = rows.Select(row => row.Select(v => Py.Head((v == null ? "" : Py.Str(v)).Replace("\n", " "), maxWidth)).ToList()).ToList();
        var widths = cols.Select((c, i) => Math.Max(Py.Len(c), text.Count == 0 ? 0 : text.Max(r => Py.Len(r[i])))).ToList();
        string Pad(string s, int w) => s + new string(' ', Math.Max(0, w - Py.Len(s)));
        out_.WriteLine(string.Join("  ", cols.Select((c, i) => Pad(c, widths[i]))));
        out_.WriteLine(string.Join("  ", widths.Select(w => new string('-', w))));
        foreach (var r in text) out_.WriteLine(string.Join("  ", r.Select((v, i) => Pad(v, widths[i]))));
        out_.WriteLine($"({rows.Count} rows)");
    }
}
