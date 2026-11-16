using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Imw.Core;

/// <summary>A database error with SQLite's own message (as Python's sqlite3 shows it).</summary>
public class DbError : Exception
{
    public DbError(string message) : base(message) { }

    public static DbError From(SqliteException exc)
    {
        var m = Regex.Match(exc.Message, @"^SQLite Error \d+: '(.*)'\.?$", RegexOptions.Singleline);
        return new DbError(m.Success ? m.Groups[1].Value : exc.Message);
    }
}

/// <summary>One result row: values by column index or by name (sqlite3.Row).</summary>
public sealed class DbRow
{
    readonly string[] _cols;
    readonly object[] _vals;

    public DbRow(string[] cols, object[] vals) { _cols = cols; _vals = vals; }

    public object this[int i] => _vals[i];

    public object this[string name]
    {
        get
        {
            for (int i = 0; i < _cols.Length; i++)
                if (string.Equals(_cols[i], name, StringComparison.OrdinalIgnoreCase)) return _vals[i];
            throw new KeyError(name);
        }
    }

    public string S(string name) => this[name] as string;
    public long? L(string name) => this[name] is long l ? l : null;
    public IReadOnlyList<string> Columns => _cols;
    public object[] Values => _vals;
    public int Count => _vals.Length;

    /// <summary>dict(row)</summary>
    public JObj ToJObj()
    {
        var o = new JObj();
        for (int i = 0; i < _cols.Length; i++) o[_cols[i]] = _vals[i];
        return o;
    }
}

public class KeyError : Exception
{
    public KeyError(string key) : base(key) { }
}

/// <summary>
/// A SQLite connection used the way Python's sqlite3 module uses one: "?" parameters, an implicit
/// BEGIN before INSERT / UPDATE / DELETE / REPLACE, nothing kept until Commit(), and closing without
/// Commit() throws the open changes away.
/// </summary>
public sealed class Db : IDisposable
{
    public readonly SqliteConnection Conn;
    public bool IsOpen { get; private set; }

    public Db(string connectionString)
    {
        Conn = new SqliteConnection(connectionString);
        try { Conn.Open(); }
        catch (SqliteException exc) { Conn.Dispose(); throw DbError.From(exc); }
        IsOpen = true;
    }

    public static Db Open(string path, bool readOnly = false) =>
        new(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());

    public bool InTransaction => SQLitePCL.raw.sqlite3_get_autocommit(Conn.Handle) == 0;

    static readonly Regex Dml = new(@"^\s*(?:(?:--[^\n]*\n|/\*.*?\*/)\s*)*(INSERT|UPDATE|DELETE|REPLACE)\b",
                                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

    /// <summary>"?" placeholders -> "?1", "?2"... outside quotes and comments, so they bind by position.</summary>
    public static string NumberPlaceholders(string sql, out int count)
    {
        var sb = new StringBuilder(sql.Length + 8);
        count = 0;
        int i = 0;
        while (i < sql.Length)
        {
            char c = sql[i];
            if (c == '\'' || c == '"' || c == '`' || c == '[')
            {
                char close = c == '[' ? ']' : c;
                int j = i + 1;
                while (j < sql.Length)
                {
                    if (sql[j] == close)
                    {
                        if (close != ']' && j + 1 < sql.Length && sql[j + 1] == close) { j += 2; continue; }
                        break;
                    }
                    j++;
                }
                int end = Math.Min(j + 1, sql.Length);
                sb.Append(sql, i, end - i);
                i = end;
                continue;
            }
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                int j = sql.IndexOf('\n', i);
                int end = j < 0 ? sql.Length : j;
                sb.Append(sql, i, end - i);
                i = end;
                continue;
            }
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                int j = sql.IndexOf("*/", i + 2, StringComparison.Ordinal);
                int end = j < 0 ? sql.Length : j + 2;
                sb.Append(sql, i, end - i);
                i = end;
                continue;
            }
            if (c == '?')
            {
                if (i + 1 < sql.Length && char.IsAsciiDigit(sql[i + 1]))
                {
                    // ?NNN: keep it as written.
                    int j = i + 1;
                    while (j < sql.Length && char.IsAsciiDigit(sql[j])) j++;
                    count = Math.Max(count, int.Parse(sql.AsSpan(i + 1, j - i - 1)));
                    sb.Append(sql, i, j - i);
                    i = j;
                    continue;
                }
                count++;
                sb.Append('?').Append(count);
                i++;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    SqliteCommand Command(string sql, IReadOnlyList<object> args)
    {
        if (!IsOpen) throw new DbError("Cannot operate on a closed database.");
        args ??= Array.Empty<object>();
        var text = NumberPlaceholders(sql, out int count);
        if (count != args.Count)
            throw new DbError($"Incorrect number of bindings supplied. The current statement uses {count}, and there are {args.Count} supplied.");
        var cmd = Conn.CreateCommand();
        cmd.CommandText = text;
        for (int i = 0; i < args.Count; i++)
            cmd.Parameters.Add(new SqliteParameter("?" + (i + 1), ToDb(args[i])));
        return cmd;
    }

    static object ToDb(object v) => v switch
    {
        null => DBNull.Value,
        bool b => b ? 1L : 0L,
        int i => (long)i,
        _ => v,
    };

    static object FromDb(object v) => v is DBNull ? null : v;

    void ImplicitBegin(string sql)
    {
        if (!InTransaction && Dml.IsMatch(sql)) Raw("BEGIN");
    }

    void Raw(string sql)
    {
        using var cmd = Conn.CreateCommand();
        cmd.CommandText = sql;
        try { cmd.ExecuteNonQuery(); }
        catch (SqliteException exc) { throw DbError.From(exc); }
    }

    /// <summary>Run one statement and return every row it gives.</summary>
    public List<DbRow> Query(string sql, params object[] args) => QueryList(sql, args);

    public List<DbRow> QueryList(string sql, IReadOnlyList<object> args)
    {
        ImplicitBegin(sql);
        using var cmd = Command(sql, args);
        try
        {
            using var r = cmd.ExecuteReader();
            var cols = Enumerable.Range(0, r.FieldCount).Select(r.GetName).ToArray();
            var rows = new List<DbRow>();
            while (r.Read())
            {
                var vals = new object[r.FieldCount];
                for (int i = 0; i < vals.Length; i++) vals[i] = FromDb(r.GetValue(i));
                rows.Add(new DbRow(cols, vals));
            }
            return rows;
        }
        catch (SqliteException exc) { throw DbError.From(exc); }
    }

    /// <summary>Column names and rows of a query (cursor.description and fetchall()).</summary>
    public (List<string> Cols, List<object[]> Rows) QueryTable(string sql, IReadOnlyList<object> args = null)
    {
        ImplicitBegin(sql);
        using var cmd = Command(sql, args);
        try
        {
            using var r = cmd.ExecuteReader();
            var cols = Enumerable.Range(0, r.FieldCount).Select(r.GetName).ToList();
            var rows = new List<object[]>();
            while (r.Read())
            {
                var vals = new object[r.FieldCount];
                for (int i = 0; i < vals.Length; i++) vals[i] = FromDb(r.GetValue(i));
                rows.Add(vals);
            }
            return (cols, rows);
        }
        catch (SqliteException exc) { throw DbError.From(exc); }
    }

    public DbRow One(string sql, params object[] args) => Query(sql, args).FirstOrDefault();

    public object Scalar(string sql, params object[] args) => One(sql, args)?[0];

    /// <summary>Run a statement; returns the rows it changed (cursor.rowcount).</summary>
    public int Execute(string sql, params object[] args)
    {
        ImplicitBegin(sql);
        using var cmd = Command(sql, args);
        try { return cmd.ExecuteNonQuery(); }
        catch (SqliteException exc) { throw DbError.From(exc); }
    }

    public long LastInsertRowId => SQLitePCL.raw.sqlite3_last_insert_rowid(Conn.Handle);

    /// <summary>executescript: commits first, then runs every statement.</summary>
    public void ExecuteScript(string sql)
    {
        Commit();
        Raw(sql);
    }

    public void Commit()
    {
        if (IsOpen && InTransaction) Raw("COMMIT");
    }

    public void Rollback()
    {
        if (IsOpen && InTransaction) Raw("ROLLBACK");
    }

    public void Close()
    {
        if (!IsOpen) return;
        IsOpen = false;
        try { if (InTransaction) Raw("ROLLBACK"); } catch (DbError) { }
        Conn.Dispose();
    }

    public void Dispose() => Close();
}
