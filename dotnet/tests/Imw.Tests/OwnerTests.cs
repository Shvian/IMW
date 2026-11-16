using Imw.Ui;
using Microsoft.Data.Sqlite;

namespace Imw.Tests;

// Port of tests/test_owner.py: only the Windows user who created a workspace or database can open it.

public class OwnerTests : TestBase
{
    static readonly Identity Ian = new() { Sid = "S-1-5-21-1-1001", Domain = "CORP", User = "ian", Display = "CORP\\ian" };
    static readonly Identity Bob = new() { Sid = "S-1-5-21-1-1002", Domain = "CORP", User = "bob", Display = "CORP\\bob" };

    public OwnerTests()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Windows can't put the made-up SIDs of Ian and Bob on a real folder (icacls refuses unknown accounts),
        // and on an elevated build server new folders belong to Administrators: stand in for both.
        Owner.RunHook = (_, _) => (0, "");
        Owner.PathOwnerHook = _ => Ian.Sid;
    }

    public override void Dispose()
    {
        Owner.RunHook = null;
        Owner.PathOwnerHook = null;
        Owner.IdentityHook = null;
        base.Dispose();
    }

    static T RunAs<T>(Identity who, Func<T> fn)
    {
        Owner.IdentityHook = () => who;
        try { return fn(); }
        finally { Owner.IdentityHook = null; }
    }

    static void RunAs(Identity who, Action fn) => RunAs(who, () => { fn(); return 0; });

    static void Sql(string db, params string[] statements)
    {
        using var con = new SqliteConnection($"Data Source={db};Pooling=False");
        con.Open();
        foreach (var s in statements)
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText = s;
            cmd.ExecuteNonQuery();
        }
    }

    static object SqlScalar(string db, string sql)
    {
        using var con = new SqliteConnection($"Data Source={db};Pooling=False");
        con.Open();
        using var cmd = con.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    static int Mode(string path) => (int)File.GetUnixFileMode(path) & 0x1FF;

    [Fact]
    public void DatabaseOpensOnlyForItsCreator()
    {
        var db = T("m.db");
        RunAs(Ian, () => new Store(db, create: true, protector: "none").Close());
        RunAs(Ian, () => new Store(db).Close());
        var exc = Assert.Throws<StoreError>(() => RunAs(Bob, () => new Store(db)));
        Assert.Contains("belongs to CORP\\ian", exc.Message);
        if (!OperatingSystem.IsWindows()) Assert.Equal(Convert.ToInt32("600", 8), Mode(db));
    }

    [Fact]
    public void OlderDatabaseIsClaimedByItsCreatorOnly()
    {
        var db = T("m.db");
        RunAs(Ian, () => new Store(db, create: true, protector: "none").Close());
        Sql(db, "DELETE FROM meta WHERE key IN ('owner_sid', 'owner_name')",
                "UPDATE meta SET value = 'ian@host' WHERE key = 'created_by'");
        Assert.Throws<StoreError>(() => RunAs(Bob, () => new Store(db)));
        RunAs(Ian, () => new Store(db).Close());            // claims it
        Assert.Throws<StoreError>(() => RunAs(Bob, () => new Store(db)));
        Assert.Equal(Ian.Sid, SqlScalar(db, "SELECT value FROM meta WHERE key='owner_sid'"));
    }

    [Fact]
    public void WorkspaceIsLockedToItsOwner()
    {
        var ws = T("ws");
        RunAs(Ian, () => Owner.ClaimWorkspace(ws));
        Directory.CreateDirectory(Path.Combine(ws, "inbox"));
        File.WriteAllText(Path.Combine(ws, "inbox", "export.csv"), "x");
        RunAs(Ian, () => Owner.ClaimWorkspace(ws));
        var exc = Assert.Throws<OwnerError>(() => RunAs(Bob, () => Owner.ClaimWorkspace(ws)));
        Assert.Contains("belongs to CORP\\ian", exc.Message);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(Convert.ToInt32("700", 8), Mode(ws));
            Assert.Equal(Convert.ToInt32("600", 8), Mode(Path.Combine(ws, "inbox", "export.csv")));
        }
    }

    [Fact]
    public void WorkspaceNeedsAnEmptyOrWorkspaceFolder()
    {
        var ws = T("docs");
        Directory.CreateDirectory(ws);
        File.WriteAllText(Path.Combine(ws, "holiday.jpg"), "x");
        var exc = Assert.Throws<OwnerError>(() => RunAs(Ian, () => Owner.ClaimWorkspace(ws)));
        Assert.Contains("holiday.jpg", exc.Message);
    }

    [Fact]
    public void OldWorkspaceIsClaimedByTheFolderOwnerOnly()
    {
        var ws = T("ws");
        Directory.CreateDirectory(Path.Combine(ws, "inbox"));
        var mine = OperatingSystem.IsWindows() ? Ian
            : new Identity { Sid = Owner.CurrentIdentity().Sid, Domain = Ian.Domain, User = Ian.User, Display = Ian.Display };
        Assert.Throws<OwnerError>(() => RunAs(Bob, () => Owner.ClaimWorkspace(ws)));
        RunAs(mine, () => Owner.ClaimWorkspace(ws));          // on Windows the folder belongs to Ian (see above)
    }

    [Fact]
    public void UiRefusesToStartOnSomeoneElsesWorkspace()
    {
        var ws = T("ws");
        RunAs(Ian, () => Owner.ClaimWorkspace(ws));
        Assert.Throws<OwnerError>(() => RunAs(Bob, () => new UiApp(ws, "plain", new TestAuth("x"))));
    }

    [Fact]
    public void IdentityIsNotTakenFromEnvironment()
    {
        var old = (Environment.GetEnvironmentVariable("USERNAME"), Environment.GetEnvironmentVariable("USERDOMAIN"),
                   Environment.GetEnvironmentVariable("USER"));
        Environment.SetEnvironmentVariable("USERNAME", "someone-else");
        Environment.SetEnvironmentVariable("USERDOMAIN", "EVIL");
        Environment.SetEnvironmentVariable("USER", "someone-else");
        try { Assert.NotEqual("someone-else", Owner.CurrentIdentity().User); }
        finally
        {
            Environment.SetEnvironmentVariable("USERNAME", old.Item1);
            Environment.SetEnvironmentVariable("USERDOMAIN", old.Item2);
            Environment.SetEnvironmentVariable("USER", old.Item3);
        }
    }
}
