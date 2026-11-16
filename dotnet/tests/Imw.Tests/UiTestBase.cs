using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Imw.Ui;

namespace Imw.Tests;

/// <summary>A Workbench web server in this process, driven over HTTPS like the browser does
/// (port of the UiServer base class in tests/test_ui.py).</summary>
public abstract class UiTestBase : TestBase
{
    public const string Password = "correct horse";
    static readonly Lazy<string> SharedCert = new(() =>
    {
        // One certificate for the whole test run (making one takes a moment).
        var dir = Path.Combine(Path.GetTempPath(), "imw-cert-" + Guid.NewGuid().ToString("N")[..8]);
        Tls.EnsureCertificate(dir);
        return Path.Combine(dir, "tls");
    });

    protected readonly string Ws;
    protected UiApp App;
    protected int Port;
    protected string Token;
    protected string Cookie;
    protected bool Ended;
    readonly Thread _thread;
    readonly X509Certificate2 _root;

    protected virtual IEnumerable<string> InboxFiles => new[] { "delinea_export.csv", "delinea_permissions.csv", "keepass_export.xml" };

    protected UiTestBase()
    {
        Ws = T("ws");
        Directory.CreateDirectory(Path.Combine(Ws, "inbox"));
        var tls = Path.Combine(Ws, "tls");
        Directory.CreateDirectory(tls);
        foreach (var f in Directory.GetFiles(SharedCert.Value)) File.Copy(f, Path.Combine(tls, Path.GetFileName(f)));
        foreach (var f in InboxFiles) File.Copy(S(f), Path.Combine(Ws, "inbox", f));
        var started = new ManualResetEventSlim();
        string url = null;
        Exception failed = null;
        _thread = new Thread(() =>
        {
            try
            {
                UiServer.Serve(Ws, 0, false, "plain", new TestAuth(Password), ready: (u, app) =>
                {
                    url = u;
                    App = app;
                    started.Set();
                });
            }
            catch (Exception exc)
            {
                failed = exc;
                started.Set();
            }
        }) { IsBackground = true };
        var old = Console.Out;
        Console.SetOut(TextWriter.Null);                 // the start-up text
        try
        {
            _thread.Start();
            started.Wait(TimeSpan.FromSeconds(30));
        }
        finally { Console.SetOut(old); }
        if (failed != null) throw failed;
        Port = new Uri(url).Port;
        Token = url.Split("t=")[1];
        _root = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(tls, Tls.CertName)));
    }

    public override void Dispose()
    {
        if (!Ended) App?.Shutdown?.Invoke();
        _thread.Join(TimeSpan.FromSeconds(10));
        UiApp.Clock = null;
        Csv.FieldLimit = 64 * 1024 * 1024;
        base.Dispose();
    }

    protected HttpClient Client(string scheme = "https")
    {
        var handler = new SocketsHttpHandler
        {
            UseCookies = false, AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.Zero,
            SslOptions = { RemoteCertificateValidationCallback = (_, cert, _, _) => cert != null && new X509Certificate2(cert).Thumbprint == _root.Thumbprint },
        };
        return new HttpClient(handler) { BaseAddress = new Uri($"{scheme}://127.0.0.1:{Port}"), Timeout = TimeSpan.FromSeconds(60) };
    }

    /// <summary>One request on its own connection (the server checks who connects once per connection).
    /// Returns the status and the JSON answer, or the raw bytes when the answer is not JSON.</summary>
    protected (int Status, object Body, HttpResponseMessage Response) Req(string method, string path, object body = null,
                                                                          Dictionary<string, string> headers = null, string host = null)
    {
        using var client = Client();
        var msg = new HttpRequestMessage(new HttpMethod(method), path);
        msg.Headers.ConnectionClose = true;
        msg.Headers.Host = host ?? $"127.0.0.1:{Port}";
        if (Cookie != null) msg.Headers.Add("Cookie", Cookie);
        if (method == "POST") msg.Headers.Add("X-IMW", "1");
        if (body != null)
        {
            msg.Content = new ByteArrayContent(body as byte[] ?? Encoding.UTF8.GetBytes(body as string ?? Json.Dumps(body)));
            msg.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        foreach (var kv in headers ?? new())
        {
            msg.Headers.Remove(kv.Key);
            msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }
        var r = client.Send(msg);
        var data = r.Content.ReadAsByteArrayAsync().Result;
        if (r.Headers.TryGetValues("Set-Cookie", out var cookies)) Cookie = cookies.First().Split(';')[0];
        object parsed;
        try { parsed = Json.Parse(Encoding.UTF8.GetString(data)); }
        catch (Exception) { parsed = data; }
        return ((int)r.StatusCode, parsed, r);
    }

    protected (int Status, JObj Body) Api(string method, string path, object body = null, Dictionary<string, string> headers = null)
    {
        var (st, b, _) = Req(method, path, body, headers);
        return (st, b as JObj);
    }

    protected (int Status, JObj Body) Post(string path, string json) => Api("POST", path, J(json));
    protected (int Status, JObj Body) Post(string path, JObj body) => Api("POST", path, body);
    protected (int Status, JObj Body) Get(string path) => Api("GET", path);

    protected void Login(bool unlock = true)
    {
        Assert.Equal(303, Req("GET", $"/?t={Token}").Status);
        if (unlock) Assert.Equal(200, Post("/api/unlock", Json.O(("password", Password))).Status);
    }

    protected static List<JObj> Rows(JObj d, string key = "rows") => d.List(key).Cast<JObj>().ToList();
    protected string WsPath(params string[] parts) => Path.Combine(new[] { Ws }.Concat(parts).ToArray());

    protected (int, JObj) IngestSamples(params string[] files) => Post("/api/ingest", Json.O(
        ("files", files.Select(f => (object)Json.O(("name", f), ("source", ""))).ToList()),
        ("permissions", new List<object> { "delinea_permissions.csv" })));
}
