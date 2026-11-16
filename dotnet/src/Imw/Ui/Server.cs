using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Imw.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;

namespace Imw.Ui;

/// <summary>
/// The local web server for the Workbench (port of make_handler / serve in imw/ui/server.py).
///
/// Security model
///   * Listens on 127.0.0.1 only, over HTTPS with a self-signed certificate made for this computer
///     (Tls.cs); the Host and Origin headers must match.
///   * The start-up link carries a one-time token that is exchanged for an HttpOnly, SameSite=Strict
///     session cookie. Changes also need a custom request header (X-IMW: 1).
///   * Nothing is shown until the Windows user who started the tool signs in with their password
///     (checked by Windows; Auth.cs). After 10 minutes without activity, or with Lock session, the page
///     locks again and needs the password.
///   * Connections from processes of other Windows users are refused.
///   * No API returns a secret value. The page's script is served as /app.js and /theme.js; the
///     Content-Security-Policy allows no inline script.
/// </summary>
public sealed class UiHandler
{
    const string Csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
                       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    const long MaxBody = 10_000_000;

    // The only files served besides index.html (a fixed list: no path from the request reaches the disk).
    static readonly Dictionary<string, string> StaticScripts = new(StringComparer.Ordinal)
    {
        ["/app.js"] = "static/app.js", ["/theme.js"] = "static/theme.js",
    };
    static readonly Dictionary<string, byte[]> Embedded = new(StringComparer.Ordinal);

    readonly UiApp _app;
    readonly int _port;
    readonly string _scheme;
    readonly HashSet<string> _hosts, _origins;
    readonly string _secure;
    readonly Dictionary<(string, string), Func<JObj, object>> _routes, _open;

    public UiHandler(UiApp app, int port, string scheme = "https")
    {
        _app = app;
        _port = port;
        _scheme = scheme;
        _hosts = new HashSet<string>(StringComparer.Ordinal) { $"127.0.0.1:{port}", $"localhost:{port}" };
        _origins = _hosts.Select(h => $"{scheme}://{h}").ToHashSet(StringComparer.Ordinal);
        _secure = scheme == "https" ? "; Secure" : "";
        _routes = app.Routes();
        _open = app.OpenRoutes();
    }

    public static byte[] Resource(string name)
    {
        lock (Embedded)
        {
            if (Embedded.TryGetValue(name, out var b)) return b;
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
                          ?? throw new FileNotFoundException($"missing built-in file {name}");
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return Embedded[name] = ms.ToArray();
        }
    }

    static async Task Send(HttpContext ctx, int status, object body, string ctype = "application/json",
                           IEnumerable<(string, string)> headers = null)
    {
        var data = body as byte[] ?? Encoding.UTF8.GetBytes(Json.Dumps(body));
        var r = ctx.Response;
        r.StatusCode = status;
        var h = r.Headers;
        h["Server"] = "IMW";
        h.ContentType = ctype;
        h.ContentLength = data.Length;
        h.CacheControl = "no-store";
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h.ContentSecurityPolicy = Csp;
        foreach (var (k, v) in headers ?? Array.Empty<(string, string)>()) h[k] = v;
        await r.Body.WriteAsync(data);
    }

    static Task SendError(HttpContext ctx, int status, string error) => Send(ctx, status, Json.O(("error", error)));

    static string Cookie(HttpContext ctx)
    {
        foreach (var part in ctx.Request.Headers.Cookie.ToString().Split(';'))
        {
            var p = Py.Strip(part);
            int eq = p.IndexOf('=');
            var (k, v) = eq < 0 ? (p, "") : (p.Substring(0, eq), p.Substring(eq + 1));
            if (k == "imw_sid") return v;
        }
        return null;
    }

    static string Header(HttpContext ctx, string name) =>
        ctx.Request.Headers.TryGetValue(name, out var v) && v.Count > 0 ? v.ToString() : null;

    string Guard(HttpContext ctx, bool mutating)
    {
        var host = Header(ctx, "Host");
        if (host == null || !_hosts.Contains(host)) return "bad host";
        var origin = Header(ctx, "Origin");
        if (!string.IsNullOrEmpty(origin) && !_origins.Contains(origin)) return "bad origin";
        if (mutating && Header(ctx, "X-IMW") != "1") return "missing header";
        return null;
    }

    static bool Same(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    /// <summary>The browser holds this run's session cookie (locked or not).</summary>
    bool SessionOk(HttpContext ctx)
    {
        lock (_app.Lock)
        {
            var sid = Cookie(ctx);
            return !string.IsNullOrEmpty(_app.Sid) && !string.IsNullOrEmpty(sid) && Same(sid, _app.Sid);
        }
    }

    bool IsUnlocked(bool touch = true)
    {
        lock (_app.Lock)
        {
            if (_app.Unlocked && UiApp.Now() - _app.LastSeen > UiApp.IdleSeconds)
            {
                _app.Unlocked = false;
                _app.AuditIfDb("lock", Json.O(("reason", "idle")));
            }
            if (_app.Unlocked && touch) _app.LastSeen = UiApp.Now();
            return _app.Unlocked;
        }
    }

    /// <summary>The browser connecting must run as the Workbench's Windows user (checked once per connection).</summary>
    bool PeerOk(HttpContext ctx)
    {
        var items = ctx.Features.Get<IConnectionItemsFeature>()?.Items;
        if (items != null && items.TryGetValue("imw_peer", out var known)) return (bool)known;
        bool ok;
        try
        {
            var c = ctx.Connection;
            var ip = c.RemoteIpAddress is { IsIPv4MappedToIPv6: true } m ? m.MapToIPv4() : c.RemoteIpAddress;
            ok = _app.PeerCheck(ip?.ToString() ?? "", c.RemotePort, _port, _app.Owner_.Sid);
        }
        catch (Exception exc)      // can't confirm: refuse
        {
            Log.Warning($"could not check who is connecting: {exc.Message}");
            ok = false;
        }
        if (items != null) items["imw_peer"] = ok;
        return ok;
    }

    static string HtmlEscape(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#x27;");

    /// <summary>parse_qs(query).get(name, [""])[0]</summary>
    static string QueryValue(string query, string name)
    {
        foreach (var part in query.Split('&', ';'))
        {
            if (part.Length == 0) continue;
            int eq = part.IndexOf('=');
            if (eq < 0) continue;
            string Dec(string x) => Uri.UnescapeDataString(x.Replace('+', ' '));
            var v = Dec(part.Substring(eq + 1));
            if (Dec(part.Substring(0, eq)) == name && v.Length > 0) return v;
        }
        return "";
    }

    static string PyTypeName(object v) => v switch
    {
        null => "NoneType", List<object> => "list", string => "str", long or int => "int", double => "float", bool => "bool", _ => "object",
    };

    public async Task Handle(HttpContext ctx)
    {
        var method = ctx.Request.Method;
        if (method != "GET" && method != "POST")
        {
            await Send(ctx, 501, Encoding.UTF8.GetBytes($"Unsupported method ({method})"), "text/plain");
            return;
        }
        var raw = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget ?? (ctx.Request.Path + ctx.Request.QueryString);
        int hash = raw.IndexOf('#');
        if (hash >= 0) raw = raw.Substring(0, hash);
        int q = raw.IndexOf('?');
        var path = q >= 0 ? raw.Substring(0, q) : raw;
        var query = q >= 0 ? raw.Substring(q + 1) : "";

        if (!PeerOk(ctx))
        {
            lock (_app.Lock) _app.AuditIfDb("refused_connection", Json.O(("reason", "another Windows user")));
            await Send(ctx, 403, Encoding.UTF8.GetBytes($"<p>This Workbench belongs to {HtmlEscape(_app.Owner_.Display)}. " +
                                                       "Connections from other Windows users are refused.</p>"), "text/html; charset=utf-8");
            return;
        }
        var problem = Guard(ctx, method == "POST");
        if (problem != null)
        {
            await SendError(ctx, 403, problem);
            return;
        }
        if (method == "GET" && path == "/")
        {
            var token = QueryValue(query, "t");
            string cookie = null;
            lock (_app.Lock)
            {
                if (token.Length > 0 && !string.IsNullOrEmpty(_app.LaunchToken) && Same(token, _app.LaunchToken))
                {
                    _app.LaunchToken = null;
                    _app.Sid = UiApp.NewToken();
                    _app.Unlocked = false;
                    cookie = $"imw_sid={_app.Sid}; HttpOnly; SameSite=Strict; Path=/{_secure}";
                }
            }
            if (cookie != null)
            {
                await Send(ctx, 303, Array.Empty<byte>(), "text/plain", new[] { ("Location", "/"), ("Set-Cookie", cookie) });
                return;
            }
            if (!SessionOk(ctx))
            {
                await Send(ctx, 401, Encoding.UTF8.GetBytes("<p>Session ended or not started. Close this tab and run " +
                                                           "<code>IMW ui</code> again to get a new link.</p>"), "text/html; charset=utf-8");
                return;
            }
            await Send(ctx, 200, Resource("static/index.html"), "text/html; charset=utf-8");
            return;
        }
        if (method == "GET" && StaticScripts.TryGetValue(path, out var script))
        {
            if (!SessionOk(ctx))
            {
                await Send(ctx, 401, Array.Empty<byte>(), "text/plain");
                return;
            }
            await Send(ctx, 200, Resource(script), "text/javascript; charset=utf-8");
            return;
        }
        if (!path.StartsWith("/api/", StringComparison.Ordinal))
        {
            await SendError(ctx, 404, "not found");
            return;
        }
        if (!SessionOk(ctx))
        {
            await SendError(ctx, 401, "Session ended. Restart the UI.");
            return;
        }
        if (path.StartsWith("/api/export/", StringComparison.Ordinal) && method == "GET")
        {
            if (!IsUnlocked())
            {
                await SendError(ctx, 423, "locked");
                return;
            }
            var what = path.Substring(path.LastIndexOf('/') + 1).Replace(".csv", "");
            if (what is not ("audit" or "edits" or "convention"))
            {
                await SendError(ctx, 404, "not found");
                return;
            }
            string text;
            try
            {
                lock (_app.Lock) text = _app.ExportCsv(what);
            }
            catch (UiError exc)
            {
                await SendError(ctx, exc.Status, exc.Message);
                return;
            }
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var file = $"imw_{(what == "convention" ? "safe_naming_convention" : what)}_{stamp}.csv";
            await Send(ctx, 200, Encoding.UTF8.GetBytes(text), "text/csv; charset=utf-8",
                       new[] { ("Content-Disposition", $"attachment; filename=\"{file}\"") });
            return;
        }
        if (_open.TryGetValue((method, path), out var fn))
            IsUnlocked(touch: false);                 // applies the idle lock before answering
        else
        {
            if (!_routes.TryGetValue((method, path), out fn))
            {
                await SendError(ctx, 404, "not found");
                return;
            }
            if (!IsUnlocked())
            {
                await SendError(ctx, 423, "locked");
                return;
            }
        }
        object body = new JObj();
        if (method == "POST")
        {
            long length = ctx.Request.ContentLength ?? 0;
            if (length > MaxBody)
            {
                await SendError(ctx, 413, "too large");
                return;
            }
            var buf = new byte[length];
            int got = 0;
            while (got < length)
            {
                int n = await ctx.Request.Body.ReadAsync(buf.AsMemory(got, (int)length - got));
                if (n == 0) break;
                got += n;
            }
            try
            {
                var span = buf.AsSpan(0, got);
                if (span.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) span = span.Slice(3);
                var text = span.Length == 0 ? "{}" : new UTF8Encoding(false, true).GetString(span);
                body = Json.Parse(text);
            }
            catch (Exception exc) when (exc is ValueError or DecoderFallbackException)
            {
                await SendError(ctx, 400, "bad JSON");
                return;
            }
        }
        try
        {
            if (body is not JObj obj)
            {
                if (!UiApp.BodyFree.Contains(path))
                    throw new InvalidOperationException($"'{PyTypeName(body)}' object has no attribute 'get'");
                obj = new JObj();
            }
            object result;
            lock (_app.Lock) result = fn(obj);
            await Send(ctx, 200, result);
        }
        catch (UiError exc)
        {
            await SendError(ctx, exc.Status, exc.Message);
        }
        catch (Exception exc)
        {
            Log.Error($"request failed: {exc}");
            await SendError(ctx, 500, $"Unexpected error: {exc.Message}");
        }
    }
}

public static class UiServer
{
    /// <summary>Run the Workbench until Ctrl+C or End session. Returns the exit code.</summary>
    public static int Serve(string workspace, int port = 0, bool openBrowser = true, string protectorFlag = null,
                            IAuthenticator authenticator = null, bool useTls = true, bool newCert = false, bool trustCert = false,
                            Action<string, UiApp> ready = null)
    {
        var app = new UiApp(workspace, protectorFlag, authenticator);
        var scheme = useTls ? "https" : "http";
        X509Certificate2 cert = null;
        string certNote = null;
        if (useTls)
        {
            (cert, var certPath, var created) = Tls.ServerCertificate(app.Ws, newCert);
            if (trustCert)
            {
                Tls.TrustCertificate(certPath);
                Console.WriteLine("Certificate added to your Windows user's Trusted Root store.");
            }
            certNote = $"HTTPS certificate: {certPath} ({(created ? "new" : "existing")}), SHA-256 {Tls.Fingerprint(certPath)}";
        }

        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore();
        if (useTls) builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.AddServerHeader = false;
            o.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);   // an idle browser connection does not stay forever
            o.Listen(IPAddress.Loopback, port, lo =>
            {
                lo.Protocols = HttpProtocols.Http1;
                if (cert != null) lo.UseHttps(cert);
            });
        });
        var web = builder.Build();
        UiHandler handler = null;
        web.Run(ctx => handler.Handle(ctx));
        web.Start();
        var actual = new Uri(web.Urls.First()).Port;
        handler = new UiHandler(app, actual, scheme);
        app.Shutdown = () => web.StopAsync().GetAwaiter().GetResult();

        var url = $"{scheme}://127.0.0.1:{actual}/?t={app.LaunchToken}";
        Console.WriteLine($"{UiApp.Product} running. Workspace: {app.Ws}");
        Console.WriteLine($"Put export files in: {app.Inbox}");
        if (certNote != null)
        {
            Console.WriteLine(certNote);
            if (!trustCert)
                Console.WriteLine("The browser warns once about this self-signed certificate: choose Advanced, then " +
                                  "Continue. To stop the warning, start once with --trust-cert.");
        }
        else Console.WriteLine("WARNING: plain HTTP (--no-tls). Use only for troubleshooting.");
        Console.WriteLine($"Open this link (works once): {url}");
        Console.WriteLine($"Sign in as {app.Auth.Display}. Press Ctrl+C to stop.");
        Console.Out.Flush();
        ready?.Invoke(url, app);
        if (openBrowser) _ = Task.Delay(500).ContinueWith(_ => OpenBrowser(url));
        web.WaitForShutdown();
        return 0;
    }

    static void OpenBrowser(string url)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
                return;
            }
            var tool = OperatingSystem.IsMacOS() ? "open" : "xdg-open";
            if (UiApp.Which(tool) == null) return;
            var psi = new System.Diagnostics.ProcessStartInfo(tool) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            psi.ArgumentList.Add(url);
            System.Diagnostics.Process.Start(psi)?.Dispose();
        }
        catch (Exception) { }     // the link is printed; the user can open it by hand
    }

    /// <summary>The ui command (port of cmd_ui).</summary>
    public static int Command(Args a)
    {
        var flag = a.B("no_secrets") ? "none" : a.B("insecure_plaintext_secrets") ? "plain" : null;
        IAuthenticator auth;
        try { auth = Auth.Get(); }
        catch (AuthError exc)
        {
            Console.Error.WriteLine($"ERROR: {exc.Message}");
            return 2;
        }
        var ws = a.S("workspace");
        // Workspaces made before the rename are called pam2pc_workspace: keep using one if it is there.
        if (ws == "imw_workspace" && !Directory.Exists("imw_workspace") && !File.Exists("imw_workspace") && Directory.Exists("pam2pc_workspace"))
        {
            Console.WriteLine("Using the existing workspace pam2pc_workspace (from before the rename). " +
                              "Rename the folder to imw_workspace, or pass -w, to change this.");
            ws = "pam2pc_workspace";
        }
        try
        {
            return Serve(ws, a.I("port"), !a.B("no_browser"), flag, auth, !a.B("no_tls"), a.B("new_cert"), a.B("trust_cert"));
        }
        catch (Exception exc) when (exc is TlsError or OwnerError or StoreError)
        {
            Console.Error.WriteLine($"ERROR: {exc.Message}");
            return 2;
        }
    }
}
