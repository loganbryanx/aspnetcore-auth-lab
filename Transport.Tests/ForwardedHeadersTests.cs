using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace Transport.Tests;

// Helper record for /whoami-network responses.
internal sealed record WhoAmI(string? RemoteIp, string Scheme, string Host, bool IsHttps);

public class ForwardedHeadersTests
{
    private static async Task<JsonElement> WhoAmIAsync(HttpClient c, params (string Name, string Value)[] headers)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/whoami-network");
        foreach (var h in headers) req.Headers.TryAddWithoutValidation(h.Name, h.Value);
        var r = await c.SendAsync(req);
        r.EnsureSuccessStatusCode();
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    // ---- Default config + loopback request: the dev-time trap ----

    [Fact] // FH-E01 -- in dev/test, headers ARE honored because loopback is a known proxy.
    public async Task LoopbackDefault_honors_spoofed_X_Forwarded_For()
    {
        using var f = new LoopbackDefaultFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c, ("X-Forwarded-For", "1.2.3.4"));

        Assert.Equal("1.2.3.4", who.GetProperty("remoteIp").GetString());
        // ^ This is the trap: dev sees headers working, ships, prod is configured differently,
        // dev "fixes" it by clearing the known-proxy lists -> introduces FH-V02 below.
    }

    // ---- Default config + non-loopback (public) source: defense works ----

    [Fact] // FH-V01 -- the framework's default protection: untrusted source's headers are IGNORED.
    public async Task PublicDefault_ignores_spoofed_X_Forwarded_For()
    {
        using var f = new PublicDefaultFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c, ("X-Forwarded-For", "1.2.3.4"));

        Assert.Equal("8.8.8.8", who.GetProperty("remoteIp").GetString());
    }

    // ---- TrustAll: the "I cleared KnownProxies to make it work" anti-pattern ----

    [Fact] // FH-V02 -- once known-proxy lists are cleared, anyone can spoof RemoteIpAddress.
    public async Task PublicTrustAll_honors_spoofed_X_Forwarded_For()
    {
        using var f = new PublicTrustAllFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c, ("X-Forwarded-For", "1.2.3.4"));

        Assert.Equal("1.2.3.4", who.GetProperty("remoteIp").GetString());
    }

    [Fact] // FH-V03 -- the IDOR-style chain: /internal-only checks IsLoopback(remoteIp).
    // Spoofing X-Forwarded-For: 127.0.0.1 bypasses the allowlist.
    public async Task PublicTrustAll_spoofed_loopback_bypasses_IP_allowlist()
    {
        using var f = new PublicTrustAllFactory();
        var c = f.CreateClient();

        // Without the spoof, allowlist correctly rejects 8.8.8.8.
        var direct = await c.GetAsync("/internal-only");
        Assert.Equal(HttpStatusCode.Forbidden, direct.StatusCode);

        // With the spoof, allowlist is bypassed.
        var req = new HttpRequestMessage(HttpMethod.Get, "/internal-only");
        req.Headers.TryAddWithoutValidation("X-Forwarded-For", "127.0.0.1");
        var spoofed = await c.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, spoofed.StatusCode);
    }

    [Fact] // FH-V04 -- spoofing scheme. Cookies marked Secure, https-only redirects, OAuth
    // callback validation -- anything that branches on Request.IsHttps is now controllable.
    public async Task PublicTrustAll_honors_spoofed_X_Forwarded_Proto()
    {
        using var f = new PublicTrustAllFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c, ("X-Forwarded-Proto", "https"));

        Assert.Equal("https", who.GetProperty("scheme").GetString());
        Assert.True(who.GetProperty("isHttps").GetBoolean());
    }

    [Fact] // FH-V05 -- spoofing host. Affects link generation, cookie scope, password-reset
    // emails, anything that uses Request.Host to build URLs.
    public async Task PublicTrustAll_honors_spoofed_X_Forwarded_Host()
    {
        using var f = new PublicTrustAllFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c, ("X-Forwarded-Host", "evil.example"));

        Assert.Equal("evil.example", who.GetProperty("host").GetString());
    }

    [Fact] // FH-V06 -- chained XFF values. RFC says left-most is the original client; ASP.NET's
    // ForwardedHeadersMiddleware walks RIGHT-to-LEFT and applies the *last* value as RemoteIp,
    // *if* each upstream IP is a known proxy. With TrustAll (no proxy validation), only ForwardLimit
    // gates how many hops are honored. ForwardLimit = null means all hops are walked.
    public async Task PublicTrustAll_chained_XForwardedFor_takes_rightmost_within_ForwardLimit()
    {
        using var f = new PublicTrustAllFactory();
        var c = f.CreateClient();
        // "10.0.0.5, 192.168.1.1, 127.0.0.1" -- a chain like "client, edge, lb"
        var who = await WhoAmIAsync(c, ("X-Forwarded-For", "10.0.0.5, 192.168.1.1, 127.0.0.1"));

        var observed = who.GetProperty("remoteIp").GetString();
        // Documented behavior: with no ForwardLimit, the leftmost (original client) is honored.
        Assert.Equal("10.0.0.5", observed);
    }

    // ---- Mode = Off ----

    [Fact] // FH-OFF01 -- if the middleware isn't registered, headers never apply.
    public async Task PublicOff_ignores_all_spoofed_headers()
    {
        using var f = new PublicOffFactory();
        var c = f.CreateClient();
        var who = await WhoAmIAsync(c,
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "evil.example"));

        Assert.Equal("8.8.8.8", who.GetProperty("remoteIp").GetString());
        Assert.NotEqual("https", who.GetProperty("scheme").GetString());
        Assert.NotEqual("evil.example", who.GetProperty("host").GetString());
    }
}
