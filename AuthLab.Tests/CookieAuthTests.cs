using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AuthLab.Tests;

public class CookieAuthTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public CookieAuthTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private HttpClient NewClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    [Fact] // C-E02
    public async Task Missing_cookie_redirects_to_login_path()
    {
        var c = NewClient();
        var r = await c.GetAsync("/cookie/secure");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Contains("/cookie/login", r.Headers.Location!.ToString());
    }

    [Fact] // C-E01
    public async Task Login_then_access_succeeds()
    {
        var c = NewClient();
        var login = await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = (string?)null });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var r = await c.GetAsync("/cookie/secure");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // C-V01: open-redirect finding (intentional in this lab)
    public async Task Login_redirect_does_not_validate_returnUrl()
    {
        var c = NewClient();
        var r = await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = "https://evil.example/" });

        // The intentional bug: redirect goes through unchanged.
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("https://evil.example/", r.Headers.Location!.ToString());
    }

    [Fact] // C-V02
    public async Task Auth_cookie_has_HttpOnly_and_SameSite_attributes()
    {
        var c = NewClient();
        var r = await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = (string?)null });

        var setCookie = r.Headers.GetValues("Set-Cookie")
            .Single(s => s.StartsWith("AuthLab.Auth=", StringComparison.Ordinal));

        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact] // C-F01
    public async Task Tampered_cookie_is_treated_as_unauthenticated()
    {
        var c = NewClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/cookie/secure");
        req.Headers.Add("Cookie", "AuthLab.Auth=NOT_A_REAL_TICKET");
        var r = await c.SendAsync(req);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
    }

    [Fact] // C-V03: post-login cookie value differs from any pre-existing one
    public async Task Login_rotates_the_auth_cookie_value()
    {
        var c = NewClient();
        var first = await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = (string?)null });
        var firstSet = first.Headers.GetValues("Set-Cookie")
            .Single(s => s.StartsWith("AuthLab.Auth=", StringComparison.Ordinal));

        var second = await c.PostAsJsonAsync("/cookie/login",
            new { user = "bob", role = (string?)null, returnUrl = (string?)null });
        var secondSet = second.Headers.GetValues("Set-Cookie")
            .Single(s => s.StartsWith("AuthLab.Auth=", StringComparison.Ordinal));

        Assert.NotEqual(firstSet, secondSet);
    }

    [Fact] // C-V04: state-changing endpoint has no antiforgery -- CSRF finding
    public async Task Transfer_endpoint_lacks_antiforgery_protection()
    {
        var c = NewClient();
        await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = (string?)null });

        // Cross-origin POST mimicry: no token, no Origin/Referer check, succeeds.
        var r = await c.PostAsync("/cookie/transfer?amount=100&to=bob", content: null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // C-LOGOUT
    public async Task Logout_clears_auth_cookie()
    {
        var c = NewClient();
        await c.PostAsJsonAsync("/cookie/login",
            new { user = "alice", role = (string?)null, returnUrl = (string?)null });

        var r = await c.PostAsync("/cookie/logout", content: null);
        var setCookies = r.Headers.GetValues("Set-Cookie")
            .Where(s => s.StartsWith("AuthLab.Auth=", StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(setCookies);
        Assert.Contains(setCookies, s => s.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }
}
