using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AuthLab.Tests;

// One [Fact] per row in the JWT test matrix.
// E = expected behavior, F = failure path, V = vulnerability check.
public class JwtAuthTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public JwtAuthTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    private static HttpRequestMessage Get(string url, string? bearer = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (bearer is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return req;
    }

    // ---- Expected ----

    [Fact] // JWT-E02
    public async Task Public_endpoint_is_anonymous()
    {
        var r = await _client.SendAsync(Get("/public"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // JWT-E03
    public async Task Missing_token_returns_401_with_bearer_challenge()
    {
        var r = await _client.SendAsync(Get("/secure"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Contains(r.Headers.WwwAuthenticate, h => h.Scheme == "Bearer");
    }

    [Fact] // JWT-E01
    public async Task Valid_token_succeeds()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.Valid()));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // JWT-E04
    public async Task Admin_role_token_reaches_admin_endpoint()
    {
        var r = await _client.SendAsync(Get("/admin", TestTokenFactory.Valid(role: "admin")));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    // ---- Failure ----

    [Fact] // JWT-F07: authenticated but unauthorized => 403, not 401
    public async Task Authenticated_but_wrong_role_returns_403()
    {
        var r = await _client.SendAsync(Get("/admin", TestTokenFactory.Valid(role: "user")));
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact] // JWT-F01
    public async Task Expired_token_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.Expired()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-F02
    public async Task Wrong_issuer_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.WrongIssuer()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-F03
    public async Task Wrong_audience_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.WrongAudience()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-F04
    public async Task Wrong_signing_key_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.WrongKey()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-F05
    public async Task Garbled_token_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", "abc.def.ghi"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-F06
    public async Task Future_nbf_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.FutureNotBefore()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    // ---- Vulnerability ----

    [Fact] // JWT-V01: alg:none must always be rejected
    public async Task AlgNone_token_rejected()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.AlgNone()));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-V03: documents the framework's default 5-min ClockSkew behavior
    public async Task Token_expired_one_minute_ago_is_still_accepted_due_to_default_clockskew()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.SlightlyExpired()));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // JWT-V04: token in query string is not accepted by default
    public async Task Token_in_query_string_is_not_accepted_by_default()
    {
        var t = TestTokenFactory.Valid();
        var r = await _client.SendAsync(Get($"/secure?access_token={t}"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // JWT-V05: bearer prefix is case-insensitive (RFC 6750)
    public async Task Bearer_prefix_is_case_insensitive()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/secure");
        req.Headers.TryAddWithoutValidation(
            "Authorization", "bearer " + TestTokenFactory.Valid());
        var r = await _client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // JWT-V07: documents what /secure returns for distinct failure reasons.
    // Surfacing distinct error_descriptions can be an info-disclosure issue --
    // confirm whether your contract allows it.
    public async Task Failure_reasons_are_distinguishable_in_WWWAuthenticate()
    {
        var expired = await _client.SendAsync(Get("/secure", TestTokenFactory.Expired()));
        var wrongIss = await _client.SendAsync(Get("/secure", TestTokenFactory.WrongIssuer()));

        var e = expired.Headers.WwwAuthenticate.ToString();
        var i = wrongIss.Headers.WwwAuthenticate.ToString();

        Assert.NotEqual(e, i); // change the JwtBearer config to make these identical
    }
}
