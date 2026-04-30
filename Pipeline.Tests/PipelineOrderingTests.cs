using System.Net;
using Xunit;
using Xunit.Abstractions;

namespace Pipeline.Tests;

// MO = Middleware Ordering / auto-injection. Each test asserts the actual behavior
// of [Authorize] under a different services-registration scenario.
//
// HEADLINE FINDING: WebApplicationBuilder.Build() auto-injects UseAuthentication
// and UseAuthorization when their services are registered, even if the user code
// never calls those middleware methods explicitly. The historical "I forgot to
// call UseAuthorization()" footgun is mitigated for apps using WebApplication.
public class PipelineOrderingTests
{
    private readonly ITestOutputHelper _out;
    public PipelineOrderingTests(ITestOutputHelper output) => _out = output;

    private static HttpRequestMessage WithUser(string url, string? user = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (user is not null) req.Headers.Add("X-Test-User", user);
        return req;
    }

    // ---- Standard pipeline: auto-injection works as the framework promises ----

    [Fact] // MO-E01
    public async Task Standard_anonymous_protected_returns_401_via_auto_injected_middleware()
    {
        using var f = new StandardFactory();
        var c = f.CreateClient();
        var r = await c.SendAsync(WithUser("/protected"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // MO-E02
    public async Task Standard_authenticated_protected_returns_200()
    {
        using var f = new StandardFactory();
        var c = f.CreateClient();
        var r = await c.SendAsync(WithUser("/protected", user: "alice"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // MO-E03 -- public endpoint always works
    public async Task Standard_public_returns_200_anonymous()
    {
        using var f = new StandardFactory();
        var c = f.CreateClient();
        var r = await c.GetAsync("/public");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    // ---- No authentication services: UseAuthentication auto-injection skipped ----

    [Fact] // MO-V01: AddAuthorization called, AddAuthentication is not. Auto-injection
    // adds UseAuthorization. AuthorizationMiddleware needs IAuthenticationService to
    // authenticate the default scheme; that service isn't registered (no
    // AddAuthentication). The framework throws a clear InvalidOperationException at
    // request time pointing the developer at AddAuthentication.
    public async Task NoAuthenticationService_protected_endpoint_throws_with_clear_error()
    {
        using var f = new NoAuthenticationServiceFactory();
        var c = f.CreateClient();
        var r = await c.SendAsync(WithUser("/protected", user: "alice"));

        Assert.Equal(HttpStatusCode.InternalServerError, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync();
        Assert.Contains("AddAuthentication", body);
    }

    // ---- No authorization services: UseAuthorization auto-injection skipped ----

    [Fact] // MO-V02: endpoint has [Authorize] metadata but no UseAuthorization
    // middleware was injected. EndpointMiddleware sees the metadata, sees no
    // marker indicating UseAuthorization ran, and THROWS InvalidOperationException
    // at request time. The handler returns 500.
    public async Task NoAuthorizationService_protected_endpoint_throws_returns_500()
    {
        using var f = new NoAuthorizationServiceFactory();
        var c = f.CreateClient();
        var r = await c.SendAsync(WithUser("/protected"));

        _out.WriteLine($"Status: {(int)r.StatusCode}");
        _out.WriteLine($"Body: {await r.Content.ReadAsStringAsync()}");

        Assert.Equal(HttpStatusCode.InternalServerError, r.StatusCode);
    }

    [Fact] // MO-V03 -- public endpoint without [Authorize] still works under broken pipeline
    public async Task NoAuthorizationService_public_endpoint_still_works()
    {
        using var f = new NoAuthorizationServiceFactory();
        var c = f.CreateClient();
        var r = await c.GetAsync("/public");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }
}
