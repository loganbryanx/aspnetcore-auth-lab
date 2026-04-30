using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Test fixtures use IWebHostBuilder.UseSetting(...) to flip these flags. UseSetting
// writes into the host's IConfiguration BEFORE user code runs, so reads here pick
// up the test fixture's values.
var addAuthN = bool.Parse(builder.Configuration["Pipeline:AddAuthentication"] ?? "true");
var addAuthZ = bool.Parse(builder.Configuration["Pipeline:AddAuthorization"] ?? "true");

if (addAuthN)
{
    builder.Services
        .AddAuthentication("Test")
        .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
}

if (addAuthZ)
{
    builder.Services.AddAuthorization();
}

var app = builder.Build();

// CRITICAL OBSERVATION FOR THIS LAB: the user code does NOT call
// app.UseAuthentication() or app.UseAuthorization() explicitly. In modern .NET,
// WebApplicationBuilder.Build() auto-injects both middlewares when their
// corresponding services are registered. The historical footgun (forgetting
// these calls and silently bypassing [Authorize]) is mitigated for apps using
// the WebApplication pattern.

app.MapGet("/public", () => Results.Ok(new { msg = "anyone" }));

app.MapGet("/protected", (ClaimsPrincipal u) =>
        Results.Ok(new
        {
            user = u.Identity?.Name,
            isAuth = u.Identity?.IsAuthenticated ?? false
        }))
    .RequireAuthorization();

app.Run();

public partial class Program;

internal sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var user = Request.Headers["X-Test-User"].FirstOrDefault();
        if (string.IsNullOrEmpty(user))
            return Task.FromResult(AuthenticateResult.NoResult());

        var claims = new[] { new Claim(ClaimTypes.Name, user) };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
