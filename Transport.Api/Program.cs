using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Default ForwardedHeaders configuration. Tests mutate options via PostConfigure
// to exercise different modes (Default, TrustAll, Off). For curl-based exploration
// outside tests, edit appsettings.json or pass options here.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto |
        ForwardedHeaders.XForwardedHost;
});

var app = builder.Build();

// Optional: simulate a non-loopback connection origin. When ForwardedHeaders:SimulateRemoteIp
// is set in configuration (typically by a test fixture), we override Connection.RemoteIpAddress
// before UseForwardedHeaders runs. This exposes the framework's behavior for the realistic
// production case where the app is exposed to the public internet rather than 127.0.0.1.
//
// Read at REQUEST time so the test fixture's in-memory config provider takes effect.
app.Use(async (ctx, next) =>
{
    var cfg = ctx.RequestServices.GetRequiredService<IConfiguration>();
    var simIp = cfg["ForwardedHeaders:SimulateRemoteIp"];
    if (!string.IsNullOrEmpty(simIp))
    {
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(simIp);
    }
    await next();
});

app.UseForwardedHeaders();

// Reflects the request's view of the network -- post-ForwardedHeaders.
app.MapGet("/whoami-network", (HttpContext ctx) => Results.Ok(new
{
    remoteIp = ctx.Connection.RemoteIpAddress?.ToString(),
    scheme = ctx.Request.Scheme,
    host = ctx.Request.Host.Value,
    isHttps = ctx.Request.IsHttps,
    headers = new
    {
        forwardedFor = ctx.Request.Headers["X-Forwarded-For"].ToString(),
        forwardedProto = ctx.Request.Headers["X-Forwarded-Proto"].ToString(),
        forwardedHost = ctx.Request.Headers["X-Forwarded-Host"].ToString(),
    }
}));

// "Internal-only" endpoint -- naive IP allowlist. The bug surface: if forwarded headers are
// misconfigured, an attacker spoofing X-Forwarded-For: 127.0.0.1 can pass this gate.
app.MapGet("/internal-only", (HttpContext ctx) =>
{
    var ip = ctx.Connection.RemoteIpAddress;
    var allowed = ip is not null && IPAddress.IsLoopback(ip);
    return allowed ? Results.Ok(new { msg = "internal data" }) : Results.StatusCode(403);
});

app.Run();

public partial class Program;
