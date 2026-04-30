using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Transport.Tests;

// Each fixture configures the Transport.Api with a different ForwardedHeaders mode and a
// simulated client IP. The simulated IP is critical: TestServer leaves Connection.RemoteIpAddress
// null by default, but production apps see real client IPs -- we have to simulate that to
// expose actual production behavior.

internal abstract class ConfigurableFactory : WebApplicationFactory<Program>
{
    protected abstract string Mode { get; }
    protected abstract string? SimulateRemoteIp { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ForwardedHeaders:SimulateRemoteIp"] = SimulateRemoteIp,
            }));

        // PostConfigure runs after the API's own Configure callback, so we can override the
        // ForwardedHeadersOptions for each test scenario without changing the API project.
        builder.ConfigureServices(services =>
        {
            services.PostConfigure<ForwardedHeadersOptions>(o =>
            {
                switch (Mode)
                {
                    case "TrustAll":
                        // The "make it work" anti-pattern -- clear known-proxy lists and
                        // remove the hop limit, so any source's headers are honored.
                        o.KnownProxies.Clear();
                        o.KnownIPNetworks.Clear();
                        o.ForwardLimit = null;
                        break;
                    case "Off":
                        // Disable header processing entirely.
                        o.ForwardedHeaders = ForwardedHeaders.None;
                        break;
                    case "Default":
                    default:
                        // Leave framework defaults: KnownProxies = [::1], KnownIPNetworks = [127.0.0.0/8].
                        break;
                }
            });
        });
    }
}

// App is reached via 127.0.0.1 -- the typical dev/test scenario AND the exact scenario where
// "headers worked locally" creates a false sense of security before production deployment.
internal sealed class LoopbackDefaultFactory : ConfigurableFactory
{
    protected override string Mode => "Default";
    protected override string? SimulateRemoteIp => "127.0.0.1";
}

// App is exposed directly to the public internet (no proxy). Forwarded headers from
// untrusted sources should be IGNORED.
internal sealed class PublicDefaultFactory : ConfigurableFactory
{
    protected override string Mode => "Default";
    protected override string? SimulateRemoteIp => "8.8.8.8";
}

// The "make it work" anti-pattern: KnownProxies and KnownNetworks cleared.
internal sealed class PublicTrustAllFactory : ConfigurableFactory
{
    protected override string Mode => "TrustAll";
    protected override string? SimulateRemoteIp => "8.8.8.8";
}

// UseForwardedHeaders effectively disabled (ForwardedHeaders.None).
internal sealed class PublicOffFactory : ConfigurableFactory
{
    protected override string Mode => "Off";
    protected override string? SimulateRemoteIp => "8.8.8.8";
}
