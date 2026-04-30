using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Pipeline.Tests;

internal abstract class PipelineFactory : WebApplicationFactory<Program>
{
    protected abstract bool AddAuthentication { get; }
    protected abstract bool AddAuthorization { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // UseSetting writes to the host's IConfiguration before user code runs.
        // Program.cs reads these values to decide whether to call
        // AddAuthentication() / AddAuthorization().
        builder.UseSetting("Pipeline:AddAuthentication", AddAuthentication.ToString());
        builder.UseSetting("Pipeline:AddAuthorization", AddAuthorization.ToString());
    }
}

// Standard pipeline -- both services registered, auto-injection runs.
internal sealed class StandardFactory : PipelineFactory
{
    protected override bool AddAuthentication => true;
    protected override bool AddAuthorization => true;
}

// AddAuthorization called, AddAuthentication is not -- auto-injection adds
// UseAuthorization but NOT UseAuthentication. The principal is never
// populated, so [Authorize] always denies.
internal sealed class NoAuthenticationServiceFactory : PipelineFactory
{
    protected override bool AddAuthentication => false;
    protected override bool AddAuthorization => true;
}

// AddAuthentication called, AddAuthorization is not -- auto-injection adds
// UseAuthentication but NOT UseAuthorization. The endpoint has [Authorize]
// metadata; without UseAuthorization the EndpointMiddleware THROWS at request
// time -> 500.
internal sealed class NoAuthorizationServiceFactory : PipelineFactory
{
    protected override bool AddAuthentication => true;
    protected override bool AddAuthorization => false;
}
