using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRequestDecompression();

var app = builder.Build();
app.UseRequestDecompression();

// Bounded endpoint: explicit 1 MB size limit. The framework's RequestDecompressionMiddleware
// wraps the request body in a SizeLimitedStream parameterised with this limit. Decompression
// amplification beyond 1 MB should produce 413 PayloadTooLarge.
app.MapPost("/upload-bounded", async (HttpContext ctx) =>
    {
        await using var copy = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(copy);
        return Results.Ok(new { decompressedBytesRead = copy.Length });
    })
    .WithMetadata(new RequestSizeLimitAttribute(1 * 1024 * 1024)); // 1 MB

// Unbounded endpoint: explicit [DisableRequestSizeLimit]. This sets MaxRequestBodySize = null
// on the IHttpMaxRequestBodySizeFeature. The middleware passes that null straight through to
// SizeLimitedStream, which then evaluates `_totalBytesRead > _sizeLimit` -- and in C# nullable
// comparison semantics, `long > long?(null)` is ALWAYS false, so the throw never fires.
//
// Attacker sends a small gzipped payload that decompresses to many MB / GB. The endpoint reads
// the entire decompressed body without any size enforcement -> resource amplification DoS.
app.MapPost("/upload-unbounded", async (HttpContext ctx) =>
    {
        await using var copy = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(copy);
        return Results.Ok(new { decompressedBytesRead = copy.Length });
    })
    .WithMetadata(new DisableRequestSizeLimitAttribute());

app.Run();

public partial class Program;
