using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using Xunit.Abstractions;

namespace AuthLab.Tests;

// JWT-V02: HS / RS algorithm-confusion attack.
//
// Setup: API is configured with `IssuerSigningKey = RsaSecurityKey` and RS256.
// `TokenValidationParameters.ValidAlgorithms` is intentionally NOT set, so we are
// testing the framework's *default* posture against algorithm confusion.
//
// Attack: an attacker fetches the public key from /dev/pubkey, then signs a forged
// token using HS256 with the public-key bytes as the HMAC shared secret. If the
// validator naively trusts the `alg` field in the token header and uses the
// configured key with whatever algorithm the token specified, the forged token
// would validate.
//
// Expected outcome: rejected. Microsoft.IdentityModel.Tokens detects key/algorithm
// mismatch (RsaSecurityKey cannot be used to verify HS256). We assert this and
// then read JwtBearerHandler / JsonWebTokenHandler to find the line that prevents it.
public class JwtAlgorithmConfusionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    private readonly ITestOutputHelper _out;

    public JwtAlgorithmConfusionTests(WebApplicationFactory<Program> factory, ITestOutputHelper output)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        _out = output;
    }

    private static HttpRequestMessage Get(string url, string? bearer = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (bearer is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return req;
    }

    [Fact] // sanity check: legitimately signed RS256 token works
    public async Task RS256_signed_token_is_accepted()
    {
        var r = await _client.SendAsync(Get("/secure", TestTokenFactory.Valid()));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // sanity check: /dev/pubkey actually exposes the public key
    public async Task Pubkey_endpoint_returns_PEM()
    {
        var r = await _client.GetAsync("/dev/pubkey");
        var body = await r.Content.ReadAsStringAsync();
        Assert.Contains("BEGIN PUBLIC KEY", body);
    }

    [Fact] // The classic confusion attack -- public key PEM as HMAC secret
    public async Task Forged_HS256_using_public_key_pem_is_rejected()
    {
        var token = TestTokenFactory.ForgedHs256_UsingPublicKeyPem();
        var r = await _client.SendAsync(Get("/secure", token));

        // Capture the WWW-Authenticate header for forensics -- this should mention
        // a key/algorithm mismatch (typically IDX10500: signature validation failed).
        _out.WriteLine($"Status: {(int)r.StatusCode}");
        _out.WriteLine($"WWW-Authenticate: {r.Headers.WwwAuthenticate}");

        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // Variant: attack using raw SubjectPublicKeyInfo DER bytes
    public async Task Forged_HS256_using_public_key_der_is_rejected()
    {
        var token = TestTokenFactory.ForgedHs256_UsingPublicKeyDer();
        var r = await _client.SendAsync(Get("/secure", token));

        _out.WriteLine($"Status: {(int)r.StatusCode}");
        _out.WriteLine($"WWW-Authenticate: {r.Headers.WwwAuthenticate}");

        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact] // The forged token, even if validated, would carry an admin role.
    // This documents the *impact* if the framework defaults were broken.
    public async Task Forged_HS256_token_payload_carries_admin_role()
    {
        var token = TestTokenFactory.ForgedHs256_UsingPublicKeyPem(role: "admin");
        // Decode payload to confirm what an attacker would gain on success.
        var payload = token.Split('.')[1];
        // base64url -> base64
        var b64 = payload.Replace('-', '+').Replace('_', '/');
        b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
        var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));

        Assert.Contains("\"admin\"", json);
        Assert.Contains("\"alice\"", json);
    }

    // ----------------------------------------------------------------------
    // M2: mutation. /secure-broken is protected by a JwtBearer scheme whose
    // IssuerSigningKeyResolver naively returns a SymmetricSecurityKey derived
    // from the public-key bytes alongside the legitimate RsaSecurityKey.
    //
    // Predictions:
    //   - Sanity: legitimate RS256 token still works against the broken scheme (200).
    //   - The SAME forged HS256 token that the default scheme rejected with 401
    //     should now succeed against the broken scheme (200) -- confirming that
    //     the default-config defense was typed-key resolution, not algorithm
    //     validation. A sloppy resolver disables the defense.
    // ----------------------------------------------------------------------

    [Fact] // Sanity: legitimate RS256 token still works on the broken scheme.
    public async Task RS256_token_validates_against_broken_resolver()
    {
        var r = await _client.SendAsync(Get("/secure-broken", TestTokenFactory.Valid()));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // THE FINDING: forged HS256 token validates against the broken scheme.
    public async Task Forged_HS256_token_succeeds_against_broken_resolver()
    {
        var token = TestTokenFactory.ForgedHs256_UsingPublicKeyPem(role: "admin");
        var r = await _client.SendAsync(Get("/secure-broken", token));

        _out.WriteLine($"Status: {(int)r.StatusCode}");
        _out.WriteLine($"WWW-Authenticate: {r.Headers.WwwAuthenticate}");
        _out.WriteLine($"Body: {await r.Content.ReadAsStringAsync()}");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact] // Regression baseline: same token still rejected by the default-config endpoint.
    // This proves the difference is the resolver, not the token.
    public async Task Same_forged_token_is_still_rejected_by_default_endpoint()
    {
        var token = TestTokenFactory.ForgedHs256_UsingPublicKeyPem(role: "admin");
        var defaultR = await _client.SendAsync(Get("/secure", token));
        var brokenR = await _client.SendAsync(Get("/secure-broken", token));

        Assert.Equal(HttpStatusCode.Unauthorized, defaultR.StatusCode);
        Assert.Equal(HttpStatusCode.OK, brokenR.StatusCode);
    }
}
