using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthLab.Api;
using Microsoft.IdentityModel.Tokens;

namespace AuthLab.Tests;

// Mints JWTs that match the AuthLab.Api configuration.
// The API now uses RS256 with the RSA key from LabKeys (shared via InternalsVisibleTo).
internal static class TestTokenFactory
{
    public const string DefaultIssuer = "https://localhost:7099";
    public const string DefaultAudience = "auth-lab";

    private static SigningCredentials LabRsaCredentials()
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(LabKeys.RsaPrivateKeyPem);
        return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
    }

    public static string Valid(string sub = "alice", string? role = null) =>
        Build(sub: sub, role: role);

    // Past default 5-minute ClockSkew -- API actually rejects it.
    public static string Expired() => Build(nbfSecs: -7200, expSecs: -3600);

    // Slightly past expiration but inside default 5-min skew -- still accepted (JWT-V03).
    public static string SlightlyExpired() => Build(nbfSecs: -120, expSecs: -60);

    public static string FutureNotBefore() => Build(nbfSecs: 3600, expSecs: 7200);
    public static string WrongIssuer() => Build(issuer: "https://attacker.example");
    public static string WrongAudience() => Build(audience: "other-api");

    // Wrong key: a fresh, unrelated RSA key pair.
    public static string WrongKey()
    {
        var rsa = RSA.Create(2048);
        var creds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        return Build(creds: creds);
    }

    // JWT-V01: hand-crafted alg:none token (no signature).
    public static string AlgNone(string sub = "alice", string? role = "admin")
    {
        var header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        var payload = "{\"sub\":\"" + sub +
                      "\",\"iss\":\"" + DefaultIssuer +
                      "\",\"aud\":\"" + DefaultAudience +
                      "\",\"exp\":9999999999" +
                      (role is null ? "" : ",\"role\":\"" + role + "\"") +
                      "}";
        return Base64Url(header) + "." + Base64Url(payload) + ".";
    }

    // JWT-V02 attack variant 1: forge an HS256 token using the *PEM-encoded public key string*
    // as the HMAC secret. This is the classic algorithm-confusion attack: the attacker has
    // the public key (from JWKS / /dev/pubkey) and tries to trick the validator into
    // verifying a symmetric signature using that key as the shared secret.
    public static string ForgedHs256_UsingPublicKeyPem(string sub = "alice", string? role = "admin")
    {
        var keyBytes = Encoding.UTF8.GetBytes(LabKeys.RsaPublicKeyPem);
        return BuildHs256(keyBytes, sub, role);
    }

    // JWT-V02 attack variant 2: same attack but using raw DER (SubjectPublicKeyInfo) bytes.
    // Some libraries normalize PEM-vs-DER inconsistently, so this is worth testing separately.
    public static string ForgedHs256_UsingPublicKeyDer(string sub = "alice", string? role = "admin")
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(LabKeys.RsaPublicKeyPem);
        var derBytes = rsa.ExportSubjectPublicKeyInfo();
        return BuildHs256(derBytes, sub, role);
    }

    private static string BuildHs256(byte[] keyBytes, string sub, string? role)
    {
        var sk = new SymmetricSecurityKey(keyBytes);
        var creds = new SigningCredentials(sk, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, sub) };
        if (!string.IsNullOrEmpty(role)) claims.Add(new Claim(ClaimTypes.Role, role));

        var t = new JwtSecurityToken(
            issuer: DefaultIssuer,
            audience: DefaultAudience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(t);
    }

    private static string Base64Url(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Build(
        string sub = "alice",
        string? role = null,
        string? issuer = null,
        string? audience = null,
        SigningCredentials? creds = null,
        int expSecs = 600,
        int nbfSecs = 0)
    {
        var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, sub) };
        if (!string.IsNullOrEmpty(role)) claims.Add(new Claim(ClaimTypes.Role, role));

        var t = new JwtSecurityToken(
            issuer: issuer ?? DefaultIssuer,
            audience: audience ?? DefaultAudience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddSeconds(nbfSecs),
            expires: DateTime.UtcNow.AddSeconds(expSecs),
            signingCredentials: creds ?? LabRsaCredentials());

        return new JwtSecurityTokenHandler().WriteToken(t);
    }
}
