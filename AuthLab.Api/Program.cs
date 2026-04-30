using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthLab.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwt = builder.Configuration.GetSection("Jwt");

// RS256: load PEM-encoded RSA private key from LabKeys, register an RsaSecurityKey.
var rsa = RSA.Create();
rsa.ImportFromPem(LabKeys.RsaPrivateKeyPem);
var signingKey = new RsaSecurityKey(rsa);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.IncludeErrorDetails = true;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwt["Issuer"],
            ValidAudience = jwt["Audience"],
            IssuerSigningKey = signingKey,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // Default ClockSkew is 5 minutes -- left as default to demonstrate JWT-V03.
            // ValidAlgorithms intentionally NOT set -- testing whether the framework
            // rejects HS/RS algorithm confusion under default configuration (JWT-V02).
        };
    })
    // M2: a deliberately broken IssuerSigningKeyResolver. Mimics a multi-tenant
    // resolver where a developer cached the public key bytes as a shared secret.
    // Returns BOTH the legitimate RsaSecurityKey (so RS256 still works) AND a
    // SymmetricSecurityKey whose bytes are the public key PEM. This re-opens the
    // HS/RS confusion attack that the default config rejected.
    .AddJwtBearer("BrokenResolver", o =>
    {
        o.IncludeErrorDetails = true;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwt["Issuer"],
            ValidAudience = jwt["Audience"],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                var rsaInner = RSA.Create();
                rsaInner.ImportFromPem(LabKeys.RsaPrivateKeyPem);
                var rsaKey = new RsaSecurityKey(rsaInner);
                var symKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(LabKeys.RsaPublicKeyPem));
                return new SecurityKey[] { rsaKey, symKey };
            }
        };
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
    {
        o.Cookie.Name = "AuthLab.Auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.LoginPath = "/cookie/login";
        o.LogoutPath = "/cookie/logout";
        o.AccessDeniedPath = "/cookie/denied";
    });

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("admin", p => p.RequireRole("admin"));
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// ---- Public ----
app.MapGet("/public", () => Results.Ok(new { msg = "anyone" }));

// ---- JWT-protected ----
app.MapGet("/secure", (ClaimsPrincipal u) =>
        Results.Ok(new
        {
            sub = u.Identity?.Name,
            claims = u.Claims.Select(c => new { c.Type, c.Value })
        }))
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme
    });

app.MapGet("/admin", (ClaimsPrincipal u) => Results.Ok(new { you = u.Identity?.Name }))
    .RequireAuthorization(new AuthorizeAttribute("admin")
    {
        AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme
    });

// M2: protected by the broken-resolver scheme. Same shape as /secure but routed to
// the JwtBearer config that has the naive resolver.
app.MapGet("/secure-broken", (ClaimsPrincipal u) =>
        Results.Ok(new
        {
            sub = u.Identity?.Name,
            claims = u.Claims.Select(c => new { c.Type, c.Value })
        }))
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = "BrokenResolver"
    });

// ---- Dev-only token minter (so curl/REST client users can grab tokens) ----
app.MapGet("/dev/token", (HttpContext ctx) =>
{
    var q = ctx.Request.Query;
    var sub = q["sub"].FirstOrDefault() ?? "alice";
    var role = q["role"].FirstOrDefault();
    var iss = q["iss"].FirstOrDefault() ?? jwt["Issuer"];
    var aud = q["aud"].FirstOrDefault() ?? jwt["Audience"];
    var expSecs = int.TryParse(q["exp"], out var e) ? e : 600;
    var nbfSecs = int.TryParse(q["nbf"], out var n) ? n : 0;
    var keyOverride = q["key"].FirstOrDefault();

    var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, sub) };
    if (!string.IsNullOrEmpty(role)) claims.Add(new Claim(ClaimTypes.Role, role));

    SecurityKey key = signingKey;
    string alg = SecurityAlgorithms.RsaSha256;
    if (keyOverride is not null)
    {
        // Override with a fresh RSA key (caller hasn't supplied one; this lets us mint
        // tokens signed by a *different* key for the wrong-key path).
        var altRsa = RSA.Create(2048);
        key = new RsaSecurityKey(altRsa);
    }
    var creds = new SigningCredentials(key, alg);

    var token = new JwtSecurityToken(
        issuer: iss,
        audience: aud,
        claims: claims,
        notBefore: DateTime.UtcNow.AddSeconds(nbfSecs),
        expires: DateTime.UtcNow.AddSeconds(expSecs),
        signingCredentials: creds);

    return Results.Text(new JwtSecurityTokenHandler().WriteToken(token));
});

// Public-key endpoint -- mimics what a JWKS / pubkey endpoint would expose.
// An attacker mounting an algorithm-confusion attack would fetch this.
app.MapGet("/dev/pubkey", () => Results.Text(LabKeys.RsaPublicKeyPem, "application/x-pem-file"));

// ---- Cookie auth flow ----
app.MapPost("/cookie/login", async (HttpContext ctx, LoginRequest body) =>
{
    var claims = new List<Claim> { new(ClaimTypes.Name, body.User) };
    if (!string.IsNullOrEmpty(body.Role)) claims.Add(new Claim(ClaimTypes.Role, body.Role));
    var id = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));

    // INTENTIONAL VULNERABILITY (C-V01 open redirect):
    // Real code should validate with `Url.IsLocalUrl(returnUrl)` before redirecting.
    if (!string.IsNullOrEmpty(body.ReturnUrl))
        return Results.Redirect(body.ReturnUrl);
    return Results.Ok(new { ok = true });
});

app.MapPost("/cookie/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { ok = true });
});

app.MapGet("/cookie/secure", (ClaimsPrincipal u) => Results.Ok(new { user = u.Identity?.Name }))
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme
    });

// INTENTIONAL VULNERABILITY (C-V04 CSRF): state-changing endpoint with no antiforgery.
app.MapPost("/cookie/transfer", (ClaimsPrincipal u, HttpContext ctx) =>
    {
        var amount = ctx.Request.Query["amount"].FirstOrDefault();
        var to = ctx.Request.Query["to"].FirstOrDefault();
        return Results.Ok(new { from = u.Identity?.Name, to, amount });
    })
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme
    });

app.MapGet("/cookie/denied", () => Results.StatusCode(403));

app.Run();

public record LoginRequest(string User, string? Role, string? ReturnUrl);

// Required for WebApplicationFactory<Program> in the test project.
public partial class Program;
