# auth-lab

A self-contained ASP.NET Core 10 lab for hands-on security research against
`JwtBearer` and Cookie authentication. Built to **break assumptions and
observe what the framework actually does** — including a working
proof-of-concept of an HS/RS algorithm-confusion attack against a misconfigured
`IssuerSigningKeyResolver`.

## What this is

A minimal API target with a paired xUnit test project. Each test corresponds
to a row in a JWT/Cookie threat matrix: expected behavior, failure paths, and
vulnerability checks. The tests double as a **regression detector for the
framework's default defenses** — if a future Microsoft.IdentityModel.Tokens
update ever weakens the typed-key resolution that prevents algorithm
confusion, the relevant tests will go red.

## Highlights

| Test class | What it asserts |
| --- | --- |
| `JwtAuthTests` | Default-config token validation: missing token, wrong issuer/audience/key, expired, `nbf` future, `alg:none`, query-string token, case-insensitive `Bearer`, distinguishable error messages |
| `CookieAuthTests` | Cookie scheme: redirect-on-missing, login flow, tampered ticket, cookie attributes (`HttpOnly`, `SameSite`), session rotation, intentional open-redirect, intentional CSRF gap |
| `JwtAlgorithmConfusionTests` | RS256 default config rejects HS256 forgery using public-key bytes as HMAC secret. The same forged token validates against a deliberately broken `IssuerSigningKeyResolver` — demonstrating that the framework's defense is *typed-key resolution* and a sloppy resolver disables it |

29 / 29 tests pass on .NET 10.0.102.

## Key finding: HS/RS algorithm confusion

| Endpoint | Resolver | Forged HS256 (signed with public-key PEM bytes) |
| --- | --- | --- |
| `/secure` | Default — `IssuerSigningKey = RsaSecurityKey` | **401** `"The signature key was not found"` |
| `/secure-broken` | Custom — returns `RsaSecurityKey` *and* `SymmetricSecurityKey(publicKeyPemBytes)` | **200** — attacker authenticated as `alice` with `role: admin` |

The default config defends correctly: `JsonWebTokenHandler` resolves keys by
algorithm type, so an `alg=HS256` token finds no matching `SymmetricSecurityKey`
and fails with `SecurityTokenSignatureKeyNotFoundException`
([trace](https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/JwtBearer/src/JwtBearerHandler.cs)).

The defense breaks the moment a custom `IssuerSigningKeyResolver` returns a
key whose type matches the token's algorithm — even if the bytes inside that
key originated from public-key material. Any multi-tenant resolver that
caches "key bytes" without remembering the original key type is a candidate
for this bug.

**Fix in application code:**

* Never wrap public-key bytes in `SymmetricSecurityKey`. They are not a secret.
* Set `TokenValidationParameters.ValidAlgorithms = ["RS256"]` (or whichever
  algorithm you actually use) as defense-in-depth.
* In a custom resolver, assert that returned keys match the token's expected
  algorithm before yielding them.

## Quick start

Requires the .NET 10 SDK (pinned via `global.json`).

```bash
git clone <this-repo>
cd auth-lab

# Run the API for manual exploration:
dotnet run --project AuthLab.Api
# Listens on https://localhost:7099

# Run the full test matrix:
dotnet test AuthLab.Tests/AuthLab.Tests.csproj
```

`tests.http` (in the repo root) drives the same flows from the VS Code REST
Client or JetBrains HTTP client.

## File layout

```
auth-lab/
  global.json
  tests.http
  AuthLab.Api/
    Program.cs              Minimal API: /public, /secure, /admin,
                            /secure-broken, /dev/token, /dev/pubkey,
                            /cookie/{login,logout,secure,transfer}
    LabKeys.cs              Lab-only RSA-2048 keypair (do not reuse)
    appsettings.json
  AuthLab.Tests/
    TestTokenFactory.cs     Mints valid / expired / wrong-iss / wrong-aud /
                            wrong-key / alg:none / forged-HS256 tokens
    JwtAuthTests.cs
    CookieAuthTests.cs
    JwtAlgorithmConfusionTests.cs
```

## Intentional vulnerabilities (do not deploy)

For pedagogy, the lab API contains three deliberate bugs. The tests assert
their presence so you can see the difference when you fix them:

1. **Open redirect** — `POST /cookie/login` redirects to `body.ReturnUrl`
   without `Url.IsLocalUrl(...)`.
2. **CSRF** — `POST /cookie/transfer` is state-changing with no antiforgery.
3. **Broken `IssuerSigningKeyResolver`** — `/secure-broken` is the algorithm-
   confusion target.

## License

MIT. The RSA keypair in `LabKeys.cs` was generated specifically for this lab
and must never be used in any real system.

## Disclaimer

This repository is for educational and defensive research only. The exploits
demonstrated here target a local, intentionally vulnerable lab API on
`localhost`. Do not point any tooling derived from this repository at systems
you do not own or are not explicitly authorized to test.
