# Brdp.Authentication

BFF (Backend-For-Frontend) authentication library for **BrdpApiGateway**.

Built with **.NET 10 / C# 14** · Redis · OIDC (TPS SSO).

The SPA never holds SSO tokens — it holds only a short-lived **BrdpToken** (HS256 JWT).
The gateway keeps the SSO tokens in Redis, which is the **session source of truth**:
deleting a key logs the user out immediately, even while the BrdpToken is still valid.

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | BFF pattern, pipeline, components, concurrency, resilience |
| [docs/SPECS.md](docs/SPECS.md) | HTTP surface, flows, tokens, invariants, configuration, logging |
| [docs/USAGE.md](docs/USAGE.md) | Host registration, configuration, SPA integration, operations |
| [docs/PLAN.md](docs/PLAN.md) | What's done, what's open, roadmap |
| [CLAUDE.md](CLAUDE.md) | Repository guide & conventions |

---

## Solution structure

```
Brdp.Authentication.sln
└── src/
    ├── Brdp.Authentication/            ← class library (all auth logic)
    │   ├── Abstractions/   interfaces (IAuthenticatedUserContext, ISessionService, …)
    │   ├── Configuration/  options, constants, scheme names
    │   ├── Controllers/    AuthController, BranchController, SessionController
    │   ├── Extensions/     AddBrdpAuthentication (DI) + UseBrdpAuthentication (pipeline)
    │   ├── Infrastructure/ RedisSessionStore, SsoHttpClient, RedisKeyHelper
    │   ├── Middleware/     Correlation → TokenRefresh → BrdpAuthentication
    │   ├── Models/         RedisSession, BrdpTokenClaims, SsoTokenResponse, …
    │   ├── Security/       DataProtection / NoOp token encryption
    │   └── Services/       SessionService, BrdpTokenService, BranchService, SsoTokenService
    │
    └── Brdp.Authentication.Api/        ← ASP.NET Core host (Program.cs, appsettings.json)
```

---

## Quick start

```csharp
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

// ...
app.UseAuthentication();          // OIDC + Cookie handlers
app.UseBrdpAuthentication();      // ForwardedHeaders → CORS → RateLimiter
                                  // → Correlation → TokenRefresh → BrdpAuthentication
app.MapControllers();
```

```bash
dotnet build
dotnet run --project src/Brdp.Authentication.Api
```

Redis must be reachable at `ConnectionStrings:Redis`. See [docs/USAGE.md](docs/USAGE.md)
for full configuration and SPA integration.

---

## HTTP surface (summary)

| Method | Route                  | Auth      | Description |
|--------|------------------------|-----------|-------------|
| GET    | `/auth/login`          | Anonymous | Initiates the OIDC challenge |
| GET    | `/auth/callback`       | Anonymous | OIDC code exchange — issues BrdpToken |
| GET    | `/auth/userinfo`       | Required  | Current user identity |
| POST   | `/auth/refresh-token`  | Anonymous | Explicit BrdpToken rotation |
| POST   | `/auth/logout`         | Required  | Revoke + delete session + sign out |
| GET    | `/auth/signed-out`     | Anonymous | Post-signout landing |
| POST   | `/branch/select`       | Required  | Branch users: upgrade token with branch context |

Full route list, flows and invariants are in [docs/SPECS.md](docs/SPECS.md).

---

## Key design decisions

| Decision | Detail |
|---|---|
| SPA never sees SSO tokens | SPA holds BrdpToken only; gateway holds SSO tokens in Redis |
| Redis is session source of truth | Deleting a key invalidates the user instantly |
| `Expiry(BrdpToken) == Expiry(SsoAccessToken)` | No SSO-token parsing on the hot path |
| Redis TTL = refresh-token lifetime | Session survives access-token rotation |
| Single-flight refresh (distributed lock) | Single-use SSO refresh tokens never double-spent |
| Authorization via middleware + Redis | JWT validity alone is insufficient; Redis is authoritative |
| Data Protection key ring in Redis | Encrypted sessions survive restarts & scale out |

---

## Redis key format

```
auth:session:{sha256(username.ToLowerInvariant())}   ← session payload (TTL = refresh lifetime)
auth:lock:{sha256(username.ToLowerInvariant())}       ← distributed refresh lock
auth:dataprotection-keys                              ← Data Protection key ring
```

---

## Production checklist

- [ ] `Authentication:SigningKey` (≥32 chars) from a secret manager / env var
- [ ] `SsoAuthentication:ClientSecret` from a secret manager / env var
- [ ] `Authentication:EncryptTokensAtRest: true`
- [ ] TLS for Redis (`rediss://` / `ssl=true`)
- [ ] `Authentication:AllowedCorsOrigins` set to the real SPA origin(s)
- [ ] `Authentication:SingleSessionEnabled` set per policy
