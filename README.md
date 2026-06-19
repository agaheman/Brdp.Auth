# Brdp.Authentication

BFF (Backend For Frontend) Authentication Library for BrdpApiGateway.

Built with **.NET 10 / C# 14** · Redis · OIDC (TPS SSO)

---

## Solution Structure

```
Brdp.Authentication.sln
│
├── src/
│   ├── Brdp.Authentication/              ← Class library (all auth logic)
│   │   ├── Abstractions/                 ← Interfaces (IAuthenticatedUserContext, etc.)
│   │   ├── Models/                       ← RedisSession, BrdpTokenClaims, etc.
│   │   ├── Configuration/                ← AuthenticationOptions, SsoAuthenticationOptions
│   │   ├── Services/                     ← SessionService, BrdpTokenService, BranchService, …
│   │   ├── Infrastructure/               ← RedisSessionStore, SsoHttpClient, RedisKeyHelper
│   │   ├── Middleware/                   ← BrdpAuthenticationMiddleware, TokenRefreshMiddleware
│   │   ├── Controllers/                  ← AuthController, BranchController, SessionController
│   │   ├── Security/                     ← NoOpTokenEncryptionService, DataProtectionEncryptionService
│   │   └── Extensions/                   ← ServiceCollectionExtensions, ApplicationBuilderExtensions
│   │
│   └── Brdp.Authentication.Api/          ← ASP.NET Core host (Program.cs, appsettings.json)
│
└── tests/
    └── Brdp.Authentication.Tests/        ← xUnit · Moq · FluentAssertions
```

---

## Key Design Decisions

| Decision | Detail |
|---|---|
| **SPA never sees SSO tokens** | SPA holds BrdpToken only; gateway holds SsoAccessToken + SsoRefreshToken in Redis |
| **IAuthenticatedUserContextAccessor (Scoped)** | Replaces `HttpContext.Items["UserContext"]`; services inject it directly, no HttpContext coupling |
| **Redis is Session Source of Truth** | Deleting a Redis key immediately invalidates user, even if BrdpToken is still valid |
| **Single Redis lookup per request** | Auth middleware reads session once; all downstream services use the populated accessor |
| **Expiry alignment** | `Expiry(BrdpToken) == Expiry(SsoAccessToken)` — no repeated SSO token parsing |
| **Redis TTL = RefreshToken expiry** | Session survives AccessToken rotation |
| **Dual refresh triggers** | Reactive (expired) + proactive (remaining < threshold) |
| **EncryptTokensAtRest** | ASP.NET Core Data Protection — active in production |

---

## Middleware Pipeline Order

```
Request
  │
  ▼
TokenRefreshMiddleware          ← rotates token if expired or near expiry
  │
  ▼
BrdpAuthenticationMiddleware    ← validates signature + Redis session + populates IAuthenticatedUserContextAccessor
  │
  ▼
Controllers / Services          ← inject IAuthenticatedUserContextAccessor, call .GetRequiredContext()
```

---

## Authentication Flows

### Login
```
SPA → GET /auth/login
    → OIDC challenge → TPS SSO
    → GET /auth/callback
        → Extract SSO tokens
        → Save Redis session (TTL = RefreshTokenExpiry)
        → Issue BrdpToken (expiry = SsoAccessTokenExpiry)
        → Return { token, isBranchUser, expiresAt }
```

### Branch Selection (branch users only)
```
SPA → POST /branch/select { branchCode }
    → BranchService.SelectBranchAsync()
        → Load Redis session
        → POST SSO /upgradeToken { accessToken, branchCode }
        → Update Redis: new tokens + branchCode
        → Issue new BrdpToken aligned to new SsoAccessToken expiry
    → Return { token, branchCode, expiresAt }
SPA stores new token (old token is now stale)
```

### Refresh (transparent)
```
Request with expired/near-expiry BrdpToken
  → TokenRefreshMiddleware detects
  → Read Redis session
  → POST SSO /refreshToken
  → Update Redis session
  → Issue new BrdpToken
  → Inject new token into Authorization header (current request continues)
  → Response header: X-New-BrdpToken: <new-token>
  → SPA intercepts header and replaces stored token
```

### Logout
```
SPA → POST /auth/logout
    → Read session from Redis
    → Revoke SsoAccessToken at SSO
    → Delete Redis session
    → Sign out OIDC cookie
    → 200 OK
SPA removes BrdpToken → redirects to login
```

---

## Registration (Program.cs)

```csharp
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

// ...

app.UseAuthentication();          // ASP.NET Core OIDC + Cookie handler
app.UseBrdpAuthentication();      // TokenRefresh → BrdpAuth middleware
app.UseAuthorization();
app.MapControllers();
```

---

## Configuration (appsettings.json)

```json
{
  "ConnectionStrings": {
    "Redis": "localhost:6379"
  },
  "Authentication": {
    "SigningKey": "<min 32 chars>",
    "Issuer": "BrdpApiGateway",
    "Audience": "BrdpSpa",
    "SingleSessionEnabled": true,
    "EncryptTokensAtRest": false,
    "ProactiveRefreshThreshold": "00:05:00"
  },
  "SsoAuthentication": {
    "ClientId": "...",
    "ClientSecret": "...",
    "Authority": "https://sso.tps.ir",
    "MetadataAddress": "https://sso.tps.ir/.well-known/openid-configuration",
    "ResponseType": "code",
    "Scopes": ["openid", "profile"],
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath": "/signout-callback-oidc",
    "UpgradeTokenEndpoint": "/protocol/openid-connect/token/upgrade"
  }
}
```

---

## Consuming IAuthenticatedUserContextAccessor in Services

```csharp
// In any Scoped service — no HttpContext dependency:
public class MyService(IAuthenticatedUserContextAccessor accessor)
{
    public void DoWork()
    {
        var user = accessor.GetRequiredContext();
        // user.UserCode, user.Username, user.BranchCode, etc.
    }
}
```

---

## Redis Key Format

```
auth:{sha256(username.ToLowerInvariant())}
```

TTL equals `RefreshTokenExpiry`. Deleting the key immediately logs the user out.

---

## Production Checklist

- [ ] Set a strong `Authentication:SigningKey` (≥ 32 chars) via secret manager / env var
- [ ] Set `Authentication:EncryptTokensAtRest: true`
- [ ] Configure Data Protection key storage (Azure Key Vault / Redis key ring)
- [ ] Use TLS for Redis connection (`rediss://`)
- [ ] Set `Authentication:SingleSessionEnabled: true`
- [ ] Replace `ClientSecret` with secret manager reference
