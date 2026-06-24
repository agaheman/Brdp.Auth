# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`Brdp.Authentication` is a **BFF (Backend-For-Frontend) authentication library** for the
BrdpApiGateway. A SPA authenticates against TPS SSO (OIDC Authorization-Code flow); the
gateway holds the SSO tokens in Redis and hands the SPA only a short-lived **BrdpToken**
(HS256 JWT). Redis is the session source of truth — deleting a key logs the user out
immediately, regardless of BrdpToken validity.

- **Stack:** .NET 10 / C# 14 · ASP.NET Core · Redis (StackExchange.Redis) · OIDC.
- **Shipped as:** a class library (`src/Brdp.Authentication`) + a thin host
  (`src/Brdp.Authentication.Api`) that demonstrates wiring.

## Project layout

```
src/
  Brdp.Authentication/            ← the library (all auth logic)
    Abstractions/   interfaces (ISessionService, IBrdpTokenService, …)
    Configuration/  options + constants + scheme names
    Controllers/    AuthController, BranchController, SessionController
    Extensions/     AddBrdpAuthentication (DI) + UseBrdpAuthentication (pipeline)
    Infrastructure/ RedisSessionStore, SsoHttpClient, RedisKeyHelper
    Middleware/     Correlation → TokenRefresh → BrdpAuthentication
    Models/         RedisSession, BrdpTokenClaims, SsoTokenResponse, …
    Security/       DataProtection / NoOp token encryption
    Services/       SessionService, BrdpTokenService, BranchService, SsoTokenService
  Brdp.Authentication.Api/        ← host (Program.cs, appsettings.json)
docs/                             ← ARCHITECTURE / SPECS / USAGE / PLAN
```

## Build / run

```bash
dotnet build                                   # build the solution
dotnet run --project src/Brdp.Authentication.Api
```

Redis must be reachable at `ConnectionStrings:Redis`. The app boots even if Redis is
temporarily down (`AbortOnConnectFail=false`) and reconnects in the background.

## Pipeline order (do not reorder casually)

`UseBrdpAuthentication()` registers, in order:
`ForwardedHeaders → CORS → RateLimiter → Correlation → TokenRefresh → BrdpAuthentication`.
It must be called **after** `UseAuthentication()` (the OIDC/Cookie handlers) and **before**
`MapControllers()`. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Conventions

- **No `HttpContext` coupling in services.** Consume `IAuthenticatedUserContextAccessor`
  and call `GetRequiredContext()`. The auth middleware populates it once per request.
- **Authorization is enforced by `BrdpAuthenticationMiddleware`** against the Redis
  session, *not* the ASP.NET authorization stack. There is intentionally no
  `UseAuthorization()` and no `[Authorize]`/`[AllowAnonymous]`. Anonymous routes are
  listed in the middleware's `_anonymousPaths`/`_skipPaths` sets — keep those in sync
  with the controller routes. Current anonymous paths:
  `/auth/signin`, `/auth/signin-callback`, `/auth/signout-callback`,
  `/auth/refresh-token`, `/auth/oidc-callback`, `/auth/oidc-signout-callback`, `/health`.
- **Redis keys** are built only via `RedisKeyHelper` (`auth:session:{sha256(username)}`,
  `auth:lock:{sha256(username)}`).
- **Token rotation is single-flight per user** via `ExecuteWithRefreshLockAsync` — any
  code that rotates SSO tokens (refresh, branch upgrade) must run inside it.
- **Logging:** every request runs inside a correlation scope (`CorrelationId`, `TraceId`,
  and once authenticated `Username`/`SessionId`). Prefer structured logging with those
  fields available; don't log raw SSO tokens.
- Tuning values (lock TTL/timeout, refresh threshold, token lifetimes, CORS origins) live
  in `AuthenticationOptions` — add new knobs there rather than hardcoding.

## Security notes

- `Authentication:SigningKey` and `SsoAuthentication:ClientSecret` must come from a secret
  manager / env vars in any real environment — do **not** rely on `appsettings.json`.
- Set `EncryptTokensAtRest=true` in production; the Data Protection key ring is persisted
  to Redis (`auth:dataprotection-keys`) so it survives restarts and is shared across
  instances.
