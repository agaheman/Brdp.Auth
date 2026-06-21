# Architecture

## 1. Pattern: Backend-For-Frontend (BFF)

The SPA never holds SSO tokens. It holds only a **BrdpToken** — a short-lived HS256 JWT
minted by the gateway. The gateway keeps the SSO `access_token` / `refresh_token` in Redis
and uses them server-side. This keeps long-lived, high-value credentials out of the
browser while letting the SPA make authenticated calls.

```
┌────────┐   BrdpToken (JWT)    ┌────────────────────────┐   SSO tokens   ┌──────────┐
│  SPA   │ ◀──────────────────▶ │  BrdpApiGateway (BFF)   │ ◀────────────▶ │ TPS SSO  │
└────────┘                      │  + Redis (session SoT)  │                └──────────┘
                                └────────────────────────┘
```

## 2. Key design decisions

| Decision | Rationale |
|---|---|
| SPA holds BrdpToken only | SSO tokens never reach the browser |
| Redis is session source of truth | Deleting a key invalidates the user instantly, even with a valid JWT |
| `Expiry(BrdpToken) == Expiry(SsoAccessToken)` | No SSO-token parsing on the hot path |
| Redis TTL = RefreshToken expiry | Session survives access-token rotation |
| `IAuthenticatedUserContextAccessor` (scoped) | Services depend on an abstraction, not `HttpContext` |
| Single Redis read per request | Auth middleware reads once; downstream reuses the accessor |
| Single-flight refresh (distributed lock) | Single-use SSO refresh tokens can't be double-consumed across tabs |
| Data Protection key ring in Redis | Encrypted sessions survive restarts and scale horizontally |

## 3. Request pipeline

`UseBrdpAuthentication()` installs, in order:

```
Request
  │
  ▼  ForwardedHeaders          restore real client IP / scheme behind the gateway
  ▼  CORS                      expose X-New-BrdpToken / X-Correlation-ID to the SPA
  ▼  RateLimiter               fixed-window throttle on /auth/* (per client IP)
  ▼  CorrelationMiddleware     open logging scope: CorrelationId + TraceId
  ▼  TokenRefreshMiddleware    rotate token if expired / near expiry (single-flight)
  ▼  BrdpAuthenticationMiddleware
                               validate JWT → read Redis session → identity cross-check
                               → populate accessor → enrich scope (Username, SessionId)
  ▼  Controllers / Services    inject IAuthenticatedUserContextAccessor
```

It must run **after** `UseAuthentication()` (OIDC/Cookie handlers, which own the
`/signin-oidc` callback) and **before** `MapControllers()`.

### Authorization model

There is no ASP.NET `UseAuthorization()` and no `[Authorize]` attributes. Authorization is
the job of `BrdpAuthenticationMiddleware`: any path not in its `_anonymousPaths` set
requires a valid BrdpToken **and** a matching live Redis session. This is deliberate —
JWT validity alone is insufficient because Redis is the source of truth. Keep
`_anonymousPaths` (auth middleware) and `_skipPaths` (refresh middleware) aligned with the
controller routes.

## 4. Components

| Component | Responsibility |
|---|---|
| `BrdpTokenService` | Issue/validate HS256 BrdpTokens; supports key rotation via `PreviousSigningKeys` |
| `SessionService` → `RedisSessionStore` | Session CRUD + distributed refresh lock (SET NX PX + Lua release) |
| `SsoTokenService` → `SsoHttpClient` | Typed HTTP client for SSO refresh / upgrade / revoke |
| `BranchService` | Branch-selection token upgrade (runs inside the refresh lock) |
| `ITokenEncryptionService` | `DataProtection` (prod) or `NoOp` (dev) encryption of SSO tokens at rest |
| `Correlation`/`TokenRefresh`/`BrdpAuthentication` middleware | Cross-cutting request handling |

## 5. Concurrency: the refresh lock

SSO refresh tokens are single-use. Multiple SPA tabs can present the same expired
BrdpToken simultaneously. `RedisSessionStore.ExecuteWithRefreshLockAsync` serialises this:

1. Acquire `auth:lock:{hash}` with `SET NX PX` (TTL `RefreshLockTtl`).
2. The winner loads the session, runs the refresh/upgrade factory, persists new tokens.
3. Losers poll (`RefreshLockPollInterval`) up to `RefreshLockTimeout`; once the winner
   has persisted, a guard detects the already-fresh session and reissues a BrdpToken
   without calling SSO again.
4. Release is atomic via a Lua compare-and-delete (only the owner can release).

Both token refresh **and** branch upgrade rotate SSO tokens, so both run inside this lock.

## 6. Resilience

- **Redis:** `AbortOnConnectFail=false`, `ConnectRetry=3` — app boots and recovers across
  Redis blips. `/health` actively pings Redis as a readiness signal.
- **SSO:** typed `HttpClient` with a 15s timeout; failures return `null` and surface as
  401/`refresh_failed` rather than unhandled exceptions.
- **Data Protection:** key ring persisted to Redis under `auth:dataprotection-keys`.

## 7. Observability

Correlation has two layers (see [SPECS.md](SPECS.md) §Logging):

- **Per request:** `CorrelationId` + `TraceId` on every log line.
- **Across the whole flow** (login → callback → branch → refresh → logout, including OIDC
  browser redirects): `SessionId` (+ `Username`), added to the scope once authenticated.
