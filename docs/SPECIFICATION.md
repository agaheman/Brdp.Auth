# Brdp.Authentication — Full Specification

> Canonical, self-contained reference for the `Brdp.Authentication` class library.
> Hand this file (plus `CLAUDE.md`) to another developer or AI to understand the
> library end-to-end without reading the source. Last aligned with branch
> `dotinEnvChanges`.

---

## 1. Purpose

`Brdp.Authentication` is a **BFF (Backend-For-Frontend) authentication library** for the
BrdpApiGateway. A SPA authenticates against **TPS SSO** (`sso.tps.ir`) using the OIDC
Authorization-Code flow. The gateway holds the SSO tokens server-side in **Redis** and
hands the SPA only a short-lived **BrdpToken** (HS256 JWT).

Core invariants:

- **The SPA never sees SSO tokens.** It only ever holds a BrdpToken (in `localStorage`,
  sent as `Authorization: Bearer`).
- **Redis is the session source of truth.** Deleting the session key logs the user out
  immediately, regardless of BrdpToken validity.
- **`Expiry(BrdpToken) == Expiry(SsoAccessToken)`** — alignment invariant, so no SSO-token
  parsing is needed on the hot path.
- **Redis TTL == RefreshTokenExpiry** — the session survives access-token rotation.

Shipped as a class library (`src/Brdp.Authentication`) plus a thin demo host
(`src/Brdp.Authentication.Api`) with a vanilla-JS sample SPA under `wwwroot/`.

Stack: .NET 10 / C# 14 · ASP.NET Core · StackExchange.Redis · OIDC.

---

## 2. Wiring (host integration)

```csharp
// Program.cs
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

var app = builder.Build();

app.UseAuthentication();      // OIDC/Cookie handlers (must come first)
app.UseBrdpAuthentication();  // BFF pipeline (see §6)
app.MapControllers();
app.MapHealthChecks("/health");
```

`AddBrdpAuthentication` registers: options binding + validation, a resilient Redis
multiplexer, Data Protection (encrypted-at-rest sessions), the typed `SsoHttpClient`,
forwarded headers, CORS, rate limiting, OIDC + cookie authentication, health checks,
and all services below.

---

## 3. Public features (the API surface)

### 3.1 Authentication (OIDC Authorization-Code flow)
`AuthController` — route prefix `/auth`:

| Method | Route | Auth | Purpose |
|---|---|---|---|
| GET  | `/auth/signin` | anon | Start OIDC challenge → redirect to SSO |
| GET  | `/auth/signin-callback` | anon | Post-login: read SSO tokens, create session, issue BrdpToken, redirect with `#token=…` |
| GET  | `/auth/userinfo` | Bearer | Authenticated user identity + session metadata |
| POST | `/auth/refresh-token` | Bearer (expired ok) | Explicit BrdpToken rotation |
| POST | `/auth/signout` | Bearer | Sign out of Brdp, return the SSO sign-out URL |
| GET  | `/auth/signout-callback` | anon | Post-SSO-signout landing |

OIDC middleware also owns two internal paths (not controller actions):
`/auth/oidc-callback` (auth code intake) and `/auth/oidc-signout-callback`.

### 3.2 Token Refresh
`TokenRefreshMiddleware` transparently rotates a BrdpToken that is expired or near expiry,
using `ISsoTokenService.RefreshAsync` under a single-flight per-user lock. The new token is
returned in the `X-New-BrdpToken` response header; the SPA replaces its stored token.
`POST /auth/refresh-token` is the explicit equivalent.

### 3.3 Token Upgrade  ← reusable feature
`ITokenUpgradeService` — **the public, repeatable feature** that enriches the live session
with extra SSO claims:

```csharp
Task<TokenUpgradeResult> UpgradeAsync(
    string username,
    IReadOnlyDictionary<string, object?> clientClaims,
    CancellationToken ct = default);
```

Behavior (runs under the single-flight refresh lock):
1. Calls SSO `grant_type=upgrade_token` with the current access token's `jti` +
   serialized `client_claims` (+ scope when configured).
2. Persists the rotated SSO tokens to the Redis session, and reads the **top-level
   `branch_code`** claim from the upgraded token into `session.BranchCode`
   (sets `IsBranchUser = true`). *Note: `branch_code` is a top-level claim, **not** inside
   `user_info`.*
3. Re-issues the BrdpToken aligned to the new access-token expiry.

Idempotent and **callable repeatedly** — e.g. select a branch, then change it. Returns
`TokenUpgradeResult { BrdpToken, AccessTokenExpiry, BranchCode }`.

### 3.4 Branch selection  ← a *use* of Token Upgrade
`IBranchService.SelectBranchAsync(username, branchCode)` is a thin wrapper that calls
`ITokenUpgradeService.UpgradeAsync` with `{ ["branch_code"] = branchCode }`.
Exposed as `POST /branch/select { "branchCode": "…" }` → `{ token, branchCode, expiresAt }`.

---

## 4. Services & abstractions

| Abstraction | Lifetime | Responsibility |
|---|---|---|
| `ISessionService` | scoped | Redis CRUD + `ExecuteWithRefreshLockAsync<T>` single-flight lock |
| `IBrdpTokenService` | singleton | Issue / validate BrdpTokens (HS256, signing-key rotation via `PreviousSigningKeys`) |
| `ISsoTokenService` | scoped | SSO HTTP calls: `RefreshAsync`, `UpgradeAsync(accessToken, clientClaims)`, `RevokeAsync` |
| `ITokenUpgradeService` | scoped | Token Upgrade feature (§3.3) |
| `IBranchService` | scoped | Branch selection (§3.4) |
| `IAuthenticatedUserContextAccessor` | scoped | Per-request user context; `GetRequiredContext()` |
| `ITokenEncryptionService` | singleton | DataProtection (prod) / NoOp (dev) encryption of tokens at rest |

Infrastructure: `RedisSessionStore`, `SsoHttpClient` (typed), `RedisKeyHelper`,
`SsoAccessTokenParser` (decodes the SSO access token — `ExtractUserInfo`,
`ExtractBranchCode`, `ExtractJti`).

**Convention:** services never touch `HttpContext`. They consume
`IAuthenticatedUserContextAccessor.GetRequiredContext()`, populated once per request by
`BrdpAuthenticationMiddleware`.

---

## 5. SSO compatibility (TPS-specific behavior)

TPS SSO is not fully OIDC-compliant; these knobs (all in `SsoAuthentication`) make it work:

| Option | Default | Why |
|---|---|---|
| `Scopes` | `[]` | Empty = let the SSO apply the client's configured scopes (sending a scope list got `Invalid Scope`) |
| `UsePkce` | `true` | TPS confidential client 500s when a PKCE `code_verifier` is sent → set **`false`** |
| `UseClientSecretJwt` | `false` | TPS works with plain `client_secret_post` |
| `SkipAtHashValidation` | `false` | TPS mis-computes `at_hash` (IDX21348) → set **`true`** to skip only that check |
| `GetClaimsFromUserInfoEndpoint` | `true` | TPS userinfo lacks `sub` (IDX21345) → set **`false`**; identity is read from the access token |
| `ClientAssertionAudience` | — | Audience for `client_secret_jwt` when enabled |

Identity source: with the userinfo endpoint disabled, `SignInCallback` reads the access
token's nested **`user_info`** JSON claim (`first_name`, `last_name`, `username`,
`user_code`, `uid`, …) via `SsoAccessTokenParser.ExtractUserInfo`.

Endpoints are **TPS `/oauth/*` paths**, not Keycloak: token `/oauth/token`, revoke
`/revoke`, end-session `/oauth/endsession` (configurable). The first SSO connection is slow
(~15s TLS handshake) so `HttpTimeoutSeconds` defaults to **60**.

Sign-out: TPS exposes a sign-out **URL**, not an API. `POST /auth/signout` signs out of
Brdp first (revoke + delete session + clear cookie), then returns
`{ signOutUrl = EndSessionEndpoint?post_logout_redirect_uri=LogoutRedirectUrl }`; the SPA
navigates the browser there.

Non-production also bypasses TLS validation on the OIDC backchannel and `SsoHttpClient`
(internal CA) — never active when `IsProduction()`.

---

## 6. Pipeline order

`UseBrdpAuthentication()` registers, in order:
`ForwardedHeaders → CORS → RateLimiter → Correlation → TokenRefresh → BrdpAuthentication`.
Call it **after** `UseAuthentication()` and **before** `MapControllers()`.

Authorization is enforced by `BrdpAuthenticationMiddleware` against the Redis session — not
the ASP.NET authorization stack (no `UseAuthorization()`, no `[Authorize]`). Anonymous
routes live in the middleware allow-list (`_anonymousPaths` / `_skipPaths`): `/auth/signin`,
`/auth/signin-callback`, `/auth/signout-callback`, `/auth/refresh-token`,
`/auth/oidc-callback`, `/auth/oidc-signout-callback`, `/health`. Keep these in sync with
controller routes.

Every request runs inside a correlation logging scope (`CorrelationId`, `TraceId`, and once
authenticated `Username`/`SessionId`). OIDC errors are caught by `OnRemoteFailure` and
redirected to `/error.html?error=…&flow=…&step=…` (the diagnostics page).

---

## 7. End-to-end flows

**Login**
```
SPA → GET /auth/signin?returnUrl=/signin-complete.html
    → 302 sso.tps.ir/oauth/authorize  (user authenticates)
    → /auth/oidc-callback (code) → OIDC middleware exchanges code (client_secret_post, no PKCE)
    → GET /auth/signin-callback  → read user_info from access token, store Redis session,
                                    issue BrdpToken
    → 302 /signin-complete.html#token=…&expiresAt=…&isBranchUser=…
    → SPA stores token in localStorage → /profile.html (GET /auth/userinfo)
```

**Token upgrade (branch)**
```
profile → branch.html (dropdown) → POST /branch/select { branchCode }
    → ITokenUpgradeService.UpgradeAsync({ branch_code }) under refresh lock
    → SSO upgrade_token → new token (branch_code claim) → update session → new BrdpToken
    → SPA stores new token → profile shows branchCode
```

**Sign-out**
```
profile → POST /auth/signout  (revoke + delete session + clear cookie) → { signOutUrl }
    → browser navigates to signOutUrl (SSO end-session) → redirects to LogoutRedirectUrl
```

---

## 8. Configuration reference

### `Authentication` (`AuthenticationOptions`)
`SigningKey`, `PreviousSigningKeys`, `Issuer`, `Audience`, `SingleSessionEnabled`,
`EncryptTokensAtRest`, `ProactiveRefreshThreshold`, `RefreshTokenLifetime`,
`AccessTokenFallbackLifetime`, `AllowedCorsOrigins`, lock TTL/timeout tuning.

### `SsoAuthentication` (`SsoAuthenticationOptions`)
`ClientId`, `ClientSecret`, `Authority`, `MetadataAddress`, `ResponseType`, `Scopes`,
`CallbackPath`, `SignedOutCallbackPath`, `TokenEndpointPath`, `RevocationEndpointPath`,
`EndSessionEndpointPath`, `LogoutRedirectUrl`, `HttpTimeoutSeconds`, `UsePkce`,
`UseClientSecretJwt`, `ClientAssertionAudience`, `SkipAtHashValidation`,
`GetClaimsFromUserInfoEndpoint`. Computed: `TokenEndpoint`, `RevocationEndpoint`,
`EndSessionEndpoint`.

### `ConnectionStrings:Redis`
StackExchange.Redis string. Connection is resilient (`AbortOnConnectFail=false`) — the app
boots without Redis and reconnects in the background.

---

## 9. Security model

- BrdpToken in `localStorage` + `Authorization: Bearer` — CSRF-immune; not a cookie.
- SSO tokens are server-side only (Redis), encrypted at rest in production
  (`EncryptTokensAtRest=true`; DataProtection key ring persisted to Redis).
- `SigningKey` and `ClientSecret` must come from a secret manager / env vars in real
  environments, never `appsettings.json`.
- Redis keys are SHA-256 hashed (`auth:session:{sha256(username)}`,
  `auth:lock:{sha256(username)}`) via `RedisKeyHelper`.
- SSO token rotation (refresh + upgrade) is single-flight per user via
  `ExecuteWithRefreshLockAsync` to prevent double-consumption of single-use SSO tokens.

---

## 10. Companion docs

- `CLAUDE.md` — working guide / conventions for editing this repo.
- `docs/ARCHITECTURE.md` — design decisions and component diagram.
- `docs/USAGE.md` — host + SPA integration walkthrough.
- `src/Brdp.Authentication.Api/OpenApi/SWAGGER.md` — Swagger UI at `/swagger`.
