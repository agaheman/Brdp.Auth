# Specifications

Functional and behavioural contract of the library.

## 1. HTTP surface

| Method | Route                  | Auth      | Description |
|--------|------------------------|-----------|-------------|
| GET    | `/auth/login`          | Anonymous | Initiates the OIDC Authorization-Code challenge |
| GET    | `/auth/callback`       | Anonymous | OIDC code exchange → creates Redis session → issues BrdpToken |
| GET    | `/auth/userinfo`       | Required  | Current user identity + session metadata |
| POST   | `/auth/refresh-token`  | Anonymous*| Explicit BrdpToken rotation (accepts expired-but-valid token) |
| POST   | `/auth/logout`         | Required  | Revoke SSO token + delete session + OIDC end-session |
| GET    | `/auth/signed-out`     | Anonymous | Post-SSO-signout landing |
| POST   | `/branch/select`       | Required  | Branch users: upgrade token with branch context |
| GET    | `/session`             | Required  | Session introspection (no tokens exposed) |
| DELETE | `/session`             | Required  | Self-logout without OIDC redirect |
| GET    | `/health`              | Anonymous | Readiness probe (pings Redis) |

\* `/auth/refresh-token` is anonymous to the auth middleware because it deliberately
accepts an expired (but signature-valid) BrdpToken; it validates the token itself.

"Required" = a valid BrdpToken **and** a matching live Redis session (enforced by
`BrdpAuthenticationMiddleware`).

## 2. Flows

### Login
```
SPA → GET /auth/login → OIDC challenge → TPS SSO
   → GET /auth/callback
       → read SSO tokens from the OIDC cookie
       → (SingleSessionEnabled) delete any prior session for the user
       → save Redis session (TTL = refresh-token lifetime)
       → issue BrdpToken (expiry = SSO access-token expiry)
   → 200 { token, isBranchUser, expiresAt, returnUrl }
```

### Branch selection (branch users only)
```
SPA → POST /branch/select { branchCode }
   → [refresh lock] SSO token-exchange upgrade with branchCode
   → update Redis (new tokens + branchCode)
   → issue new BrdpToken aligned to new access-token expiry
   → 200 { token, branchCode, expiresAt }      (SPA replaces its token)
```

### Transparent refresh
```
Request with expired / near-expiry BrdpToken
   → TokenRefreshMiddleware detects (reactive: expired; proactive: < ProactiveRefreshThreshold)
   → [refresh lock] SSO refresh_token grant → update Redis → issue new BrdpToken
   → inject new token into the inbound Authorization header (request continues)
   → response header X-New-BrdpToken: <new-token>   (SPA replaces its token)
   → on failure: 401 + header X-Auth-Error: refresh_failed
```

### Logout
```
SPA → POST /auth/logout
   → revoke SSO access token + delete Redis session
   → SignOut(Cookie, OIDC) → SSO global signout
   → SSO → GET /auth/signed-out → 200 { signedOut: true }
```

## 3. Tokens & session

### BrdpToken (JWT, HS256)
Claims: `sub`, `userCode`, `username`, `firstName`, `lastName`; `iss`/`aud` per options;
`nbf`/`exp` set at issue. Validated with 30s clock skew. `exp == SSO access-token exp`.
Rotation supported via `PreviousSigningKeys` (old keys still validate).

### RedisSession (`auth:session:{sha256(username)}`)
`sessionId`, `userCode`, `username`, `firstName`, `lastName`, `isBranchUser`, `branchCode?`,
`clientIp`, `ssoAccessToken`, `ssoRefreshToken`, `accessTokenExpiry`, `refreshTokenExpiry`.
TTL = `refreshTokenExpiry − now`. `ssoAccessToken`/`ssoRefreshToken` encrypted at rest when
`EncryptTokensAtRest=true`.

## 4. Invariants

1. The SPA never receives an SSO token.
2. A request authorizes only if BrdpToken **and** Redis session both validate and the
   `userCode` claim matches the session.
3. Only one SSO token rotation per user runs at a time (refresh + branch upgrade share the
   lock); single-use refresh tokens are never double-spent.
4. Redis TTL is driven by the SSO refresh-token lifetime (`refresh_expires_in` when the SSO
   advertises it, else `AuthenticationOptions.RefreshTokenLifetime`).
5. Deleting the Redis key logs the user out on their next request.

## 5. Configuration (`Authentication` section)

| Key | Default | Meaning |
|---|---|---|
| `SigningKey` | — (required, ≥32 chars) | HS256 signing key |
| `PreviousSigningKeys` | `[]` | Old keys still accepted during rotation |
| `Issuer` / `Audience` | — (required) | JWT `iss` / `aud` |
| `SingleSessionEnabled` | `true` | New login invalidates prior session |
| `EncryptTokensAtRest` | `false` | Encrypt SSO tokens in Redis (force-on in Production) |
| `ProactiveRefreshThreshold` | `00:05:00` | Refresh when remaining lifetime is below this |
| `RefreshTokenLifetime` | `08:00:00` | Fallback session TTL when SSO omits `refresh_expires_in` |
| `AccessTokenFallbackLifetime` | `01:00:00` | Fallback access-token lifetime when `expires_at` is missing |
| `RefreshLockTtl` | `00:00:10` | Lock auto-expiry |
| `RefreshLockTimeout` | `00:00:08` | Max wait to acquire the lock |
| `RefreshLockPollInterval` | `00:00:00.100` | Poll interval while waiting |
| `AllowedCorsOrigins` | `[]` | SPA origin(s) allowed cross-origin |

`SsoAuthentication` section: `ClientId`, `ClientSecret`, `Authority`, `MetadataAddress`
(required), plus `ResponseType`, `Scopes`, `CallbackPath`, `SignedOutCallbackPath`,
`UpgradeTokenEndpoint`.

## 6. Logging / correlation

- **Per request:** `X-Correlation-ID` (inbound honoured, else generated from the W3C trace
  id) is echoed in the response, exposed via CORS, set on `Activity`, and added to a
  logging scope (`CorrelationId`, `TraceId`) around the whole request.
- **Whole flow:** once authenticated, `Username` + `SessionId` + `UserCode` are added to
  the scope, so the multi-request journey (login → … → logout) joins on `SessionId` even
  across OIDC browser redirects where the header cannot survive.
- Requires a scope-aware logger (console `IncludeScopes:true`, or Serilog/OpenTelemetry).
