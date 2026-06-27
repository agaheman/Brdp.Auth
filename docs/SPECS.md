# Specifications

Functional and behavioural contract of the library.

## 1. HTTP surface

| Method | Route                      | Auth      | Description |
|--------|----------------------------|-----------|-------------|
| GET    | `/auth/signin`             | Anonymous | Initiates the OIDC Authorization-Code challenge |
| GET    | `/auth/oidc-callback`      | Anonymous | OIDC middleware code-exchange callback (`CallbackPath`) |
| GET    | `/auth/signin-callback`    | Anonymous | Reads SSO tokens → creates Redis session → issues BrdpToken |
| GET    | `/auth/userinfo`           | Required  | Current user identity + session metadata |
| POST   | `/auth/refresh-token`      | Anonymous*| Explicit BrdpToken rotation (accepts expired-but-valid token) |
| POST   | `/auth/signout`            | Required  | Sign out of Brdp, then returns the SSO sign-out URL |
| GET    | `/auth/oidc-signout-callback` | Anonymous | OIDC signed-out callback (`SignedOutCallbackPath`) |
| GET    | `/auth/signout-callback`   | Anonymous | Post-SSO-signout landing |
| POST   | `/branch/select`           | Required  | Branch selection (a use of the Token Upgrade feature) |
| GET    | `/session`                 | Required  | Session introspection (no tokens exposed) |
| DELETE | `/session`                 | Required  | Self-logout without OIDC redirect |
| GET    | `/health`                  | Anonymous | Readiness probe (pings Redis) |

\* `/auth/refresh-token` is anonymous to the auth middleware because it deliberately
accepts an expired (but signature-valid) BrdpToken; it validates the token itself.

"Required" = a valid BrdpToken **and** a matching live Redis session (enforced by
`BrdpAuthenticationMiddleware`).

## 2. Flows

### Login
```
SPA → GET /auth/signin → OIDC challenge → TPS SSO
   → GET /auth/oidc-callback (OIDC middleware code exchange)
   → GET /auth/signin-callback
       → read SSO tokens from the OIDC cookie
       → read identity from the access token's nested user_info claim
       → (SingleSessionEnabled) delete any prior session for the user
       → issue BrdpToken (expiry = SSO access-token expiry)
       → save Redis session { identity, ssoToken, brdpToken } (TTL = refresh-token lifetime)
   → redirect returnUrl#token=…  (browser SPA) OR 200 { token, isBranchUser, expiresAt }
```

### Branch selection (a use of the Token Upgrade feature)
```
SPA → POST /branch/select { branchCode }
   → ITokenUpgradeService.UpgradeAsync(username, { branch_code })
   → [refresh lock] SSO upgrade_token grant (access_token_jti + client_claims)
   → update Redis: rotate ssoToken, set root branchCode/isBranchUser, re-issue+store brdpToken
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

### Logout (TPS SSO has no sign-out API, only a URL)
```
SPA → POST /auth/signout
   → revoke SSO access token + delete Redis session + clear local OIDC cookie
   → 200 { signOutUrl }                         (Brdp is signed out first)
SPA → window.location = signOutUrl              (SSO end-session URL)
   → SSO clears its session → redirects to SsoAuthentication:LogoutRedirectUrl
```

## 3. Tokens & session

### BrdpToken (JWT, HS256)
Claims: `sub`, `userCode`, `username`, `firstName`, `lastName`; `iss`/`aud` per options;
`nbf`/`exp` set at issue. Validated with 30s clock skew. `exp == SSO access-token exp`.
Rotation supported via `PreviousSigningKeys` (old keys still validate).

### RedisSession (`auth:session:{sha256(username)}`)
Two clearly separated tokens plus identity at the root:

```jsonc
{
  "sessionId": "…",
  "clientIp": "10.20.153.42",
  "userCode": "99990001",          // ── identity (root)
  "username": "99990001",
  "firstName": "نگار",
  "lastName": "اصلحا",
  "branchCode": "1",
  "isBranchUser": true,
  "ssoToken": {                    // ── SsoToken: raw SSO pair + expiries (server-only)
    "accessToken": "eyJ…",         //    encrypted at rest when EncryptTokensAtRest=true
    "refreshToken": "…",           //    encrypted at rest when EncryptTokensAtRest=true
    "accessTokenExpiry": "…",
    "refreshTokenExpiry": "…"
  },
  "brdpToken": "eyJ…"             // ── BrdpToken: the issued JWT the SPA holds (not encrypted)
}
```

TTL = `ssoToken.refreshTokenExpiry − now`. The `brdpToken` is re-issued and re-stored on
every refresh/upgrade. The rich SSO `user_info` is parsed at login to fill the root identity
but is **not** stored.

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
`TokenEndpointPath` (`/oauth/token`), `RevocationEndpointPath` (`/revoke`),
`EndSessionEndpointPath` (`/oauth/endsession`), `LogoutRedirectUrl`, `HttpTimeoutSeconds`
(`60`), and TPS-compatibility switches: `UsePkce`, `UseClientSecretJwt`,
`ClientAssertionAudience`, `SkipAtHashValidation`, `GetClaimsFromUserInfoEndpoint`.

## 6. Logging / correlation

- **Per request:** `X-Correlation-ID` (inbound honoured, else generated from the W3C trace
  id) is echoed in the response, exposed via CORS, set on `Activity`, and added to a
  logging scope (`CorrelationId`, `TraceId`) around the whole request.
- **Whole flow:** once authenticated, `Username` + `SessionId` + `UserCode` are added to
  the scope, so the multi-request journey (login → … → logout) joins on `SessionId` even
  across OIDC browser redirects where the header cannot survive.
- Requires a scope-aware logger (console `IncludeScopes:true`, or Serilog/OpenTelemetry).
