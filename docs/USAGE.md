# Usage

How to consume `Brdp.Authentication` in a gateway host and from a SPA.

## 1. Register (Program.cs)

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();        // OIDC + Cookie handlers (own the /signin-oidc callback)
app.UseBrdpAuthentication();    // ForwardedHeaders → CORS → RateLimiter → Correlation
                                // → TokenRefresh → BrdpAuthentication
app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
```

`UseBrdpAuthentication()` must be **after** `UseAuthentication()` and **before**
`MapControllers()`. Do not add `UseAuthorization()` — authorization is enforced by the BFF
middleware against the Redis session.

## 2. Configure (appsettings.json)

```json
{
  "ConnectionStrings": { "Redis": "localhost:6379" },
  "Authentication": {
    "SigningKey": "<from secret manager, >= 32 chars>",
    "Issuer": "BrdpApiGateway",
    "Audience": "BrdpSpa",
    "SingleSessionEnabled": true,
    "EncryptTokensAtRest": true,
    "ProactiveRefreshThreshold": "00:05:00",
    "AllowedCorsOrigins": [ "https://app.brdp.ir" ]
  },
  "SsoAuthentication": {
    "ClientId": "<id>",
    "ClientSecret": "<from secret manager>",
    "Authority": "https://sso.tps.ir",
    "MetadataAddress": "https://sso.tps.ir/.well-known/openid-configuration",
    "Scopes": [ "openid", "profile" ]
  },
  "Logging": { "Console": { "IncludeScopes": true } }
}
```

> **Secrets:** provide `SigningKey` and `ClientSecret` via environment variables / a secret
> manager (e.g. `Authentication__SigningKey`, `SsoAuthentication__ClientSecret`), never from
> a committed `appsettings.json`.

## 3. Consume the user context in your own services

No `HttpContext` dependency — inject the accessor:

```csharp
public sealed class OrderService(IAuthenticatedUserContextAccessor accessor)
{
    public Task PlaceOrderAsync()
    {
        var user = accessor.GetRequiredContext();
        // user.UserCode, user.Username, user.BranchCode, user.SessionId, ...
        return Task.CompletedTask;
    }
}
```

## 4. SPA integration

1. **Login:** redirect the browser to `GET /auth/login?returnUrl=/dashboard`. After SSO,
   the gateway returns `{ token, isBranchUser, expiresAt }` from `/auth/callback`. Store
   the `token`.
2. **Authenticated calls:** send `Authorization: Bearer <BrdpToken>`.
3. **Transparent refresh:** on every response, check for `X-New-BrdpToken`; if present,
   replace the stored token. (Requires the gateway origin in `AllowedCorsOrigins` so the
   header is readable cross-origin.)
4. **Explicit refresh:** `POST /auth/refresh-token` with the (possibly expired) token in
   the `Authorization` header → `{ token }`.
5. **Branch users:** if `isBranchUser`, call `POST /branch/select { "branchCode": "..." }`
   and replace the stored token with the returned one.
6. **Logout:** `POST /auth/logout`, then drop the stored token and redirect to login.

Example fetch wrapper:

```js
async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...opts.headers, Authorization: `Bearer ${getToken()}` },
  });
  const rotated = res.headers.get("X-New-BrdpToken");
  if (rotated) setToken(rotated);
  if (res.status === 401) redirectToLogin();
  return res;
}
```

## 5. Operations

- **Health:** `GET /health` returns 200 only when Redis is reachable — use it as the
  readiness probe.
- **Force-logout a user:** delete their `auth:session:{sha256(username)}` key in Redis;
  the next request is rejected.
- **Rotate the signing key:** deploy the new key as `SigningKey` and move the old one into
  `PreviousSigningKeys`; remove it after the longest token lifetime has elapsed.

## 6. Production checklist

- [ ] `SigningKey` (≥32 chars) and `ClientSecret` from a secret manager / env vars
- [ ] `EncryptTokensAtRest: true`
- [ ] TLS for Redis (`rediss://…` / `ssl=true`)
- [ ] `AllowedCorsOrigins` set to the real SPA origin(s)
- [ ] `SingleSessionEnabled` set per policy
- [ ] Confirm the gateway sets `X-Forwarded-For` / `X-Forwarded-Proto`
