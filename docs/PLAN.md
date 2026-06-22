# Plan / Roadmap

Status of the production-readiness work and what remains.

## Done — production hardening

- [x] **Redis resilience** — `AbortOnConnectFail=false`, `ConnectRetry=3`, 5s connect
      timeout; the app boots and recovers across Redis blips instead of crashing.
- [x] **Data Protection key ring → Redis** (`auth:dataprotection-keys`, shared application
      name) — encrypted sessions survive restarts and work across scaled-out instances.
- [x] **CORS policy** exposing `X-New-BrdpToken`, `X-Correlation-ID`, `X-Auth-Error` —
      the transparent-refresh flow now works cross-origin.
- [x] **Forwarded headers** — real client IP / scheme behind the gateway.
- [x] **Rate limiting** — fixed-window per-IP throttle on `/auth/*`.
- [x] **Real health check** — `/health` pings Redis (readiness probe).
- [x] **Correlated logging** — per-request `CorrelationId`/`TraceId` + whole-flow
      `SessionId`/`Username` scope.
- [x] **Correctness:** SSO-driven session TTL (`refresh_expires_in`); branch upgrade runs
      under the refresh lock; removed dead authorization stack; aligned route/skip paths;
      fixed stale comments/docstrings; removed dead lock-timeout code.
- [x] **Polish:** stable `SsoTokenResponse` expiry; configurable lock timing; signing-key
      rotation via `PreviousSigningKeys`; OpenAPI document in Development.

## Open — owner action (not code)

- [ ] **Rotate & externalise secrets.** `appsettings.json` still contains a sample
      `ClientSecret` and placeholder `SigningKey`. Move both to a secret manager / env vars
      and rotate the committed client secret. *(Deliberately left as an owner task.)*
- [ ] Use TLS for Redis in production (`ssl=true` / `rediss://`).
- [ ] Set `AllowedCorsOrigins` to the real SPA origin(s) per environment.

## Backlog — future enhancements

- [ ] **Automated tests.** Characterization/unit coverage for `BrdpTokenService`
      (issue/validate/rotation), the refresh lock (single-flight under contention), expiry
      alignment, and middleware 401 paths.
- [ ] **SSO call resilience.** Add retry/circuit-breaker (e.g. `Microsoft.Extensions.Http`
      resilience) around `SsoHttpClient`.
- [ ] **Metrics/tracing.** Emit OpenTelemetry spans/metrics for login, refresh, branch
      upgrade, and lock contention.
- [ ] **Distributed-cache health detail** and structured `/health` response for dashboards.
- [ ] **Admin/session-management** surface (list/terminate sessions) if operationally
      required.

## Notes on intentional design choices

- Authorization is enforced by `BrdpAuthenticationMiddleware` against Redis, not the ASP.NET
  authorization stack — JWT validity alone is insufficient when Redis is the source of
  truth. Keep `_anonymousPaths` / `_skipPaths` in sync with controller routes.
- Token rotation is single-flight per user. Any new code path that rotates SSO tokens must
  run inside `ExecuteWithRefreshLockAsync`.
