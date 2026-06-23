using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Middleware;

/// <summary>
/// Core authentication middleware — runs once per request and builds the
/// <see cref="IAuthenticatedUserContext"/> that all downstream code consumes.
///
/// Pipeline:
///   1. Extract BrdpToken from Authorization header (<c>Bearer …</c>).
///   2. Validate signature (expiry handled separately in <see cref="TokenRefreshMiddleware"/>).
///   3. Extract username / userCode from token claims.
///   4. Single Redis lookup — read session.
///   5. Verify session exists and identity matches.
///   6. Populate <see cref="IAuthenticatedUserContextAccessor.Context"/>.
///
/// Anonymous endpoints (decorated with <c>[AllowAnonymous]</c> or inside excluded paths)
/// are passed through without a 401.
/// </summary>
public sealed class BrdpAuthenticationMiddleware
{
    private readonly RequestDelegate                        _next;
    private readonly IBrdpTokenService                      _brdpTokens;
    private readonly ILogger<BrdpAuthenticationMiddleware>  _logger;
    private readonly AuthenticationOptions                  _options;

    /// <summary>Paths that bypass authentication entirely.</summary>
    private static readonly HashSet<string> _anonymousPaths =
    [
        "/auth/login",
        "/auth/callback",
        "/auth/signed-out",
        "/auth/refresh-token",          // accepts expired tokens — handled internally
        "/signin-oidc",           // ASP.NET Core OIDC middleware internal callback
        "/signout-callback-oidc", // ASP.NET Core OIDC middleware internal signout
        "/health",
    ];

    public BrdpAuthenticationMiddleware(
        RequestDelegate                         next,
        IBrdpTokenService                       brdpTokens,
        IOptions<AuthenticationOptions>         options,
        ILogger<BrdpAuthenticationMiddleware>   logger)
    {
        _next       = next;
        _brdpTokens = brdpTokens;
        _options    = options.Value;
        _logger     = logger;
    }

    // ISessionService is Scoped, so it is injected per-request via InvokeAsync
    // (not the singleton constructor) to avoid a captive-dependency / root-scope resolve.
    public async Task InvokeAsync(
        HttpContext context,
        IAuthenticatedUserContextAccessor accessor,
        ISessionService sessions)
    {
        // ── Bypass anonymous paths ────────────────────────────────────────────
        if (IsAnonymousPath(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // ── Step 1: Extract token ─────────────────────────────────────────────
        var token = ExtractBearerToken(context.Request);
        if (token is null)
        {
            _logger.LogDebug("No Bearer token on {Path}. Returning 401.", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // ── Step 2: Validate signature AND expiry ─────────────────────────────
        // We use the full Validate (expiry enforced). TokenRefreshMiddleware runs
        // earlier in the pipeline and has already swapped an expired/near-expiry token
        // for a fresh one in the Authorization header. If that middleware is NOT
        // registered, expired tokens correctly fail here.
        var claims = _brdpTokens.Validate(token);
        if (claims is null)
        {
            _logger.LogWarning("Invalid BrdpToken on {Path}. Returning 401.", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // ── Step 3: Single Redis lookup ───────────────────────────────────────
        var session = await sessions
            .GetByUsernameAsync(claims.Username, context.RequestAborted)
            .ConfigureAwait(false);

        if (session is null)
        {
            _logger.LogWarning(
                "No Redis session for user {Username} on {Path}. Returning 401.",
                claims.Username, context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // ── Step 4: Identity cross-check ──────────────────────────────────────
        if (!string.Equals(claims.UserCode, session.UserCode, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "UserCode mismatch: token={TokenUserCode}, session={SessionUserCode}. Returning 401.",
                claims.UserCode, session.UserCode);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // ── Step 5: Populate accessor — available to all downstream DI ────────
        accessor.Context = AuthenticatedUserContext.FromSession(session);

        // ── Step 6: Enrich the logging scope with the session identity ────────
        // Adds Username + SessionId to every downstream log line. Combined with the
        // CorrelationId from CorrelationMiddleware, this lets a complete authentication
        // flow be reconstructed across separate requests (login → … → logout) by
        // filtering on SessionId, even across OIDC browser redirects.
        using (_logger.BeginScope(new Dictionary<string, object>
        {
            ["Username"]  = session.Username,
            ["UserCode"]  = session.UserCode,
            ["SessionId"] = session.SessionId,
        }))
        {
            _logger.LogDebug(
                "User {Username} authenticated for {Path}.", claims.Username, context.Request.Path);

            await _next(context).ConfigureAwait(false);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string? ExtractBearerToken(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        return header["Bearer ".Length..].Trim();
    }

    private static bool IsAnonymousPath(PathString path)
    {
        foreach (var p in _anonymousPaths)
            if (path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
