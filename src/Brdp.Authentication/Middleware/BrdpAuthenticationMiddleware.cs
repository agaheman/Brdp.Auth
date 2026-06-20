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
    private readonly ISessionService                        _sessions;
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
        ISessionService                         sessions,
        IOptions<AuthenticationOptions>         options,
        ILogger<BrdpAuthenticationMiddleware>   logger)
    {
        _next       = next;
        _brdpTokens = brdpTokens;
        _sessions   = sessions;
        _options    = options.Value;
        _logger     = logger;
    }

    public async Task InvokeAsync(HttpContext context, IAuthenticatedUserContextAccessor accessor)
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

        // ── Step 2: Validate signature (expiry may be skipped by refresh middleware) ──
        // At this stage we use ValidateIgnoringExpiry so that the refresh middleware
        // (which runs before this one in the pipeline) has already replaced the token
        // in the Authorization header if it was expired. If the refresh middleware is
        // NOT registered, expired tokens will correctly fail here.
        var claims = _brdpTokens.Validate(token);
        if (claims is null)
        {
            _logger.LogWarning("Invalid BrdpToken on {Path}. Returning 401.", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // ── Step 3: Single Redis lookup ───────────────────────────────────────
        var session = await _sessions
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

        _logger.LogDebug(
            "User {Username} authenticated for {Path}.", claims.Username, context.Request.Path);

        await _next(context).ConfigureAwait(false);
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
