using System.IdentityModel.Tokens.Jwt;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Middleware;

/// <summary>
/// Transparently refreshes BrdpTokens before the authentication middleware validates them.
///
/// Triggers:
///   A) BrdpToken is expired (reactive).
///   B) BrdpToken lifetime remaining &lt; <see cref="AuthenticationOptions.ProactiveRefreshThreshold"/> (proactive).
///
/// Concurrency:
///   Uses <see cref="ISessionService.ExecuteWithRefreshLockAsync{T}"/> to guarantee that only
///   one request per user calls the SSO refresh endpoint at a time. Concurrent requests that
///   arrive while a refresh is in-flight wait and receive the already-rotated token — preventing
///   the single-use SSO refresh token from being consumed twice.
///
/// Response signalling:
///   New token is written to the <c>X-New-BrdpToken</c> response header.
///   The SPA must read this header and replace its stored token.
///
/// Pipeline order (Program.cs):
///   1. UseAuthentication()       ← OIDC/Cookie middleware
///   2. UseBrdpAuthentication()   ← TokenRefreshMiddleware → BrdpAuthenticationMiddleware
/// </summary>
public sealed class TokenRefreshMiddleware
{
    private readonly RequestDelegate                 _next;
    private readonly IBrdpTokenService               _brdpTokens;
    private readonly AuthenticationOptions           _options;
    private readonly ILogger<TokenRefreshMiddleware> _logger;

    public const string NewTokenHeader  = "X-New-BrdpToken";
    public const string AuthErrorHeader = "X-Auth-Error";

    private static readonly HashSet<string> _skipPaths =
    [
        "/auth/signin",
        "/auth/signin-callback",
        "/auth/signout-callback",
        "/auth/refresh-token",            // avoid recursion
        "/auth/oidc-callback",
        "/auth/oidc-signout-callback",
        "/health",
    ];

    public TokenRefreshMiddleware(
        RequestDelegate                  next,
        IBrdpTokenService                brdpTokens,
        IOptions<AuthenticationOptions>  options,
        ILogger<TokenRefreshMiddleware>  logger)
    {
        _next       = next;
        _brdpTokens = brdpTokens;
        _options    = options.Value;
        _logger     = logger;
    }

    // ISessionService and ISsoTokenService are Scoped, so they are injected per-request
    // via InvokeAsync rather than the singleton constructor (avoids root-scope resolve).
    public async Task InvokeAsync(
        HttpContext context,
        ISessionService sessions,
        ISsoTokenService ssoTokens)
    {
        if (ShouldSkip(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var rawToken = ExtractBearerToken(context.Request);
        if (rawToken is null)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!NeedsRefresh(rawToken, out var claims))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation("Token refresh triggered for {Username}.", claims?.Username ?? "unknown");

        var newToken = await RefreshWithLockAsync(claims, sessions, ssoTokens, context.RequestAborted)
            .ConfigureAwait(false);

        if (newToken is null)
        {
            context.Response.StatusCode              = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AuthErrorHeader] = "refresh_failed";
            return;
        }

        // Inject the fresh token so BrdpAuthenticationMiddleware sees a valid token.
        context.Request.Headers.Authorization      = $"Bearer {newToken}";
        // Signal SPA to replace its stored token.
        context.Response.Headers[NewTokenHeader]   = newToken;

        await _next(context).ConfigureAwait(false);
    }

    // ── Refresh with distributed lock ─────────────────────────────────────────

    private async Task<string?> RefreshWithLockAsync(
        BrdpTokenClaims? claims,
        ISessionService sessions,
        ISsoTokenService ssoTokens,
        CancellationToken ct)
    {
        if (claims is null) return null;

        return await sessions.ExecuteWithRefreshLockAsync<string>(
            claims.Username,
            async (session, innerCt) =>
            {
                // Guard: another caller may have already refreshed — check if
                // the current session tokens are newer than what we started with.
                if (session.AccessTokenExpiry > DateTimeOffset.UtcNow + _options.ProactiveRefreshThreshold)
                {
                    _logger.LogDebug(
                        "Session for {Username} was already refreshed by a concurrent caller. " +
                        "Issuing BrdpToken from current session.", claims.Username);

                    return _brdpTokens.Issue(SessionToClaims(session), session.AccessTokenExpiry);
                }

                var ssoResponse = await ssoTokens
                    .RefreshAsync(session.SsoRefreshToken, innerCt)
                    .ConfigureAwait(false);

                if (ssoResponse is null)
                {
                    _logger.LogWarning("SSO refresh failed for {Username}.", claims.Username);
                    return null;
                }

                session.SsoAccessToken     = ssoResponse.AccessToken;
                session.SsoRefreshToken    = ssoResponse.RefreshToken;
                session.AccessTokenExpiry  = ssoResponse.AccessTokenExpiry;
                session.RefreshTokenExpiry = ssoResponse.RefreshTokenExpiry;

                await sessions.UpdateAsync(session, innerCt).ConfigureAwait(false);

                return _brdpTokens.Issue(SessionToClaims(session), ssoResponse.AccessTokenExpiry);
            },
            ct: ct).ConfigureAwait(false);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private bool NeedsRefresh(string token, out BrdpTokenClaims? claims)
    {
        claims = _brdpTokens.Validate(token);

        if (claims is null)
        {
            var claimsIgnoringExpiry = _brdpTokens.ValidateIgnoringExpiry(token);
            if (claimsIgnoringExpiry is null) return false; // invalid signature — auth middleware rejects
            claims = claimsIgnoringExpiry;
            return true; // expired → reactive refresh
        }

        var expiry    = GetExpiry(token);
        if (expiry is null) return false;

        var remaining = expiry.Value - DateTimeOffset.UtcNow;
        return remaining < _options.ProactiveRefreshThreshold; // near expiry → proactive refresh
    }

    private static BrdpTokenClaims SessionToClaims(RedisSession session) => new()
    {
        Sub       = session.UserCode,
        UserCode  = session.UserCode,
        Username  = session.Username,
        FirstName = session.FirstName,
        LastName  = session.LastName,
    };

    private static string? ExtractBearerToken(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) ||
            !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;
        return header["Bearer ".Length..].Trim();
    }

    private static DateTimeOffset? GetExpiry(string token)
    {
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            return new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
        }
        catch { return null; }
    }

    private static bool ShouldSkip(PathString path)
    {
        foreach (var p in _skipPaths)
            if (path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
