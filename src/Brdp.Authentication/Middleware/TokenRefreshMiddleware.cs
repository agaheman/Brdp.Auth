using System.IdentityModel.Tokens.Jwt;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Middleware;

/// <summary>
/// Intercepts requests to transparently refresh the BrdpToken when:
///   A) The token is expired (reactive refresh).
///   B) The remaining lifetime is below <see cref="AuthenticationOptions.ProactiveRefreshThreshold"/> (proactive refresh).
///
/// Registration order (in <c>Program.cs</c>):
///   1. <see cref="TokenRefreshMiddleware"/>  ← runs first, may replace token
///   2. <see cref="BrdpAuthenticationMiddleware"/>  ← validates the (possibly new) token
///
/// When a refresh succeeds the new BrdpToken is returned in the
/// <c>X-New-BrdpToken</c> response header. The SPA must detect this header
/// and replace its stored token.
///
/// If the SSO refresh token is also expired → 401 with <c>X-Auth-Error: refresh_expired</c>.
/// </summary>
public sealed class TokenRefreshMiddleware
{
    private readonly RequestDelegate                    _next;
    private readonly IBrdpTokenService                  _brdpTokens;
    private readonly ISessionService                    _sessions;
    private readonly ISsoTokenService                   _ssoTokens;
    private readonly AuthenticationOptions              _options;
    private readonly ILogger<TokenRefreshMiddleware>    _logger;

    public const string NewTokenHeader  = "X-New-BrdpToken";
    public const string AuthErrorHeader = "X-Auth-Error";

    private static readonly HashSet<string> _skipPaths =
    [
        "/auth/login",
        "/auth/signin-callback",
        "/auth/signout-callback",
        "/auth/refresh",          // avoid recursion — this endpoint handles its own expired tokens
        "/signin-oidc",           // ASP.NET Core OIDC middleware internal callback
        "/signout-callback-oidc", // ASP.NET Core OIDC middleware internal signout
        "/health",
    ];

    public TokenRefreshMiddleware(
        RequestDelegate                     next,
        IBrdpTokenService                   brdpTokens,
        ISessionService                     sessions,
        ISsoTokenService                    ssoTokens,
        IOptions<AuthenticationOptions>     options,
        ILogger<TokenRefreshMiddleware>     logger)
    {
        _next       = next;
        _brdpTokens = brdpTokens;
        _sessions   = sessions;
        _ssoTokens  = ssoTokens;
        _options    = options.Value;
        _logger     = logger;
    }

    public async Task InvokeAsync(HttpContext context)
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

        // Check if refresh is needed (expired OR proactive threshold)
        if (!NeedsRefresh(rawToken, out var claims))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation(
            "Token refresh triggered for {Username}.", claims?.Username ?? "unknown");

        var newToken = await RefreshAsync(claims, context.RequestAborted).ConfigureAwait(false);

        if (newToken is null)
        {
            // Refresh token expired — user must re-login.
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AuthErrorHeader] = "refresh_expired";
            return;
        }

        // Replace the token in the current request so BrdpAuthenticationMiddleware validates
        // the freshly issued token, not the expired one.
        context.Request.Headers.Authorization = $"Bearer {newToken}";

        // Signal the SPA to store the new token.
        context.Response.Headers[NewTokenHeader] = newToken;

        await _next(context).ConfigureAwait(false);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private bool NeedsRefresh(string token, out BrdpTokenClaims? claims)
    {
        // First try normal validation (checks expiry).
        claims = _brdpTokens.Validate(token);

        if (claims is null)
        {
            // Could be expired or invalid signature — try ignoring expiry to get claims.
            var claimsIgnoringExpiry = _brdpTokens.ValidateIgnoringExpiry(token);
            if (claimsIgnoringExpiry is null)
                return false; // Completely invalid signature — let auth middleware reject it.

            claims = claimsIgnoringExpiry;
            return true; // Expired token → reactive refresh.
        }

        // Token is valid — check proactive threshold.
        var expiry = GetExpiry(token);
        if (expiry is null) return false;

        var remaining = expiry.Value - DateTimeOffset.UtcNow;
        return remaining < _options.ProactiveRefreshThreshold;
    }

    private async Task<string?> RefreshAsync(BrdpTokenClaims? claims, CancellationToken ct)
    {
        if (claims is null) return null;

        var session = await _sessions.GetByUsernameAsync(claims.Username, ct).ConfigureAwait(false);
        if (session is null)
        {
            _logger.LogWarning("No session found during refresh for {Username}.", claims.Username);
            return null;
        }

        var ssoResponse = await _ssoTokens.RefreshAsync(session.SsoRefreshToken, ct).ConfigureAwait(false);
        if (ssoResponse is null)
        {
            _logger.LogWarning("SSO refresh failed for {Username}.", claims.Username);
            return null;
        }

        // Update Redis session with new tokens.
        session.SsoAccessToken     = ssoResponse.AccessToken;
        session.SsoRefreshToken    = ssoResponse.RefreshToken;
        session.AccessTokenExpiry  = ssoResponse.AccessTokenExpiry;
        session.RefreshTokenExpiry = ssoResponse.RefreshTokenExpiry;

        await _sessions.UpdateAsync(session, ct).ConfigureAwait(false);

        // Issue new BrdpToken — expiry aligned to new SsoAccessToken expiry.
        var newClaims = new BrdpTokenClaims
        {
            Sub       = session.UserCode,
            UserCode  = session.UserCode,
            Username  = session.Username,
            FirstName = session.FirstName,
            LastName  = session.LastName,
        };

        return _brdpTokens.Issue(newClaims, ssoResponse.AccessTokenExpiry);
    }

    private static string? ExtractBearerToken(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
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
