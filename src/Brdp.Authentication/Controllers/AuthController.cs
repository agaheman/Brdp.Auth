using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Middleware;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Controllers;

/// <summary>
/// Handles the OIDC Authorization-Code flow with TPS SSO,
/// BrdpToken issuance, token refresh, and logout.
///
/// Endpoints:
///   GET  /auth/login    — initiates OIDC challenge (anonymous)
///   GET  /auth/callback — OIDC callback; issues BrdpToken + Redis session
///   GET  /auth/me       — returns current user identity
///   POST /auth/refresh  — explicit refresh (SPA can call proactively)
///   GET  /auth/logout   — clears session + OIDC sign-out
/// </summary>
[ApiController]
[Route("auth")]
public sealed class AuthController : ControllerBase
{
    private readonly ISessionService                    _sessions;
    private readonly IBrdpTokenService                  _brdpTokens;
    private readonly ISsoTokenService                   _ssoTokens;
    private readonly IAuthenticatedUserContextAccessor  _accessor;
    private readonly AuthenticationOptions              _options;
    private readonly SsoAuthenticationOptions           _ssoOptions;

    public AuthController(
        ISessionService                     sessions,
        IBrdpTokenService                   brdpTokens,
        ISsoTokenService                    ssoTokens,
        IAuthenticatedUserContextAccessor   accessor,
        IOptions<AuthenticationOptions>     options,
        IOptions<SsoAuthenticationOptions>  ssoOptions)
    {
        _sessions   = sessions;
        _brdpTokens = brdpTokens;
        _ssoTokens  = ssoTokens;
        _accessor   = accessor;
        _options    = options.Value;
        _ssoOptions = ssoOptions.Value;
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    /// <summary>Redirects the browser to the TPS SSO login page.</summary>
    [HttpGet("login")]
    [AllowAnonymous]
    public IActionResult Login([FromQuery] string returnUrl = "/")
        => Challenge(
            new AuthenticationProperties { RedirectUri = $"/auth/callback?returnUrl={Uri.EscapeDataString(returnUrl)}" },
            SsoAuthenticationDefaults.OidcScheme);

    // ── OIDC Callback ─────────────────────────────────────────────────────────

    /// <summary>
    /// Called by ASP.NET Core OIDC middleware after the SSO login completes.
    /// Extracts SSO tokens from the auth result, creates a Redis session, and issues a BrdpToken.
    /// </summary>
    [HttpGet("callback")]
    [AllowAnonymous]
    public async Task<IActionResult> Callback(
        [FromQuery] string returnUrl = "/",
        CancellationToken ct = default)
    {
        var result = await HttpContext.AuthenticateAsync(SsoAuthenticationDefaults.CookieScheme);
        if (!result.Succeeded)
            return Unauthorized(new { error = "oidc_authentication_failed" });

        var principal = result.Principal;

        // Extract identity claims set by the OIDC middleware.
        var userCode  = principal.FindFirst("userCode")?.Value
                     ?? principal.FindFirst("sub")?.Value
                     ?? throw new InvalidOperationException("userCode/sub claim not found in SSO token.");
        var username  = principal.FindFirst("preferred_username")?.Value
                     ?? principal.Identity?.Name
                     ?? throw new InvalidOperationException("preferred_username claim not found.");
        var firstName = principal.FindFirst("given_name")?.Value ?? string.Empty;
        var lastName  = principal.FindFirst("family_name")?.Value ?? string.Empty;
        var isBranchUser = bool.TryParse(principal.FindFirst("isBranchUser")?.Value, out var b) && b;

        // Retrieve SSO tokens stored by the OIDC middleware.
        var ssoAccessToken  = result.Properties?.GetTokenValue("access_token")
                           ?? throw new InvalidOperationException("access_token not available.");
        var ssoRefreshToken = result.Properties?.GetTokenValue("refresh_token") ?? string.Empty;

        // Parse expiry from the stored token metadata.
        var accessExpiryRaw  = result.Properties?.GetTokenValue("expires_at");
        var accessTokenExpiry = DateTimeOffset.TryParse(accessExpiryRaw, out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow.AddHours(1);

        // Rough refresh token lifetime (SSO doesn't always expose this — default to 8 h).
        var refreshTokenExpiry = DateTimeOffset.UtcNow.AddHours(8);

        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // SingleSession: invalidate any existing session for this username.
        if (_options.SingleSessionEnabled)
            await _sessions.DeleteAsync(username, ct).ConfigureAwait(false);

        // Persist Redis session.
        var session = new RedisSession
        {
            UserCode           = userCode,
            Username           = username,
            FirstName          = firstName,
            LastName           = lastName,
            IsBranchUser       = isBranchUser,
            ClientIp           = clientIp,
            SsoAccessToken     = ssoAccessToken,
            SsoRefreshToken    = ssoRefreshToken,
            AccessTokenExpiry  = accessTokenExpiry,
            RefreshTokenExpiry = refreshTokenExpiry,
        };

        await _sessions.SaveAsync(session, ct).ConfigureAwait(false);

        // Issue BrdpToken aligned to SsoAccessToken expiry.
        var claims = new BrdpTokenClaims
        {
            Sub       = userCode,
            UserCode  = userCode,
            Username  = username,
            FirstName = firstName,
            LastName  = lastName,
        };

        var brdpToken = _brdpTokens.Issue(claims, accessTokenExpiry);

        // Return token to SPA. SPA stores it and attaches it as Bearer on subsequent requests.
        return Ok(new
        {
            token        = brdpToken,
            isBranchUser,
            expiresAt    = accessTokenExpiry,
            returnUrl,
        });
    }

    // ── Me ────────────────────────────────────────────────────────────────────

    /// <summary>Returns the current user identity from the authenticated context.</summary>
    [HttpGet("me")]
    public IActionResult Me()
    {
        var user = _accessor.GetRequiredContext();
        return Ok(new
        {
            user.UserCode,
            user.Username,
            user.FirstName,
            user.LastName,
            user.BranchCode,
            user.IsBranchUser,
            user.SessionId,
        });
    }

    // ── Explicit Refresh ──────────────────────────────────────────────────────

    /// <summary>
    /// Explicit refresh endpoint — SPA can call this proactively.
    /// The middleware handles transparent refresh automatically, but this endpoint
    /// provides a direct surface for SPA token management flows.
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]  // Token may already be expired when this is called.
    public async Task<IActionResult> Refresh(
        [FromHeader(Name = "Authorization")] string? authHeader,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Unauthorized(new { error = "missing_token" });

        var expiredToken = authHeader["Bearer ".Length..].Trim();

        // Allow expired tokens here — we only need the claims to locate the session.
        var claims = _brdpTokens.ValidateIgnoringExpiry(expiredToken);
        if (claims is null)
            return Unauthorized(new { error = "invalid_token" });

        var session = await _sessions.GetByUsernameAsync(claims.Username, ct).ConfigureAwait(false);
        if (session is null)
            return Unauthorized(new { error = "session_not_found" });

        var ssoResponse = await _ssoTokens.RefreshAsync(session.SsoRefreshToken, ct).ConfigureAwait(false);
        if (ssoResponse is null)
            return Unauthorized(new { error = "refresh_token_expired" });

        // Update session.
        session.SsoAccessToken     = ssoResponse.AccessToken;
        session.SsoRefreshToken    = ssoResponse.RefreshToken;
        session.AccessTokenExpiry  = ssoResponse.AccessTokenExpiry;
        session.RefreshTokenExpiry = ssoResponse.RefreshTokenExpiry;
        await _sessions.UpdateAsync(session, ct).ConfigureAwait(false);

        // Issue new BrdpToken.
        var newClaims = new BrdpTokenClaims
        {
            Sub       = session.UserCode,
            UserCode  = session.UserCode,
            Username  = session.Username,
            FirstName = session.FirstName,
            LastName  = session.LastName,
        };

        var newBrdpToken = _brdpTokens.Issue(newClaims, ssoResponse.AccessTokenExpiry);

        return Ok(new
        {
            token     = newBrdpToken,
            expiresAt = ssoResponse.AccessTokenExpiry,
        });
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Deletes the Redis session and signs out of the OIDC cookie.
    /// Also revokes the SSO access token.
    /// </summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct = default)
    {
        var user = _accessor.GetRequiredContext();

        var session = await _sessions.GetByUsernameAsync(user.Username, ct).ConfigureAwait(false);
        if (session is not null)
        {
            await _ssoTokens.RevokeAsync(session.SsoAccessToken, ct).ConfigureAwait(false);
            await _sessions.DeleteAsync(user.Username, ct).ConfigureAwait(false);
        }

        await HttpContext.SignOutAsync(SsoAuthenticationDefaults.CookieScheme).ConfigureAwait(false);

        return Ok();
    }
}
