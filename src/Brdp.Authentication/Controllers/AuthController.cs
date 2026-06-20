using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Controllers;

/// <summary>
/// OIDC Authorization-Code flow surface for the BFF.
///
/// Route map:
///   GET  /auth/login             — Challenge: redirects browser to TPS SSO login page
///   GET  /auth/signin-callback   — OIDC callback: exchanges code → tokens, creates Redis session, issues BrdpToken
///   GET  /auth/me                — Identity: returns current user context
///   POST /auth/refresh           — Token refresh: accepts expired BrdpToken, returns new one
///   POST /auth/logout            — Logout: revokes SSO token, deletes Redis session, signs out cookie
///   GET  /auth/signout-callback  — Post-SSO-signout landing page
/// </summary>
[ApiController]
[Route("auth")]
public sealed class AuthController : ControllerBase
{
    private readonly ISessionService                   _sessions;
    private readonly IBrdpTokenService                 _brdpTokens;
    private readonly ISsoTokenService                  _ssoTokens;
    private readonly IAuthenticatedUserContextAccessor _accessor;
    private readonly AuthenticationOptions             _authOptions;

    public AuthController(
        ISessionService                    sessions,
        IBrdpTokenService                  brdpTokens,
        ISsoTokenService                   ssoTokens,
        IAuthenticatedUserContextAccessor  accessor,
        IOptions<AuthenticationOptions>    authOptions)
    {
        _sessions    = sessions;
        _brdpTokens  = brdpTokens;
        _ssoTokens   = ssoTokens;
        _accessor    = accessor;
        _authOptions = authOptions.Value;
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Initiates the OIDC Authorization-Code flow.
    /// Redirects the browser to TPS SSO. After successful login, SSO redirects
    /// back to <c>/auth/signin-callback</c>.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("login")]
    public IActionResult Login([FromQuery] string returnUrl = "/")
        => Challenge(
            new AuthenticationProperties
            {
                RedirectUri = $"/auth/signin-callback?returnUrl={Uri.EscapeDataString(returnUrl)}"
            },
            SsoAuthenticationDefaults.OidcScheme);

    // ── SignInCallback ─────────────────────────────────────────────────────────

    /// <summary>
    /// OIDC signin callback — invoked by the browser after SSO redirects back.
    /// Reads the authenticated principal and SSO tokens from the cookie established
    /// by the OIDC middleware, persists a Redis session, and issues a BrdpToken for the SPA.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("signin-callback")]
    public async Task<IActionResult> SignInCallback(
        [FromQuery] string returnUrl = "/",
        CancellationToken ct = default)
    {
        var result = await HttpContext.AuthenticateAsync(SsoAuthenticationDefaults.CookieScheme);
        if (!result.Succeeded)
            return Unauthorized(new { error = "oidc_authentication_failed" });

        var principal = result.Principal!;

        var userCode = principal.FindFirst("userCode")?.Value
                    ?? principal.FindFirst("sub")?.Value
                    ?? throw new InvalidOperationException("userCode/sub claim missing from SSO token.");

        var username = principal.FindFirst("preferred_username")?.Value
                    ?? principal.Identity?.Name
                    ?? throw new InvalidOperationException("preferred_username claim missing from SSO token.");

        var firstName    = principal.FindFirst("given_name")?.Value  ?? string.Empty;
        var lastName     = principal.FindFirst("family_name")?.Value ?? string.Empty;
        var isBranchUser = bool.TryParse(principal.FindFirst("isBranchUser")?.Value, out var b) && b;

        var ssoAccessToken  = result.Properties?.GetTokenValue("access_token")
                           ?? throw new InvalidOperationException("access_token not stored by OIDC middleware.");
        var ssoRefreshToken = result.Properties?.GetTokenValue("refresh_token") ?? string.Empty;

        var accessExpiryRaw = result.Properties?.GetTokenValue("expires_at");
        var accessTokenExpiry = DateTimeOffset.TryParse(accessExpiryRaw, out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow.AddHours(1);

        var refreshTokenExpiry = DateTimeOffset.UtcNow.AddHours(8);
        var clientIp           = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (_authOptions.SingleSessionEnabled)
            await _sessions.DeleteAsync(username, ct).ConfigureAwait(false);

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

        var brdpToken = _brdpTokens.Issue(
            new BrdpTokenClaims
            {
                Sub       = userCode,
                UserCode  = userCode,
                Username  = username,
                FirstName = firstName,
                LastName  = lastName,
            },
            accessTokenExpiry);

        return Ok(new
        {
            token        = brdpToken,
            isBranchUser,
            expiresAt    = accessTokenExpiry,
            returnUrl,
        });
    }

    // ── Me ────────────────────────────────────────────────────────────────────

    /// <summary>Returns the current authenticated user's identity and session metadata.</summary>
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

    // ── Refresh ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Explicit token refresh endpoint.
    /// Accepts an expired (but signature-valid) BrdpToken in the Authorization header,
    /// calls SSO refresh, updates the Redis session, and returns a new BrdpToken.
    /// The middleware (<see cref="Middleware.TokenRefreshMiddleware"/>) handles transparent
    /// refresh automatically on every request; this endpoint is for SPA-driven refresh flows.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(
        [FromHeader(Name = "Authorization")] string? authorization,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Unauthorized(new { error = "missing_token" });

        var expiredToken = authorization["Bearer ".Length..].Trim();

        var claims = _brdpTokens.ValidateIgnoringExpiry(expiredToken);
        if (claims is null)
            return Unauthorized(new { error = "invalid_token" });

        var session = await _sessions.GetByUsernameAsync(claims.Username, ct).ConfigureAwait(false);
        if (session is null)
            return Unauthorized(new { error = "session_not_found" });

        var ssoResponse = await _ssoTokens.RefreshAsync(session.SsoRefreshToken, ct).ConfigureAwait(false);
        if (ssoResponse is null)
            return Unauthorized(new { error = "refresh_token_expired" });

        session.SsoAccessToken     = ssoResponse.AccessToken;
        session.SsoRefreshToken    = ssoResponse.RefreshToken;
        session.AccessTokenExpiry  = ssoResponse.AccessTokenExpiry;
        session.RefreshTokenExpiry = ssoResponse.RefreshTokenExpiry;

        await _sessions.UpdateAsync(session, ct).ConfigureAwait(false);

        var newBrdpToken = _brdpTokens.Issue(
            new BrdpTokenClaims
            {
                Sub       = session.UserCode,
                UserCode  = session.UserCode,
                Username  = session.Username,
                FirstName = session.FirstName,
                LastName  = session.LastName,
            },
            ssoResponse.AccessTokenExpiry);

        return Ok(new
        {
            token     = newBrdpToken,
            expiresAt = ssoResponse.AccessTokenExpiry,
        });
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revokes the SSO access token, deletes the Redis session, and initiates
    /// the OIDC sign-out flow. The browser is redirected to SSO for global sign-out,
    /// which then calls back to <c>/auth/signout-callback</c>.
    /// </summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct = default)
    {
        var user    = _accessor.GetRequiredContext();
        var session = await _sessions.GetByUsernameAsync(user.Username, ct).ConfigureAwait(false);

        if (session is not null)
        {
            await _ssoTokens.RevokeAsync(session.SsoAccessToken, ct).ConfigureAwait(false);
            await _sessions.DeleteAsync(user.Username, ct).ConfigureAwait(false);
        }

        return SignOut(
            new AuthenticationProperties { RedirectUri = "/auth/signout-callback" },
            SsoAuthenticationDefaults.CookieScheme,
            SsoAuthenticationDefaults.OidcScheme);
    }

    // ── SignOutCallback ───────────────────────────────────────────────────────

    /// <summary>
    /// Post-logout landing page — SSO redirects here after completing global sign-out.
    /// The SPA should intercept this and redirect to the login page.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("signout-callback")]
    public IActionResult SignOutCallback() => Ok(new { signedOut = true });
}
