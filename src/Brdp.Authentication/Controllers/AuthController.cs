using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using AuthenticationOptions = Brdp.Authentication.Configuration.AuthenticationOptions;

// Disambiguate from Microsoft.AspNetCore.Authentication.AuthenticationOptions,
// which the OIDC handler brings into scope via the `using` above.
namespace Brdp.Authentication.Controllers;

/// <summary>
/// OIDC Authorization-Code flow surface for the BFF.
///
/// Action names follow the OIDC/OAuth2 specification terminology and ASP.NET Core Identity conventions:
///
///   GET  /auth/SignIn             SignIn          — initiates OIDC Authorization-Code challenge
///   GET  /auth/SignInCallback     SignInCallback  — OIDC code exchange; creates session + issues BrdpToken
///   GET  /auth/userinfo           UserInfo        — mirrors the OIDC userinfo endpoint semantics
///   POST /auth/refresh-token      RefreshToken    — explicit token rotation (RFC 6749 §6)
///   POST /auth/SignOut            SignOut         — revoke + delete session + trigger OIDC end_session
///   GET  /auth/SignOutCallback    SignOutCallback — post-SSO-signout landing (OIDC post_logout_redirect_uri)
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
        ISessionService                   sessions,
        IBrdpTokenService                 brdpTokens,
        ISsoTokenService                  ssoTokens,
        IAuthenticatedUserContextAccessor accessor,
        IOptions<AuthenticationOptions>   authOptions)
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
    /// Challenges the OIDC scheme, which redirects the browser to the TPS SSO
    /// authorization endpoint. After authentication SSO redirects to <c>/auth/SignInCallback</c>.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("SignIn")]
    public IActionResult SignIn([FromQuery] string returnUrl = "/")
        => Challenge(
            new AuthenticationProperties
            {
                RedirectUri = $"/auth/SignInCallback?returnUrl={Uri.EscapeDataString(returnUrl)}"
            },
            SsoAuthenticationDefaults.OidcScheme);

    // ── Callback ──────────────────────────────────────────────────────────────

    /// <summary>
    /// OIDC Authorization-Code callback (post_login_redirect_uri).
    /// The OIDC middleware has already exchanged the code for tokens and written
    /// them into the cookie session. This action reads those tokens, creates the
    /// Redis session, and issues a BrdpToken for the SPA.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("SignInCallback")]
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

        var accessTokenExpiry = DateTimeOffset.TryParse(
                result.Properties?.GetTokenValue("expires_at"), out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow + _authOptions.AccessTokenFallbackLifetime;

        // Prefer the SSO's real refresh-token lifetime (captured by the OIDC
        // OnTokenResponseReceived event) so the Redis TTL matches it; fall back to
        // the configured RefreshTokenLifetime only when SSO does not advertise it.
        var refreshTokenExpiry =
            result.Properties is not null
            && result.Properties.Items.TryGetValue("sso.refresh_expires_in", out var refreshExpiresInRaw)
            && int.TryParse(refreshExpiresInRaw, out var refreshExpiresIn)
                ? DateTimeOffset.UtcNow.AddSeconds(refreshExpiresIn)
                : DateTimeOffset.UtcNow + _authOptions.RefreshTokenLifetime;

        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

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

        // Browser SPA flow: when returnUrl points at a local page, redirect there
        // and hand the BrdpToken back in the URL fragment (#token=…), which never
        // travels to a server or appears in access logs. Url.IsLocalUrl rejects
        // absolute/off-site URLs, so this cannot be abused as an open redirect.
        if (!string.IsNullOrWhiteSpace(returnUrl) && returnUrl != "/" && Url.IsLocalUrl(returnUrl))
        {
            var separator   = returnUrl.Contains('#') ? '&' : '#';
            var redirectUrl =
                $"{returnUrl}{separator}token={Uri.EscapeDataString(brdpToken)}" +
                $"&expiresAt={Uri.EscapeDataString(accessTokenExpiry.ToString("O"))}" +
                $"&isBranchUser={(isBranchUser ? "true" : "false")}";

            return Redirect(redirectUrl);
        }

        // Programmatic callers (returnUrl omitted or "/") keep the JSON contract.
        return Ok(new
        {
            token        = brdpToken,
            isBranchUser,
            expiresAt    = accessTokenExpiry,
            returnUrl,
        });
    }

    // ── UserInfo ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the authenticated user's identity and session metadata.
    /// Mirrors the OIDC <c>userinfo</c> endpoint semantics (RFC 5849).
    /// </summary>
    [HttpGet("userinfo")]
    public IActionResult UserInfo()
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

    // ── RefreshToken ──────────────────────────────────────────────────────────

    /// <summary>
    /// Explicit token rotation endpoint (RFC 6749 §6).
    ///
    /// Accepts an expired (but signature-valid) BrdpToken in the Authorization header.
    /// Uses a distributed Redis lock to guarantee only one SSO refresh call per user
    /// across all concurrent SPA tabs/requests — preventing double-consumption of the
    /// single-use SSO refresh token.
    ///
    /// The <see cref="Middleware.TokenRefreshMiddleware"/> handles transparent rotation on every
    /// request. Use this endpoint for SPA-initiated explicit refresh flows.
    /// </summary>
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(
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

        var newBrdpToken = await _sessions.ExecuteWithRefreshLockAsync<string>(
            claims.Username,
            async (session, innerCt) =>
            {
                // Guard: if another tab already refreshed, the session's AccessToken
                // is already fresh — reuse it without hitting SSO again.
                if (session.AccessTokenExpiry > DateTimeOffset.UtcNow + _authOptions.ProactiveRefreshThreshold)
                {
                    return _brdpTokens.Issue(SessionToClaims(session), session.AccessTokenExpiry);
                }

                var ssoResponse = await _ssoTokens
                    .RefreshAsync(session.SsoRefreshToken, innerCt)
                    .ConfigureAwait(false);

                if (ssoResponse is null) return null;

                session.SsoAccessToken     = ssoResponse.AccessToken;
                session.SsoRefreshToken    = ssoResponse.RefreshToken;
                session.AccessTokenExpiry  = ssoResponse.AccessTokenExpiry;
                session.RefreshTokenExpiry = ssoResponse.RefreshTokenExpiry;

                await _sessions.UpdateAsync(session, innerCt).ConfigureAwait(false);

                return _brdpTokens.Issue(SessionToClaims(session), ssoResponse.AccessTokenExpiry);
            },
            ct: ct).ConfigureAwait(false);

        if (newBrdpToken is null)
            return Unauthorized(new { error = "refresh_failed" });

        return Ok(new { token = newBrdpToken });
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revokes the SSO access token, deletes the Redis session, and triggers
    /// the OIDC end_session flow. SSO redirects the browser to <c>/auth/SignOutCallback</c>
    /// after completing global sign-out.
    /// </summary>
    [HttpPost("SignOut")]
    public async Task<IActionResult> SignOut(CancellationToken ct = default)
    {
        var user    = _accessor.GetRequiredContext();
        var session = await _sessions.GetByUsernameAsync(user.Username, ct).ConfigureAwait(false);

        if (session is not null)
        {
            await _ssoTokens.RevokeAsync(session.SsoAccessToken, ct).ConfigureAwait(false);
            await _sessions.DeleteAsync(user.Username, ct).ConfigureAwait(false);
        }

        return SignOut(
            new AuthenticationProperties { RedirectUri = "/auth/SignOutCallback" },
            SsoAuthenticationDefaults.CookieScheme,
            SsoAuthenticationDefaults.OidcScheme);
    }

    // ── SignedOut ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Post-logout landing page (OIDC post_logout_redirect_uri).
    /// SSO redirects here after completing global sign-out.
    /// SPA should detect this response and navigate to the login page.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("SignOutCallback")]
    public IActionResult SignOutCallback() => Ok(new { signedOut = true });

    // ── Private helpers ───────────────────────────────────────────────────────

    private static BrdpTokenClaims SessionToClaims(RedisSession session) => new()
    {
        Sub       = session.UserCode,
        UserCode  = session.UserCode,
        Username  = session.Username,
        FirstName = session.FirstName,
        LastName  = session.LastName,
    };
}
