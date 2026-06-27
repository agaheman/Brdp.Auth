using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Infrastructure;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;

namespace Brdp.Authentication.Services;

/// <summary>
/// Implements the reusable <see cref="ITokenUpgradeService"/> feature.
///
/// Each upgrade runs under the same single-flight refresh lock as token refresh — the
/// SSO tokens are single-use, so an upgrade must never race a concurrent refresh/upgrade
/// on the same session. Steps:
///   1. Call SSO <c>upgrade_token</c> with the current access token + client claims.
///   2. Persist the rotated SSO tokens (and any branch_code) to the Redis session.
///   3. Issue a new BrdpToken aligned to the upgraded access-token expiry.
/// </summary>
internal sealed class TokenUpgradeService : ITokenUpgradeService
{
    private readonly ISessionService              _sessions;
    private readonly ISsoTokenService             _ssoTokens;
    private readonly IBrdpTokenService            _brdpTokens;
    private readonly ILogger<TokenUpgradeService> _logger;

    public TokenUpgradeService(
        ISessionService               sessions,
        ISsoTokenService              ssoTokens,
        IBrdpTokenService             brdpTokens,
        ILogger<TokenUpgradeService>  logger)
    {
        _sessions   = sessions;
        _ssoTokens  = ssoTokens;
        _brdpTokens = brdpTokens;
        _logger     = logger;
    }

    public async Task<TokenUpgradeResult> UpgradeAsync(
        string username,
        IReadOnlyDictionary<string, object?> clientClaims,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentNullException.ThrowIfNull(clientClaims);

        _logger.LogInformation(
            "Token upgrade started for {Username} with claims [{Claims}]",
            username, string.Join(", ", clientClaims.Keys));

        var result = await _sessions.ExecuteWithRefreshLockAsync<TokenUpgradeResult>(
            username,
            async (session, innerCt) =>
            {
                var upgraded = await _ssoTokens
                    .UpgradeAsync(session.Sso.AccessToken, clientClaims, innerCt)
                    .ConfigureAwait(false);

                if (upgraded is null)
                    throw new InvalidOperationException(
                        $"SSO upgrade_token failed for user '{username}'.");

                // Treat the upgraded token as the new authoritative token: recompute the
                // SSO-token half from the token itself rather than the (partial) response.
                var branchCode   = SsoAccessTokenParser.ExtractBranchCode(upgraded.AccessToken);
                var accessExpiry = SsoAccessTokenParser.ExtractExpiry(upgraded.AccessToken)
                                   ?? upgraded.AccessTokenExpiry;

                // ── SSO token half ────────────────────────────────────────────
                session.Sso.AccessToken       = upgraded.AccessToken;
                session.Sso.AccessTokenExpiry = accessExpiry;
                session.Sso.BranchCode        = branchCode;
                session.Sso.UserInfo          = SsoAccessTokenParser.ExtractUserInfo(upgraded.AccessToken)
                                                ?? session.Sso.UserInfo;

                // The upgrade_token grant reuses the existing refresh token and omits
                // refresh_expires_in. Adopt a new refresh token only if returned, and keep a
                // valid (future) refresh expiry so the session TTL stays positive.
                if (!string.IsNullOrWhiteSpace(upgraded.RefreshToken))
                    session.Sso.RefreshToken = upgraded.RefreshToken;
                if (upgraded.RefreshTokenExpiry > DateTimeOffset.UtcNow)
                    session.Sso.RefreshTokenExpiry = upgraded.RefreshTokenExpiry;

                // ── API Gateway token half (what the UI uses) ─────────────────
                session.ApiGateway.BranchCode   = branchCode;
                session.ApiGateway.IsBranchUser = !string.IsNullOrEmpty(branchCode);
                session.ApiGateway.ExpiresAt    = accessExpiry;

                await _sessions.UpdateAsync(session, innerCt).ConfigureAwait(false);

                // Reissue BrdpToken from the API Gateway half, aligned to the new expiry.
                var claims = new BrdpTokenClaims
                {
                    Sub       = session.ApiGateway.UserCode,
                    UserCode  = session.ApiGateway.UserCode,
                    Username  = session.ApiGateway.Username,
                    FirstName = session.ApiGateway.FirstName,
                    LastName  = session.ApiGateway.LastName,
                };

                var newBrdpToken = _brdpTokens.Issue(claims, accessExpiry);

                _logger.LogInformation(
                    "Token upgrade completed for {Username} (branch {BranchCode}, accessExpiry {Expiry:o}).",
                    username, session.ApiGateway.BranchCode ?? "none", accessExpiry);

                return new TokenUpgradeResult
                {
                    BrdpToken         = newBrdpToken,
                    AccessTokenExpiry = accessExpiry,
                    BranchCode        = session.ApiGateway.BranchCode,
                };
            },
            ct: ct).ConfigureAwait(false);

        return result
            ?? throw new InvalidOperationException(
                $"No active session found for user '{username}'. Cannot upgrade token.");
    }
}
