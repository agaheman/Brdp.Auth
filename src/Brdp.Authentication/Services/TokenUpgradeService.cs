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
                    .UpgradeAsync(session.SsoAccessToken, clientClaims, innerCt)
                    .ConfigureAwait(false);

                if (upgraded is null)
                    throw new InvalidOperationException(
                        $"SSO upgrade_token failed for user '{username}'.");

                // Treat the upgraded token as the new authoritative token: recompute every
                // session prop from the token itself rather than the (partial) response.
                var branchCode   = SsoAccessTokenParser.ExtractBranchCode(upgraded.AccessToken);
                var accessExpiry = SsoAccessTokenParser.ExtractExpiry(upgraded.AccessToken)
                                   ?? upgraded.AccessTokenExpiry;

                session.SsoAccessToken    = upgraded.AccessToken;
                session.AccessTokenExpiry = accessExpiry;

                // Branch reflects the new token's claim (authoritative).
                session.BranchCode   = branchCode;
                session.IsBranchUser = !string.IsNullOrEmpty(branchCode);

                // Refresh token: the upgrade_token grant reuses the existing refresh token
                // and does not return refresh_expires_in. Adopt a new refresh token only if
                // one is returned, and keep a valid (future) refresh expiry so the session
                // TTL (= RefreshTokenExpiry - now) stays positive and the save is not skipped.
                if (!string.IsNullOrWhiteSpace(upgraded.RefreshToken))
                    session.SsoRefreshToken = upgraded.RefreshToken;
                if (upgraded.RefreshTokenExpiry > DateTimeOffset.UtcNow)
                    session.RefreshTokenExpiry = upgraded.RefreshTokenExpiry;

                await _sessions.UpdateAsync(session, innerCt).ConfigureAwait(false);

                // Reissue BrdpToken aligned to the new access-token expiry.
                var claims = new BrdpTokenClaims
                {
                    Sub       = session.UserCode,
                    UserCode  = session.UserCode,
                    Username  = session.Username,
                    FirstName = session.FirstName,
                    LastName  = session.LastName,
                };

                var newBrdpToken = _brdpTokens.Issue(claims, accessExpiry);

                _logger.LogInformation(
                    "Token upgrade completed for {Username} (branch {BranchCode}, accessExpiry {Expiry:o}).",
                    username, session.BranchCode ?? "none", accessExpiry);

                return new TokenUpgradeResult
                {
                    BrdpToken         = newBrdpToken,
                    AccessTokenExpiry = accessExpiry,
                    BranchCode        = session.BranchCode,
                };
            },
            ct: ct).ConfigureAwait(false);

        return result
            ?? throw new InvalidOperationException(
                $"No active session found for user '{username}'. Cannot upgrade token.");
    }
}
