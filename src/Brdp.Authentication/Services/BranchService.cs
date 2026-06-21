using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;

namespace Brdp.Authentication.Services;

/// <summary>
/// Orchestrates the complete branch-selection upgrade flow:
///
///   1. Load current Redis session (must exist — user is already logged in).
///   2. Call SSO <c>upgradeToken</c> with the current access token + selected branch code.
///   3. Update Redis session: new SsoTokens, branchCode, updated expiry.
///   4. Issue a new BrdpToken aligned to the new SsoAccessToken expiry.
///   5. Return the new BrdpToken to the caller — the SPA must replace the old one.
///
/// The flow is idempotent: selecting the same branch again simply re-upgrades the token.
/// </summary>
internal sealed class BranchService : IBranchService
{
    private readonly ISessionService            _sessions;
    private readonly ISsoTokenService           _ssoTokens;
    private readonly IBrdpTokenService          _brdpTokens;
    private readonly ILogger<BranchService>     _logger;

    public BranchService(
        ISessionService         sessions,
        ISsoTokenService        ssoTokens,
        IBrdpTokenService       brdpTokens,
        ILogger<BranchService>  logger)
    {
        _sessions   = sessions;
        _ssoTokens  = ssoTokens;
        _brdpTokens = brdpTokens;
        _logger     = logger;
    }

    public async Task<BranchSelectionResult> SelectBranchAsync(
        string username,
        string branchCode,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(branchCode);

        _logger.LogInformation(
            "Branch selection started for {Username} → branch {BranchCode}", username, branchCode);

        // Run under the same distributed lock as token refresh: branch upgrade rotates
        // the (single-use) SSO tokens, so it must not race a concurrent refresh on the
        // same session. The lock loads the current session and hands it to us.
        var result = await _sessions.ExecuteWithRefreshLockAsync<BranchSelectionResult>(
            username,
            async (session, innerCt) =>
            {
                // ── Step 1: Call SSO upgradeToken ────────────────────────────
                var upgraded = await _ssoTokens
                    .UpgradeAsync(session.SsoAccessToken, branchCode, innerCt)
                    .ConfigureAwait(false);

                if (upgraded is null)
                    throw new InvalidOperationException(
                        $"SSO upgrade token call failed for user '{username}' and branch '{branchCode}'. " +
                        "The branch may not be accessible to this user.");

                // ── Step 2: Update Redis session ─────────────────────────────
                session.BranchCode         = branchCode;
                session.SsoAccessToken     = upgraded.AccessToken;
                session.SsoRefreshToken    = upgraded.RefreshToken;
                session.AccessTokenExpiry  = upgraded.AccessTokenExpiry;
                session.RefreshTokenExpiry = upgraded.RefreshTokenExpiry;

                await _sessions.UpdateAsync(session, innerCt).ConfigureAwait(false);

                // ── Step 3: Issue new BrdpToken ──────────────────────────────
                // Expiry(BrdpToken) == Expiry(SsoAccessToken) — alignment invariant.
                var claims = new BrdpTokenClaims
                {
                    Sub       = session.UserCode,
                    UserCode  = session.UserCode,
                    Username  = session.Username,
                    FirstName = session.FirstName,
                    LastName  = session.LastName,
                };

                var newBrdpToken = _brdpTokens.Issue(claims, upgraded.AccessTokenExpiry);

                _logger.LogInformation(
                    "Branch selection completed for {Username} → branch {BranchCode}, new token issued.",
                    username, branchCode);

                return new BranchSelectionResult
                {
                    BrdpToken         = newBrdpToken,
                    BranchCode        = branchCode,
                    AccessTokenExpiry = upgraded.AccessTokenExpiry,
                };
            },
            ct: ct).ConfigureAwait(false);

        return result
            ?? throw new InvalidOperationException(
                $"No active session found for user '{username}'. Cannot perform branch selection.");
    }
}
