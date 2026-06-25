using Brdp.Authentication.Models;

namespace Brdp.Authentication.Abstractions;

/// <summary>
/// <b>Token Upgrade</b> — a reusable feature that enriches the current user's SSO token
/// with additional <c>client_claims</c> via the SSO <c>upgrade_token</c> grant, persists the
/// upgraded tokens back to the Redis session, and issues a fresh BrdpToken aligned to the
/// new access-token expiry.
///
/// It is idempotent and <b>repeatable</b>: call it as many times as needed to add or replace
/// claims on the live session (e.g. select a branch, then change the branch). Each call
/// rotates the SSO tokens under the single-flight refresh lock and updates the saved session.
///
/// Branch selection is one use of this feature — see <see cref="IBranchService"/>.
/// </summary>
public interface ITokenUpgradeService
{
    /// <summary>
    /// Upgrade the user's token with the given client claims and update the saved session.
    /// </summary>
    /// <param name="username">The authenticated user whose session is upgraded.</param>
    /// <param name="clientClaims">
    /// Claims to embed in the upgraded token (e.g. <c>{ ["branch_code"] = "1" }</c>).
    /// </param>
    /// <returns>The new BrdpToken and applied branch code.</returns>
    /// <exception cref="InvalidOperationException">No active session, or the SSO upgrade failed.</exception>
    Task<TokenUpgradeResult> UpgradeAsync(
        string username,
        IReadOnlyDictionary<string, object?> clientClaims,
        CancellationToken ct = default);
}
