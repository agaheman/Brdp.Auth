using Brdp.Authentication.Models;

namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Wraps all HTTP calls to the SSO (TPS) server.
/// </summary>
public interface ISsoTokenService
{
    /// <summary>
    /// Exchange a refresh token for a new access/refresh token pair.
    /// Returns <c>null</c> when the refresh token is expired or revoked.
    /// </summary>
    Task<SsoTokenResponse?> RefreshAsync(string refreshToken, CancellationToken ct = default);

    /// <summary>
    /// Call the SSO <c>upgrade_token</c> grant to obtain a token enriched with the given
    /// client claims (e.g. branch info). The claims are echoed into the new token.
    /// </summary>
    Task<SsoTokenResponse?> UpgradeAsync(
        string accessToken,
        IReadOnlyDictionary<string, object?> clientClaims,
        CancellationToken ct = default);

    /// <summary>
    /// Revoke the access token at the SSO server (logout).
    /// </summary>
    Task RevokeAsync(string accessToken, CancellationToken ct = default);
}
