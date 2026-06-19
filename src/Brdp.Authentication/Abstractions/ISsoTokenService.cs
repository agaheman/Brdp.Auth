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
    /// Call the SSO upgrade endpoint to obtain a token enriched with branch information.
    /// </summary>
    Task<SsoTokenResponse?> UpgradeAsync(string accessToken, string branchCode, CancellationToken ct = default);

    /// <summary>
    /// Revoke the access token at the SSO server (logout).
    /// </summary>
    Task RevokeAsync(string accessToken, CancellationToken ct = default);
}
