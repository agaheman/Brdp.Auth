using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Infrastructure;
using Brdp.Authentication.Models;

namespace Brdp.Authentication.Services;

/// <summary>
/// Implements <see cref="ISsoTokenService"/> by delegating to the typed <see cref="SsoHttpClient"/>.
/// This indirection allows services to depend on the interface while the HTTP concerns
/// remain isolated in the infrastructure layer.
/// </summary>
internal sealed class SsoTokenService : ISsoTokenService
{
    private readonly SsoHttpClient _client;

    public SsoTokenService(SsoHttpClient client) => _client = client;

    public Task<SsoTokenResponse?> RefreshAsync(string refreshToken, CancellationToken ct = default) =>
        _client.RefreshTokenAsync(refreshToken, ct);

    public Task<SsoTokenResponse?> UpgradeAsync(string accessToken, string branchCode, CancellationToken ct = default) =>
        _client.UpgradeTokenAsync(accessToken, branchCode, ct);

    public Task RevokeAsync(string accessToken, CancellationToken ct = default) =>
        _client.RevokeTokenAsync(accessToken, ct);
}
