using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// Deserialized response from the SSO token / refresh / upgrade endpoints.
/// </summary>
public sealed class SsoTokenResponse
{
    /// <summary>
    /// Captured once at construction (i.e. deserialization) so the computed expiry
    /// properties below are stable rather than drifting on every access.
    /// </summary>
    private readonly DateTimeOffset _receivedAt = DateTimeOffset.UtcNow;

    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; init; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; init; }

    /// <summary>Computed from <see cref="ExpiresIn"/> relative to the receive time.</summary>
    public DateTimeOffset AccessTokenExpiry  => _receivedAt.AddSeconds(ExpiresIn);

    /// <summary>Computed from <see cref="RefreshExpiresIn"/> relative to the receive time.</summary>
    public DateTimeOffset RefreshTokenExpiry => _receivedAt.AddSeconds(RefreshExpiresIn);
}
