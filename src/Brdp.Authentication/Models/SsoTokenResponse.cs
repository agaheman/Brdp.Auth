using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// Deserialized response from the SSO token / refresh / upgrade endpoints.
/// </summary>
public sealed class SsoTokenResponse
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; init; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; init; }

    /// <summary>Computed from <see cref="ExpiresIn"/> at parse time.</summary>
    public DateTimeOffset AccessTokenExpiry  => DateTimeOffset.UtcNow.AddSeconds(ExpiresIn);

    /// <summary>Computed from <see cref="RefreshExpiresIn"/> at parse time.</summary>
    public DateTimeOffset RefreshTokenExpiry => DateTimeOffset.UtcNow.AddSeconds(RefreshExpiresIn);
}
