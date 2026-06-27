using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The <b>SsoToken</b> half of a cached session — the raw TPS SSO token pair and their
/// expiries. Stored server-side only; never sent to the SPA. The token strings are
/// encrypted when <c>EncryptTokensAtRest = true</c>.
/// </summary>
public sealed class SsoTokenData
{
    /// <summary>SSO access token (JWT). Stored encrypted in production.</summary>
    [JsonPropertyName("accessToken")]
    public required string AccessToken { get; set; }

    /// <summary>SSO refresh token. Stored encrypted in production.</summary>
    [JsonPropertyName("refreshToken")]
    public required string RefreshToken { get; set; }

    [JsonPropertyName("accessTokenExpiry")]
    public required DateTimeOffset AccessTokenExpiry { get; set; }

    [JsonPropertyName("refreshTokenExpiry")]
    public required DateTimeOffset RefreshTokenExpiry { get; set; }
}
