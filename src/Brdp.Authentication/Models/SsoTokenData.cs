using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The <b>SSO token</b> half of a cached session — the heavy, claim-rich token issued
/// by TPS SSO, with all of its properties. Stored server-side only; never sent to the SPA.
/// The tokens are stored encrypted when <c>EncryptTokensAtRest = true</c>.
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

    /// <summary>Top-level <c>branch_code</c> claim — present after a branch upgrade.</summary>
    [JsonPropertyName("branchCode")]
    public string? BranchCode { get; set; }

    /// <summary>Full identity payload from the access token's nested <c>user_info</c> claim.</summary>
    [JsonPropertyName("userInfo")]
    public SsoUserInfo? UserInfo { get; set; }
}
