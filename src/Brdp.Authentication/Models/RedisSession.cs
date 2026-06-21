using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The payload stored in Redis under key <c>auth:session:{sha256(username)}</c>.
///
/// TTL rule: Redis TTL = RefreshTokenExpiry (not AccessTokenExpiry).
/// An expired AccessToken does NOT mean an expired session — the refresh flow
/// can restore it as long as RefreshToken is still valid.
///
/// In production (<c>EncryptTokensAtRest = true</c>), <see cref="SsoAccessToken"/>,
/// <see cref="SsoRefreshToken"/>, and any persisted BrdpToken are encrypted before write
/// and decrypted after read by <see cref="Infrastructure.RedisSessionStore"/>.
/// </summary>
public sealed class RedisSession
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("userCode")]
    public required string UserCode { get; init; }

    [JsonPropertyName("username")]
    public required string Username { get; init; }

    [JsonPropertyName("firstName")]
    public required string FirstName { get; init; }

    [JsonPropertyName("lastName")]
    public required string LastName { get; init; }

    [JsonPropertyName("isBranchUser")]
    public bool IsBranchUser { get; init; }

    /// <summary>Populated after branch selection. <c>null</c> for non-branch users.</summary>
    [JsonPropertyName("branchCode")]
    public string? BranchCode { get; set; }

    [JsonPropertyName("clientIp")]
    public required string ClientIp { get; init; }

    /// <summary>Stored encrypted in production.</summary>
    [JsonPropertyName("ssoAccessToken")]
    public required string SsoAccessToken { get; set; }

    /// <summary>Stored encrypted in production.</summary>
    [JsonPropertyName("ssoRefreshToken")]
    public required string SsoRefreshToken { get; set; }

    [JsonPropertyName("accessTokenExpiry")]
    public required DateTimeOffset AccessTokenExpiry { get; set; }

    [JsonPropertyName("refreshTokenExpiry")]
    public required DateTimeOffset RefreshTokenExpiry { get; set; }
}
