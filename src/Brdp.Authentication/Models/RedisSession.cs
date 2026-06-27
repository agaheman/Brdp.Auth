using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The payload stored in Redis under key <c>auth:session:{sha256(username)}</c>.
///
/// The session is split into two clearly separated halves:
///   • <see cref="Sso"/>        — the heavy, claim-rich SSO token + all its props (server-only).
///   • <see cref="ApiGateway"/> — the minimal claims the BrdpToken carries (what the UI uses).
///
/// TTL rule: Redis TTL = <c>Sso.RefreshTokenExpiry</c> (not the access-token expiry).
/// An expired access token does NOT mean an expired session — the refresh/upgrade flow
/// can restore it while the refresh token is still valid.
///
/// In production (<c>EncryptTokensAtRest = true</c>), <see cref="SsoTokenData.AccessToken"/>
/// and <see cref="SsoTokenData.RefreshToken"/> are encrypted before write and decrypted
/// after read by <see cref="Infrastructure.RedisSessionStore"/>.
/// </summary>
public sealed class RedisSession
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("clientIp")]
    public required string ClientIp { get; init; }

    /// <summary>SSO token half — all SSO props (tokens, expiries, branch, user_info).</summary>
    [JsonPropertyName("sso")]
    public required SsoTokenData Sso { get; set; }

    /// <summary>API Gateway token half — the minimal claims the SPA/UI consumes.</summary>
    [JsonPropertyName("apiGateway")]
    public required ApiGatewayTokenData ApiGateway { get; set; }
}
