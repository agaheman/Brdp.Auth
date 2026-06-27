using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The payload stored in Redis under key <c>auth:session:{sha256(username)}</c>.
///
/// Layout:
///   • Identity at the root (userCode / username / names / branch) — what the UI sees.
///   • <see cref="SsoToken"/> — the raw SSO token pair + expiries (server-only).
///   • <see cref="BrdpToken"/> — the issued BrdpToken JWT the SPA holds.
///
/// TTL rule: Redis TTL = <c>SsoToken.RefreshTokenExpiry</c> (not the access-token expiry).
/// An expired access token does NOT mean an expired session — the refresh/upgrade flow
/// can restore it while the refresh token is still valid.
///
/// In production (<c>EncryptTokensAtRest = true</c>), <see cref="SsoTokenData.AccessToken"/>
/// and <see cref="SsoTokenData.RefreshToken"/> are encrypted before write and decrypted
/// after read by <see cref="Infrastructure.RedisSessionStore"/>. The BrdpToken is not
/// encrypted (short-lived; the SPA already holds it).
/// </summary>
public sealed class RedisSession
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("clientIp")]
    public required string ClientIp { get; init; }

    // ── Identity (root) — the minimal claims the UI/BrdpToken use ──────────────
    [JsonPropertyName("userCode")]
    public required string UserCode { get; init; }

    [JsonPropertyName("username")]
    public required string Username { get; init; }

    [JsonPropertyName("firstName")]
    public string FirstName { get; set; } = string.Empty;

    [JsonPropertyName("lastName")]
    public string LastName { get; set; } = string.Empty;

    /// <summary>Branch selected via a token upgrade; <c>null</c> before selection.</summary>
    [JsonPropertyName("branchCode")]
    public string? BranchCode { get; set; }

    [JsonPropertyName("isBranchUser")]
    public bool IsBranchUser { get; set; }

    // ── Tokens ────────────────────────────────────────────────────────────────
    /// <summary>Raw SSO token pair + expiries (server-only, encrypted at rest).</summary>
    [JsonPropertyName("ssoToken")]
    public required SsoTokenData SsoToken { get; set; }

    /// <summary>The issued BrdpToken (HS256 JWT) the SPA holds. Re-issued on refresh/upgrade.</summary>
    [JsonPropertyName("brdpToken")]
    public string BrdpToken { get; set; } = string.Empty;
}
