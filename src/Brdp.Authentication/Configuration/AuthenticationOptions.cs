using System.ComponentModel.DataAnnotations;

namespace Brdp.Authentication.Configuration;

/// <summary>
/// Bound from <c>appsettings.json</c> section <c>"Authentication"</c>.
/// </summary>
public sealed class AuthenticationOptions
{
    public const string SectionName = "Authentication";

    /// <summary>Symmetric key used to sign BrdpTokens (HMAC-SHA256, min 32 chars).</summary>
    [Required, MinLength(32)]
    public required string SigningKey { get; init; }

    /// <summary>Value placed in the <c>iss</c> claim of BrdpTokens.</summary>
    [Required]
    public required string Issuer { get; init; }

    /// <summary>Value placed in the <c>aud</c> claim of BrdpTokens.</summary>
    [Required]
    public required string Audience { get; init; }

    /// <summary>
    /// When <c>true</c>, a new login invalidates any existing session for that username.
    /// </summary>
    public bool SingleSessionEnabled { get; init; } = true;

    /// <summary>
    /// Encrypt <c>SsoAccessToken</c> and <c>SsoRefreshToken</c> before storing in Redis.
    /// Should be <c>true</c> in production.
    /// </summary>
    public bool EncryptTokensAtRest { get; init; } = false;

    /// <summary>
    /// Proactive refresh threshold: if the BrdpToken lifetime remaining is below this
    /// value, the refresh flow is triggered even though the token is not yet expired.
    /// </summary>
    public TimeSpan ProactiveRefreshThreshold { get; init; } = TimeSpan.FromMinutes(5);
}
