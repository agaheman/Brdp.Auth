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

    /// <summary>
    /// Previously-active signing keys. Tokens signed with any of these still validate,
    /// enabling zero-downtime signing-key rotation: deploy with the new key as
    /// <see cref="SigningKey"/> and the old key moved here until all old tokens expire.
    /// </summary>
    public string[] PreviousSigningKeys { get; init; } = [];

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

    /// <summary>
    /// Fallback session lifetime used to set the Redis TTL when the SSO token response
    /// does not advertise a <c>refresh_expires_in</c>. The SSO-provided value is always
    /// preferred when present.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Fallback access-token lifetime used at login when the OIDC <c>expires_at</c>
    /// property is missing. The SSO-provided value is always preferred when present.
    /// </summary>
    public TimeSpan AccessTokenFallbackLifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>How long a distributed refresh lock is held before it auto-expires.</summary>
    public TimeSpan RefreshLockTtl { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Maximum time a caller waits to acquire the refresh lock before giving up.</summary>
    public TimeSpan RefreshLockTimeout { get; init; } = TimeSpan.FromSeconds(8);

    /// <summary>Poll interval while waiting for a contended refresh lock to release.</summary>
    public TimeSpan RefreshLockPollInterval { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Origins allowed to call the BFF from a browser (the SPA origin(s), e.g.
    /// <c>https://app.brdp.ir</c>). Required for the transparent-refresh flow so the SPA
    /// can read the <c>X-New-BrdpToken</c> / <c>X-Correlation-ID</c> response headers.
    /// When empty, no CORS policy is applied (same-origin only).
    /// </summary>
    public string[] AllowedCorsOrigins { get; init; } = [];
}
