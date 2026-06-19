using Brdp.Authentication.Models;

namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Issues and validates BrdpTokens — the only tokens the SPA ever sees.
///
/// Expiry alignment rule:
///   Expiry(BrdpToken) == Expiry(SsoAccessToken)
/// This eliminates the need to repeatedly parse SSO tokens during request processing.
/// </summary>
public interface IBrdpTokenService
{
    /// <summary>
    /// Issue a new BrdpToken from the given user data.
    /// The token expiry is set to match <paramref name="accessTokenExpiry"/>.
    /// </summary>
    string Issue(BrdpTokenClaims claims, DateTimeOffset accessTokenExpiry);

    /// <summary>
    /// Validate signature and expiry, return extracted claims.
    /// Returns <c>null</c> on any validation failure — callers must treat null as 401.
    /// </summary>
    BrdpTokenClaims? Validate(string token);

    /// <summary>
    /// Validate signature only — ignores expiry.
    /// Used during refresh flow where an expired-but-signed token is still trusted.
    /// </summary>
    BrdpTokenClaims? ValidateIgnoringExpiry(string token);
}
