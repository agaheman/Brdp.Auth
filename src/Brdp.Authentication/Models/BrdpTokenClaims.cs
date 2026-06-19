namespace Brdp.Authentication.Models;

/// <summary>
/// Claims carried inside a BrdpToken (JWT issued by this gateway).
/// The SPA never sees SSO tokens — it only ever holds a BrdpToken.
///
/// Claim names are kept short to minimise token size.
/// </summary>
public sealed class BrdpTokenClaims
{
    /// <summary>Subject — matches <c>userCode</c>.</summary>
    public required string Sub { get; init; }

    public required string UserCode  { get; init; }
    public required string Username  { get; init; }
    public required string FirstName { get; init; }
    public required string LastName  { get; init; }
}
