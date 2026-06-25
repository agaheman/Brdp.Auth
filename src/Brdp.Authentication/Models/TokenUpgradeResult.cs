namespace Brdp.Authentication.Models;

/// <summary>
/// Result of a Token Upgrade — a new BrdpToken backed by the upgraded SSO token,
/// plus any branch code the upgrade applied.
/// </summary>
public sealed class TokenUpgradeResult
{
    /// <summary>New BrdpToken issued after the upgrade — the SPA must replace the old one.</summary>
    public required string BrdpToken { get; init; }

    /// <summary>Aligned to the upgraded SSO access-token expiry.</summary>
    public required DateTimeOffset AccessTokenExpiry { get; init; }

    /// <summary>Branch code carried by the upgraded token, if any.</summary>
    public string? BranchCode { get; init; }
}
