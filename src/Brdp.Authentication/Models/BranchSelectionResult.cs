namespace Brdp.Authentication.Models;

/// <summary>Result returned to the SPA after successful branch selection.</summary>
public sealed class BranchSelectionResult
{
    /// <summary>New BrdpToken issued after token upgrade — SPA must replace the old one.</summary>
    public required string BrdpToken { get; init; }

    public required string BranchCode { get; init; }

    public required DateTimeOffset AccessTokenExpiry { get; init; }
}
