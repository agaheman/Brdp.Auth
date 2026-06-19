using Brdp.Authentication.Models;

namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Orchestrates the branch-selection upgrade flow:
///   1. Validate the selected branch is accessible to the user.
///   2. Call SSO upgradeToken to obtain a branch-enriched SSO token.
///   3. Update Redis session with new tokens and branchCode.
///   4. Issue a new BrdpToken aligned to the new SsoAccessToken expiry.
/// </summary>
public interface IBranchService
{
    Task<BranchSelectionResult> SelectBranchAsync(
        string username,
        string branchCode,
        CancellationToken ct = default);
}
