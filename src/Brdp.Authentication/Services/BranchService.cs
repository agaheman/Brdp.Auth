using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;

namespace Brdp.Authentication.Services;

/// <summary>
/// Branch selection — a thin <b>use</b> of the reusable Token Upgrade feature
/// (<see cref="ITokenUpgradeService"/>). It builds the branch client-claims and
/// delegates the SSO upgrade, session update, and BrdpToken reissue to that feature.
///
/// Repeatable: selecting a different branch simply upgrades the token again.
/// </summary>
internal sealed class BranchService : IBranchService
{
    private readonly ITokenUpgradeService    _tokenUpgrade;
    private readonly ILogger<BranchService>  _logger;

    public BranchService(
        ITokenUpgradeService    tokenUpgrade,
        ILogger<BranchService>  logger)
    {
        _tokenUpgrade = tokenUpgrade;
        _logger       = logger;
    }

    public async Task<BranchSelectionResult> SelectBranchAsync(
        string username,
        string branchCode,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(branchCode);

        _logger.LogInformation("Branch selection for {Username} → branch {BranchCode}", username, branchCode);

        // Branch is just a set of client claims fed to the Token Upgrade feature.
        var upgrade = await _tokenUpgrade.UpgradeAsync(
            username,
            new Dictionary<string, object?> { ["branch_code"] = branchCode },
            ct).ConfigureAwait(false);

        return new BranchSelectionResult
        {
            BrdpToken         = upgrade.BrdpToken,
            BranchCode        = upgrade.BranchCode ?? branchCode,
            AccessTokenExpiry = upgrade.AccessTokenExpiry,
        };
    }
}
