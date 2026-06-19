using Brdp.Authentication.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace Brdp.Authentication.Controllers;

/// <summary>
/// Handles the branch-selection flow for branch users.
///
/// After login, branch users are redirected to a branch selection page.
/// The SPA calls <c>POST /branch/select</c> with the chosen branch code.
/// The response contains a new BrdpToken (with branch context) that the SPA must store.
///
/// Flow:
///   SPA → POST /branch/select { branchCode } → gateway upgrades SSO token → new BrdpToken
/// </summary>
[ApiController]
[Route("branch")]
public sealed class BranchController : ControllerBase
{
    private readonly IBranchService                     _branchService;
    private readonly IAuthenticatedUserContextAccessor  _accessor;

    public BranchController(
        IBranchService                    branchService,
        IAuthenticatedUserContextAccessor accessor)
    {
        _branchService = branchService;
        _accessor      = accessor;
    }

    /// <summary>
    /// Select a branch and upgrade the BrdpToken.
    /// The SPA must replace the current BrdpToken with the one returned in the response.
    /// </summary>
    [HttpPost("select")]
    public async Task<IActionResult> SelectBranch(
        [FromBody] SelectBranchRequest request,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.BranchCode))
            return BadRequest(new { error = "branch_code_required" });

        var user = _accessor.GetRequiredContext();

        if (!user.IsBranchUser)
            return Forbid();

        var result = await _branchService
            .SelectBranchAsync(user.Username, request.BranchCode, ct)
            .ConfigureAwait(false);

        return Ok(new
        {
            token      = result.BrdpToken,
            branchCode = result.BranchCode,
            expiresAt  = result.AccessTokenExpiry,
        });
    }
}

/// <summary>Request body for branch selection.</summary>
public sealed record SelectBranchRequest(string BranchCode);
