using Brdp.Authentication.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace Brdp.Authentication.Controllers;

/// <summary>
/// Provides session introspection and management endpoints.
/// Useful for admin tooling and diagnostics.
///
/// All endpoints require an authenticated BrdpToken (middleware enforces this).
/// </summary>
[ApiController]
[Route("session")]
public sealed class SessionController : ControllerBase
{
    private readonly ISessionService                    _sessions;
    private readonly IAuthenticatedUserContextAccessor  _accessor;

    public SessionController(
        ISessionService                   sessions,
        IAuthenticatedUserContextAccessor accessor)
    {
        _sessions = sessions;
        _accessor = accessor;
    }

    /// <summary>Returns session metadata for the current user (no tokens exposed).</summary>
    [HttpGet]
    public async Task<IActionResult> GetSession(CancellationToken ct = default)
    {
        var user    = _accessor.GetRequiredContext();
        var session = await _sessions.GetByUsernameAsync(user.Username, ct).ConfigureAwait(false);

        if (session is null)
            return NotFound(new { error = "session_not_found" });

        // Tokens themselves are never exposed — only identity + SSO token expiries.
        return Ok(new
        {
            session.SessionId,
            session.ClientIp,
            session.UserCode,
            session.Username,
            session.FirstName,
            session.LastName,
            session.BranchCode,
            session.IsBranchUser,
            ssoToken = new
            {
                session.SsoToken.AccessTokenExpiry,
                session.SsoToken.RefreshTokenExpiry,
            },
        });
    }

    /// <summary>Terminates the current user's session (self-logout without OIDC redirect).</summary>
    [HttpDelete]
    public async Task<IActionResult> DeleteSession(CancellationToken ct = default)
    {
        var user = _accessor.GetRequiredContext();
        await _sessions.DeleteAsync(user.Username, ct).ConfigureAwait(false);
        return NoContent();
    }
}
