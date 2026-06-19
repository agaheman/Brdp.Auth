namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Represents the identity and session data of the currently authenticated user.
/// Built once per request by <see cref="IAuthenticatedUserContextAccessor"/> and
/// available throughout the entire pipeline — services and controllers never touch
/// Redis or HttpContext directly.
/// </summary>
public interface IAuthenticatedUserContext
{
    /// <summary>Unique user identifier (matches Redis session and BrdpToken sub claim).</summary>
    string UserCode { get; }

    /// <summary>Login username — used as the Redis key seed (sha256).</summary>
    string Username { get; }

    string FirstName { get; }
    string LastName  { get; }

    /// <summary>
    /// Branch code populated after the branch-selection upgrade flow.
    /// <c>null</c> for non-branch users or before branch is selected.
    /// </summary>
    string? BranchCode { get; }

    /// <summary>Client IP recorded at login time (from Redis session).</summary>
    string ClientIp { get; }

    /// <summary>Opaque session identifier stored in Redis.</summary>
    string SessionId { get; }

    /// <summary>True when the user is a branch operator and must select a branch before the dashboard.</summary>
    bool IsBranchUser { get; }
}
