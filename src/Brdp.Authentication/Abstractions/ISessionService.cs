using Brdp.Authentication.Models;

namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Manages BrdpApiGateway sessions stored in Redis.
/// Redis is the single source of truth — deleting a session immediately
/// invalidates the user even if their BrdpToken has not yet expired.
/// </summary>
public interface ISessionService
{
    /// <summary>Persist a new session. TTL is derived from <paramref name="session"/>.RefreshTokenExpiry.</summary>
    Task SaveAsync(RedisSession session, CancellationToken ct = default);

    /// <summary>Read session for the given username. Returns <c>null</c> if not found / expired.</summary>
    Task<RedisSession?> GetByUsernameAsync(string username, CancellationToken ct = default);

    /// <summary>Overwrite selected fields after branch selection or token refresh.</summary>
    Task UpdateAsync(RedisSession session, CancellationToken ct = default);

    /// <summary>Remove session (logout or single-session invalidation).</summary>
    Task DeleteAsync(string username, CancellationToken ct = default);

    /// <summary>True when a live session exists for the given username.</summary>
    Task<bool> ExistsAsync(string username, CancellationToken ct = default);
}
