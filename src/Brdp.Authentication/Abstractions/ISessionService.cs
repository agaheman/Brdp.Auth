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

    /// <summary>Overwrite session fields after branch selection or token refresh.</summary>
    Task UpdateAsync(RedisSession session, CancellationToken ct = default);

    /// <summary>Remove session (logout or single-session invalidation).</summary>
    Task DeleteAsync(string username, CancellationToken ct = default);

    /// <summary>True when a live session exists for the given username.</summary>
    Task<bool> ExistsAsync(string username, CancellationToken ct = default);

    /// <summary>
    /// Acquires a distributed Redis lock for the given username, executes
    /// <paramref name="refreshFactory"/> exactly once, then releases the lock.
    ///
    /// Solves the SPA refresh race condition:
    ///   - Multiple tabs may simultaneously send the same expired BrdpToken.
    ///   - Without a lock, each tab reads the same SsoRefreshToken from Redis
    ///     and tries to exchange it — but SSO refresh tokens are single-use,
    ///     so only the first call succeeds and all others get 401.
    ///
    /// With this lock:
    ///   - The first caller acquires the lock and runs <paramref name="refreshFactory"/>.
    ///   - Subsequent callers wait (up to <paramref name="timeout"/>) for the lock to release.
    ///   - After the lock is released, waiters re-read the session from Redis and
    ///     return the already-refreshed token — zero additional SSO calls.
    ///
    /// Pattern: Redis SET NX PX (atomic acquire) + Lua script release (atomic release).
    /// </summary>
    Task<T?> ExecuteWithRefreshLockAsync<T>(
        string username,
        Func<RedisSession, CancellationToken, Task<T?>> refreshFactory,
        TimeSpan? timeout = null,
        CancellationToken ct = default) where T : class;
}
