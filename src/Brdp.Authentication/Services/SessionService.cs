using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Infrastructure;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;

namespace Brdp.Authentication.Services;

/// <summary>
/// Application-level session service.
/// Delegates all persistence and distributed locking to <see cref="RedisSessionStore"/>.
/// </summary>
internal sealed class SessionService : ISessionService
{
    private readonly RedisSessionStore       _store;
    private readonly ILogger<SessionService> _logger;

    public SessionService(RedisSessionStore store, ILogger<SessionService> logger)
    {
        _store  = store;
        _logger = logger;
    }

    public Task SaveAsync(RedisSession session, CancellationToken ct = default) =>
        _store.SaveAsync(session, ct);

    public Task<RedisSession?> GetByUsernameAsync(string username, CancellationToken ct = default) =>
        _store.GetByUsernameAsync(username, ct);

    public Task UpdateAsync(RedisSession session, CancellationToken ct = default) =>
        _store.UpdateAsync(session, ct);

    public Task DeleteAsync(string username, CancellationToken ct = default) =>
        _store.DeleteAsync(username, ct);

    public Task<bool> ExistsAsync(string username, CancellationToken ct = default) =>
        _store.ExistsAsync(username, ct);

    public Task<T?> ExecuteWithRefreshLockAsync<T>(
        string username,
        Func<RedisSession, CancellationToken, Task<T?>> refreshFactory,
        TimeSpan? timeout = null,
        CancellationToken ct = default) where T : class =>
        _store.ExecuteWithRefreshLockAsync(username, refreshFactory, timeout, ct);
}
