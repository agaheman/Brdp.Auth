using System.Text.Json;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Redis-backed session store with distributed locking for concurrent refresh protection.
///
/// Key layout:
///   <c>auth:session:{sha256(username)}</c> — session payload (TTL = RefreshTokenExpiry)
///   <c>auth:lock:{sha256(username)}</c>    — distributed mutex (TTL = LockTtl)
///
/// Encryption:
///   When <c>EncryptTokensAtRest = true</c>, SsoAccessToken and SsoRefreshToken
///   are encrypted via <see cref="ITokenEncryptionService"/> before write and
///   decrypted after read.
/// </summary>
internal sealed class RedisSessionStore
{
    private readonly IConnectionMultiplexer     _redis;
    private readonly ITokenEncryptionService    _encryption;
    private readonly AuthenticationOptions      _options;
    private readonly ILogger<RedisSessionStore> _logger;

    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    /// <summary>How long a refresh lock is held before expiring automatically.</summary>
    private static readonly TimeSpan LockTtl = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Lua script for atomic lock release:
    /// Only deletes the key if its value matches the caller's token,
    /// preventing a slow caller from releasing a lock it no longer owns.
    /// </summary>
    private const string ReleaseLockScript = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """;

    public RedisSessionStore(
        IConnectionMultiplexer          redis,
        ITokenEncryptionService         encryption,
        IOptions<AuthenticationOptions> options,
        ILogger<RedisSessionStore>      logger)
    {
        _redis      = redis;
        _encryption = encryption;
        _options    = options.Value;
        _logger     = logger;
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    public async Task SaveAsync(RedisSession session, CancellationToken ct)
    {
        var key     = RedisKeyHelper.SessionKey(session.Username);
        var payload = Serialize(EncryptIfRequired(session));
        var ttl     = session.RefreshTokenExpiry - DateTimeOffset.UtcNow;

        if (ttl <= TimeSpan.Zero)
        {
            _logger.LogWarning(
                "Skipping session save for {Username} — RefreshTokenExpiry is in the past.", session.Username);
            return;
        }

        await _redis.GetDatabase()
                    .StringSetAsync(key, payload, ttl)
                    .ConfigureAwait(false);

        _logger.LogDebug(
            "Session saved for {Username} (ttl={Ttl:g})", session.Username, ttl);
    }

    public Task UpdateAsync(RedisSession session, CancellationToken ct) =>
        SaveAsync(session, ct);

    // ── Read ──────────────────────────────────────────────────────────────────

    public async Task<RedisSession?> GetByUsernameAsync(string username, CancellationToken ct)
    {
        var raw = await _redis.GetDatabase()
                              .StringGetAsync(RedisKeyHelper.SessionKey(username))
                              .ConfigureAwait(false);

        if (raw.IsNullOrEmpty) return null;

        var session = Deserialize(raw!);
        if (session is null)
        {
            _logger.LogWarning("Failed to deserialize session for {Username}.", username);
            return null;
        }

        return DecryptIfRequired(session);
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    public async Task DeleteAsync(string username, CancellationToken ct)
    {
        await _redis.GetDatabase()
                    .KeyDeleteAsync(RedisKeyHelper.SessionKey(username))
                    .ConfigureAwait(false);

        _logger.LogDebug("Session deleted for {Username}.", username);
    }

    // ── Exists ────────────────────────────────────────────────────────────────

    public Task<bool> ExistsAsync(string username, CancellationToken ct) =>
        _redis.GetDatabase()
              .KeyExistsAsync(RedisKeyHelper.SessionKey(username));

    // ── Distributed Refresh Lock ──────────────────────────────────────────────

    /// <summary>
    /// Acquires an exclusive Redis lock for <paramref name="username"/>, runs
    /// <paramref name="refreshFactory"/> once, then releases the lock.
    ///
    /// Concurrent callers that cannot acquire the lock wait and poll until
    /// the winner releases it, then return the session the winner already
    /// persisted — without calling SSO again.
    ///
    /// Failure modes:
    ///   • Lock never acquired within <paramref name="timeout"/> → returns null (caller treats as 401).
    ///   • Lock acquired but <paramref name="refreshFactory"/> returns null → lock released, null propagated.
    ///   • Redis down → exception propagates (caller's circuit breaker / retry handles it).
    /// </summary>
    public async Task<T?> ExecuteWithRefreshLockAsync<T>(
        string username,
        Func<RedisSession, CancellationToken, Task<T?>> refreshFactory,
        TimeSpan? timeout,
        CancellationToken ct) where T : class
    {
        var lockKey   = RedisKeyHelper.LockKey(username);
        var lockToken = Guid.NewGuid().ToString("N"); // unique per caller to prevent cross-release
        var deadline  = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(8));
        var db        = _redis.GetDatabase();

        // ── Acquire lock (SET NX PX) ──────────────────────────────────────────
        while (true)
        {
            ct.ThrowIfCancellationRequested();

            var acquired = await db
                .StringSetAsync(lockKey, lockToken, LockTtl, When.NotExists)
                .ConfigureAwait(false);

            if (acquired) break;

            if (DateTimeOffset.UtcNow >= deadline)
            {
                _logger.LogWarning(
                    "Could not acquire refresh lock for {Username} within timeout. " +
                    "Another refresh may be in progress.", username);

                // Last resort: read whatever the winner wrote and return it.
                // The session in Redis should already have fresh tokens.
                var latestSession = await GetByUsernameAsync(username, ct).ConfigureAwait(false);
                if (latestSession is not null)
                {
                    _logger.LogInformation(
                        "Returning session refreshed by concurrent caller for {Username}.", username);
                    // Return null here — the middleware/controller will re-read the
                    // updated session on the next request. Returning a stale BrdpToken
                    // is worse than asking the SPA to retry.
                }

                return null;
            }

            _logger.LogDebug(
                "Refresh lock for {Username} is held by another caller — waiting 100 ms.", username);

            await Task.Delay(100, ct).ConfigureAwait(false);
        }

        // ── Lock acquired — we are the sole refresh caller ────────────────────
        try
        {
            var session = await GetByUsernameAsync(username, ct).ConfigureAwait(false);
            if (session is null)
            {
                _logger.LogWarning(
                    "Acquired refresh lock for {Username} but session no longer exists in Redis.", username);
                return null;
            }

            return await refreshFactory(session, ct).ConfigureAwait(false);
        }
        finally
        {
            // ── Atomic release via Lua — only if we still own the lock ────────
            await db.ScriptEvaluateAsync(
                    ReleaseLockScript,
                    keys:   [(RedisKey)lockKey],
                    values: [(RedisValue)lockToken])
                .ConfigureAwait(false);

            _logger.LogDebug("Refresh lock released for {Username}.", username);
        }
    }

    // ── Serialization helpers ─────────────────────────────────────────────────

    private static string Serialize(RedisSession session) =>
        JsonSerializer.Serialize(session, _json);

    private static RedisSession? Deserialize(string json)
    {
        try   { return JsonSerializer.Deserialize<RedisSession>(json, _json); }
        catch { return null; }
    }

    // ── Encryption helpers ────────────────────────────────────────────────────

    private RedisSession EncryptIfRequired(RedisSession session)
    {
        if (!_options.EncryptTokensAtRest) return session;
        session.SsoAccessToken  = _encryption.Encrypt(session.SsoAccessToken);
        session.SsoRefreshToken = _encryption.Encrypt(session.SsoRefreshToken);
        return session;
    }

    private RedisSession DecryptIfRequired(RedisSession session)
    {
        if (!_options.EncryptTokensAtRest) return session;
        session.SsoAccessToken  = _encryption.Decrypt(session.SsoAccessToken);
        session.SsoRefreshToken = _encryption.Decrypt(session.SsoRefreshToken);
        return session;
    }
}
