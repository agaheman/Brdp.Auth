using System.Text.Json;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Redis-backed session store.
///
/// Key   : <c>auth:{sha256(username)}</c>  (see <see cref="RedisKeyHelper"/>)
/// TTL   : <see cref="RedisSession.RefreshTokenExpiry"/> — session survives AccessToken rotation.
/// Encryption: when <c>EncryptTokensAtRest = true</c>, <see cref="SsoAccessToken"/> and
///             <see cref="SsoRefreshToken"/> are encrypted via <see cref="ITokenEncryptionService"/>
///             before write and decrypted after read.
/// </summary>
internal sealed class RedisSessionStore
{
    private readonly IConnectionMultiplexer      _redis;
    private readonly ITokenEncryptionService     _encryption;
    private readonly AuthenticationOptions       _options;
    private readonly ILogger<RedisSessionStore>  _logger;

    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

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

    // ── Write ────────────────────────────────────────────────────────────────

    public async Task SaveAsync(RedisSession session, CancellationToken ct)
    {
        var key     = RedisKeyHelper.SessionKey(session.Username);
        var payload = Serialize(EncryptIfRequired(session));
        var ttl     = session.RefreshTokenExpiry - DateTimeOffset.UtcNow;

        if (ttl <= TimeSpan.Zero)
        {
            _logger.LogWarning("Attempted to save session for {Username} with non-positive TTL. Skipping.", session.Username);
            return;
        }

        var db = _redis.GetDatabase();
        await db.StringSetAsync(key, payload, ttl).ConfigureAwait(false);

        _logger.LogDebug("Session saved for {Username} (key={Key}, ttl={Ttl})", session.Username, key, ttl);
    }

    public async Task UpdateAsync(RedisSession session, CancellationToken ct)
    {
        // Preserve remaining TTL — derive from refreshTokenExpiry which may have changed.
        await SaveAsync(session, ct).ConfigureAwait(false);
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    public async Task<RedisSession?> GetByUsernameAsync(string username, CancellationToken ct)
    {
        var key = RedisKeyHelper.SessionKey(username);
        var db  = _redis.GetDatabase();
        var raw = await db.StringGetAsync(key).ConfigureAwait(false);

        if (raw.IsNullOrEmpty)
            return null;

        var session = Deserialize(raw!);
        if (session is null)
        {
            _logger.LogWarning("Failed to deserialize session for key {Key}.", key);
            return null;
        }

        return DecryptIfRequired(session);
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    public async Task DeleteAsync(string username, CancellationToken ct)
    {
        var key = RedisKeyHelper.SessionKey(username);
        var db  = _redis.GetDatabase();
        await db.KeyDeleteAsync(key).ConfigureAwait(false);

        _logger.LogDebug("Session deleted for {Username} (key={Key})", username, key);
    }

    // ── Exists ───────────────────────────────────────────────────────────────

    public async Task<bool> ExistsAsync(string username, CancellationToken ct)
    {
        var key = RedisKeyHelper.SessionKey(username);
        var db  = _redis.GetDatabase();
        return await db.KeyExistsAsync(key).ConfigureAwait(false);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string Serialize(RedisSession session) =>
        JsonSerializer.Serialize(session, _json);

    private static RedisSession? Deserialize(string json)
    {
        try   { return JsonSerializer.Deserialize<RedisSession>(json, _json); }
        catch { return null; }
    }

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
