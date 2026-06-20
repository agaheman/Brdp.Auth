using System.Security.Cryptography;
using System.Text;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Centralises Redis key construction to ensure consistency across all stores.
///
/// Key format:
///   Session : <c>auth:session:{sha256(username)}</c>
///   Lock    : <c>auth:lock:{sha256(username)}</c>
///
/// Username is lowercased before hashing to avoid case-sensitivity issues.
/// </summary>
internal static class RedisKeyHelper
{
    private const string SessionPrefix = "auth:session:";
    private const string LockPrefix    = "auth:lock:";

    public static string SessionKey(string username) =>
        SessionPrefix + Hash(username);

    public static string LockKey(string username) =>
        LockPrefix + Hash(username);

    private static string Hash(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        var bytes = Encoding.UTF8.GetBytes(username.ToLowerInvariant());
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
}
