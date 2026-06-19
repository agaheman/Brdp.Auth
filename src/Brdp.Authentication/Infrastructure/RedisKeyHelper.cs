using System.Security.Cryptography;
using System.Text;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Centralises Redis key construction to ensure consistency across all stores.
/// Key format: <c>auth:{sha256(username.ToLowerInvariant())}</c>
/// </summary>
internal static class RedisKeyHelper
{
    private const string Prefix = "auth:";

    /// <summary>
    /// Returns the Redis key for the given username.
    /// Username is lowercased before hashing to avoid case-sensitivity issues.
    /// </summary>
    public static string SessionKey(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        var bytes = Encoding.UTF8.GetBytes(username.ToLowerInvariant());
        var hash  = SHA256.HashData(bytes);
        var hex   = Convert.ToHexStringLower(hash);

        return $"{Prefix}{hex}";
    }
}
