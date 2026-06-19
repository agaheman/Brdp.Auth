using Brdp.Authentication.Abstractions;

namespace Brdp.Authentication.Security;

/// <summary>
/// No-op encryption service registered in non-production environments.
/// Tokens are stored as plain text in Redis.
/// Never use in production — set <c>Authentication:EncryptTokensAtRest = true</c>.
/// </summary>
internal sealed class NoOpTokenEncryptionService : ITokenEncryptionService
{
    public string Encrypt(string plainText) => plainText;
    public string Decrypt(string cipherText) => cipherText;
}
