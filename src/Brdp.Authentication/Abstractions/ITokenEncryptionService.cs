namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Encrypts/decrypts SSO tokens before they are stored in Redis.
/// Active only when <c>Authentication:EncryptTokensAtRest = true</c> (production).
/// A no-op implementation is registered in non-production environments.
/// </summary>
public interface ITokenEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}
