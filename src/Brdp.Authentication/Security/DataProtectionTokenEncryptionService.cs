using Brdp.Authentication.Abstractions;
using Microsoft.AspNetCore.DataProtection;

namespace Brdp.Authentication.Security;

/// <summary>
/// Production encryption using ASP.NET Core Data Protection (AES-256-CBC + HMACSHA256).
/// Registered when <c>Authentication:EncryptTokensAtRest = true</c>.
///
/// The purpose string <c>"Brdp.Authentication.SsoTokens"</c> scopes the keys so they
/// cannot be used to decrypt data protected with a different purpose.
/// </summary>
internal sealed class DataProtectionTokenEncryptionService : ITokenEncryptionService
{
    private readonly IDataProtector _protector;

    public DataProtectionTokenEncryptionService(IDataProtectionProvider provider)
        => _protector = provider.CreateProtector("Brdp.Authentication.SsoTokens");

    public string Encrypt(string plainText) =>
        _protector.Protect(plainText);

    public string Decrypt(string cipherText) =>
        _protector.Unprotect(cipherText);
}
