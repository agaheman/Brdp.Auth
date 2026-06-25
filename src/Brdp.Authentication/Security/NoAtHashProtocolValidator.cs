using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Brdp.Authentication.Security;

/// <summary>
/// An <see cref="OpenIdConnectProtocolValidator"/> that skips the <c>at_hash</c>
/// (access-token hash) check on the id_token.
///
/// Rationale: some SSO servers compute the <c>at_hash</c> claim incorrectly, which
/// makes the fully-compliant default validator reject an otherwise-valid login with
/// <c>IDX21348: Validating the 'at_hash' failed</c>. Skipping this single check lets
/// such servers work while every other protection — id_token signature, issuer,
/// audience, nonce, and expiry validation — remains fully enforced.
///
/// Enable via <c>SsoAuthentication:SkipAtHashValidation = true</c>.
/// </summary>
public sealed class NoAtHashProtocolValidator : OpenIdConnectProtocolValidator
{
    /// <summary>
    /// Overrides the base <c>at_hash</c> validation with a no-op. The access-token
    /// binding check is intentionally skipped; all other token validation still runs.
    /// </summary>
    protected override void ValidateAtHash(OpenIdConnectProtocolValidationContext validationContext)
    {
        // Intentionally no-op — see class summary.
    }
}
