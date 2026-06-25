using System.ComponentModel.DataAnnotations;

namespace Brdp.Authentication.Configuration;

/// <summary>
/// Bound from <c>appsettings.json</c> section <c>"SsoAuthentication"</c>.
/// Maps directly to the TPS SSO OIDC configuration.
/// </summary>
public sealed class SsoAuthenticationOptions
{
    public const string SectionName = "SsoAuthentication";

    [Required] public required string ClientId            { get; init; }
    [Required] public required string ClientSecret        { get; init; }
    [Required] public required string Authority           { get; init; }
    [Required] public required string MetadataAddress     { get; init; }

    public string   ResponseType           { get; init; } = "code";
    public string[] Scopes                 { get; init; } = ["openid", "profile"];
    public string   CallbackPath           { get; init; } = "/signin-oidc";
    public string   SignedOutCallbackPath  { get; init; } = "/signout-callback-oidc";

    /// <summary>
    /// Use PKCE (code_challenge / code_verifier) on the Authorization-Code flow.
    /// Default <c>true</c>. Some confidential-client OAuth servers fail when both a
    /// <c>client_secret</c> and a <c>code_verifier</c> are sent on the token request;
    /// set <c>false</c> to send only the client_secret.
    /// </summary>
    public bool UsePkce { get; init; } = true;

    /// <summary>
    /// Call the OIDC userinfo endpoint to enrich the principal. Default <c>true</c>.
    /// Set <c>false</c> when the SSO userinfo response omits the <c>sub</c> claim
    /// (handler throws IDX21345); identity is then read from the id_token instead.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; init; } = true;

    /// <summary>
    /// Authenticate at the token endpoint with a signed JWT client assertion
    /// (<c>client_secret_jwt</c>, RFC 7523) instead of sending the secret as a plain
    /// form field. Required when the SSO client's token_endpoint_auth_method is
    /// <c>SECRET_JWT</c>. The assertion is signed HS256 with <see cref="ClientSecret"/>.
    /// </summary>
    public bool UseClientSecretJwt { get; init; }

    /// <summary>
    /// Audience claim for the <c>client_secret_jwt</c> assertion. Defaults to the
    /// discovered token endpoint (RFC 7523 §3). Set this only if the SSO expects a
    /// different audience (e.g. its issuer identifier).
    /// </summary>
    public string? ClientAssertionAudience { get; init; }

    /// <summary>
    /// Skip OIDC <c>at_hash</c> (access-token hash) validation of the id_token.
    /// Some SSO servers compute <c>at_hash</c> incorrectly, which makes the
    /// fully-compliant .NET validator reject an otherwise-valid login
    /// (error IDX21348). Set <c>true</c> to tolerate such servers. The id_token
    /// signature itself is still fully validated — only the access-token binding
    /// check is skipped.
    /// </summary>
    public bool SkipAtHashValidation { get; init; }

    // ── Endpoint paths (relative to Authority) — TPS SSO uses /oauth/* not Keycloak paths ──
    public string TokenEndpointPath      { get; init; } = "/oauth/token";
    public string RevocationEndpointPath { get; init; } = "/revoke";
    public string EndSessionEndpointPath { get; init; } = "/oauth/endsession";

    /// <summary>
    /// Absolute URL the SSO redirects the browser back to after global sign-out
    /// (sent as <c>post_logout_redirect_uri</c>). e.g. <c>https://host/index.html</c>.
    /// </summary>
    public string LogoutRedirectUrl { get; init; } = "";

    /// <summary>Token endpoint — also used for refresh_token and upgrade_token grants.</summary>
    public string TokenEndpoint      => $"{Authority.TrimEnd('/')}{TokenEndpointPath}";

    /// <summary>Token revocation endpoint.</summary>
    public string RevocationEndpoint => $"{Authority.TrimEnd('/')}{RevocationEndpointPath}";

    /// <summary>End-session (sign-out) endpoint — TPS SSO exposes a URL, not an API.</summary>
    public string EndSessionEndpoint => $"{Authority.TrimEnd('/')}{EndSessionEndpointPath}";
}
