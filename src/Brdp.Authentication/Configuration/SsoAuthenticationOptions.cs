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

    /// <summary>Token endpoint — derived from <see cref="Authority"/> if not set explicitly.</summary>
    public string TokenEndpoint => $"{Authority.TrimEnd('/')}/protocol/openid-connect/token";

    /// <summary>Revocation endpoint.</summary>
    public string RevocationEndpoint => $"{Authority.TrimEnd('/')}/protocol/openid-connect/revoke";

    /// <summary>
    /// Custom upgrade endpoint on the TPS SSO for branch-token enrichment.
    /// POST with current access_token + branch_code → returns enriched tokens.
    /// </summary>
    public string UpgradeTokenEndpoint { get; init; } = "/protocol/openid-connect/token/upgrade";
}
