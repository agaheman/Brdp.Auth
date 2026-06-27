using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// The <b>API Gateway token</b> half of a cached session — the minimal set of claims the
/// BrdpToken carries and the SPA/UI consumes. Deliberately small: identity + branch +
/// expiry, no SSO tokens. These are the values used to (re)issue the BrdpToken.
/// </summary>
public sealed class ApiGatewayTokenData
{
    [JsonPropertyName("userCode")]
    public required string UserCode { get; set; }

    [JsonPropertyName("username")]
    public required string Username { get; set; }

    [JsonPropertyName("firstName")]
    public string FirstName { get; set; } = string.Empty;

    [JsonPropertyName("lastName")]
    public string LastName { get; set; } = string.Empty;

    /// <summary>Branch selected via a token upgrade; <c>null</c> before selection.</summary>
    [JsonPropertyName("branchCode")]
    public string? BranchCode { get; set; }

    [JsonPropertyName("isBranchUser")]
    public bool IsBranchUser { get; set; }

    /// <summary>BrdpToken expiry — aligned to the SSO access-token expiry.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; set; }
}
