using System.Text.Json.Serialization;

namespace Brdp.Authentication.Models;

/// <summary>
/// Identity payload carried inside the TPS SSO access token's nested
/// <c>user_info</c> claim. The SSO does not expose these as standard OIDC
/// claims, nor a spec-compliant userinfo endpoint — they live in this object.
/// </summary>
public sealed class SsoUserInfo
{
    [JsonPropertyName("first_name")]     public string? FirstName     { get; init; }
    [JsonPropertyName("last_name")]      public string? LastName      { get; init; }
    [JsonPropertyName("full_name")]      public string? FullName      { get; init; }
    [JsonPropertyName("mobile")]         public string? Mobile        { get; init; }
    [JsonPropertyName("username")]       public string? Username      { get; init; }
    [JsonPropertyName("user_code")]      public string? UserCode      { get; init; }
    [JsonPropertyName("user_type")]      public string? UserType      { get; init; }
    [JsonPropertyName("personnel_code")] public string? PersonnelCode { get; init; }
    [JsonPropertyName("sub_system")]     public string? SubSystem     { get; init; }
    [JsonPropertyName("uid")]            public string? Uid           { get; init; }
    [JsonPropertyName("nin")]            public string? Nin           { get; init; }
    [JsonPropertyName("account_id")]     public string? AccountId     { get; init; }
}
