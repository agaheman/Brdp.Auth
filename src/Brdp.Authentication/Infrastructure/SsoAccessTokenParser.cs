using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Brdp.Authentication.Models;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Extracts identity from the TPS SSO access token. The SSO embeds user identity
/// in a nested <c>user_info</c> JSON claim (and the branch in <c>branch_code</c>)
/// rather than using standard OIDC claims or a userinfo endpoint.
/// </summary>
public static class SsoAccessTokenParser
{
    /// <summary>Reads and deserializes the <c>user_info</c> claim, or null if absent.</summary>
    public static SsoUserInfo? ExtractUserInfo(string accessToken)
    {
        var claim = ReadClaim(accessToken, "user_info");
        if (string.IsNullOrWhiteSpace(claim)) return null;

        try
        {
            return JsonSerializer.Deserialize<SsoUserInfo>(claim);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Reads the top-level <c>branch_code</c> claim, or null if absent.</summary>
    public static string? ExtractBranchCode(string accessToken)
        => ReadClaim(accessToken, "branch_code");

    private static string? ReadClaim(string accessToken, string claimType)
    {
        var jwt = new JwtSecurityToken(accessToken);
        return jwt.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
}
