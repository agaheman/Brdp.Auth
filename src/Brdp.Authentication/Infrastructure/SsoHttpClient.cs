using System.Net.Http.Json;
using System.Text.Json;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Infrastructure;

/// <summary>
/// Typed HTTP client for all communication with the TPS SSO server.
/// Registered via <c>AddHttpClient&lt;SsoHttpClient&gt;</c> — base address and
/// timeout are configured in <see cref="Extensions.ServiceCollectionExtensions"/>.
/// </summary>
internal sealed class SsoHttpClient
{
    private readonly HttpClient                  _http;
    private readonly SsoAuthenticationOptions    _ssoOptions;
    private readonly ILogger<SsoHttpClient>      _logger;

    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public SsoHttpClient(
        HttpClient                          http,
        IOptions<SsoAuthenticationOptions>  ssoOptions,
        ILogger<SsoHttpClient>              logger)
    {
        _http       = http;
        _ssoOptions = ssoOptions.Value;
        _logger     = logger;
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    public async Task<SsoTokenResponse?> RefreshTokenAsync(string refreshToken, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"]    = "refresh_token",
            ["client_id"]     = _ssoOptions.ClientId,
            ["client_secret"] = _ssoOptions.ClientSecret,
            ["refresh_token"] = refreshToken,
        };

        return await PostFormAsync(_ssoOptions.TokenEndpoint, form, ct).ConfigureAwait(false);
    }

    // ── UpgradeToken (TPS upgrade_token grant) ────────────────────────────────
    // Re-issues the current access token enriched with arbitrary client_claims.
    // Posted to the regular token endpoint with grant_type=upgrade_token, keyed by
    // the current token's jti. Used by the reusable Token Upgrade feature (e.g. branch).

    public async Task<SsoTokenResponse?> UpgradeTokenAsync(
        string accessToken, IReadOnlyDictionary<string, object?> clientClaims, CancellationToken ct)
    {
        var jti = SsoAccessTokenParser.ExtractJti(accessToken);
        if (string.IsNullOrEmpty(jti))
        {
            _logger.LogWarning("upgrade_token: access token has no jti claim.");
            return null;
        }

        var form = new Dictionary<string, string>
        {
            ["grant_type"]           = "upgrade_token",
            ["client_id"]            = _ssoOptions.ClientId,
            ["client_secret"]        = _ssoOptions.ClientSecret,
            ["access_token_jti"]     = jti,
            ["revoke_current_token"] = "false",
            ["client_claims"]        = JsonSerializer.Serialize(clientClaims),
        };

        // Only send scope when explicitly configured; otherwise inherit the token's scopes.
        var scope = string.Join(' ', _ssoOptions.Scopes);
        if (!string.IsNullOrWhiteSpace(scope))
            form["scope"] = scope;

        return await PostFormAsync(_ssoOptions.TokenEndpoint, form, ct).ConfigureAwait(false);
    }

    // ── Revoke ────────────────────────────────────────────────────────────────

    public async Task RevokeTokenAsync(string accessToken, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["token"]         = accessToken,
            ["client_id"]     = _ssoOptions.ClientId,
            ["client_secret"] = _ssoOptions.ClientSecret,
        };

        using var content  = new FormUrlEncodedContent(form);
        using var response = await _http.PostAsync(_ssoOptions.RevocationEndpoint, content, ct)
                                        .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            _logger.LogWarning("SSO revocation returned {StatusCode}", response.StatusCode);
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private async Task<SsoTokenResponse?> PostFormAsync(
        string endpoint, Dictionary<string, string> form, CancellationToken ct)
    {
        try
        {
            using var content  = new FormUrlEncodedContent(form);
            using var response = await _http.PostAsync(endpoint, content, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("SSO token request to {Endpoint} returned {StatusCode}",
                    endpoint, response.StatusCode);
                return null;
            }

            return await response.Content
                                 .ReadFromJsonAsync<SsoTokenResponse>(_json, ct)
                                 .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SSO token request to {Endpoint} failed.", endpoint);
            return null;
        }
    }
}
