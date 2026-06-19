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

    // ── UpgradeToken (Branch Selection) ──────────────────────────────────────

    public async Task<SsoTokenResponse?> UpgradeTokenAsync(
        string accessToken, string branchCode, CancellationToken ct)
    {
        var endpoint = $"{_ssoOptions.Authority.TrimEnd('/')}{_ssoOptions.UpgradeTokenEndpoint}";

        var form = new Dictionary<string, string>
        {
            ["grant_type"]    = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["client_id"]     = _ssoOptions.ClientId,
            ["client_secret"] = _ssoOptions.ClientSecret,
            ["subject_token"] = accessToken,
            ["branch_code"]   = branchCode,
        };

        return await PostFormAsync(endpoint, form, ct).ConfigureAwait(false);
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
