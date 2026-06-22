using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Brdp.Authentication.Services;

/// <summary>
/// Issues and validates BrdpTokens (HS256 JWT).
///
/// Expiry alignment:
///   Expiry(BrdpToken) == Expiry(SsoAccessToken)
/// This means we never need to parse SSO tokens during normal request processing.
/// </summary>
internal sealed class BrdpTokenService : IBrdpTokenService
{
    private readonly AuthenticationOptions      _options;
    private readonly ILogger<BrdpTokenService>  _logger;

    private readonly SigningCredentials _signingCredentials;
    private readonly TokenValidationParameters _validationParameters;
    private readonly TokenValidationParameters _validationParametersIgnoreExpiry;

    private static readonly JwtSecurityTokenHandler _handler = new();

    public BrdpTokenService(
        IOptions<AuthenticationOptions> options,
        ILogger<BrdpTokenService>       logger)
    {
        _options = options.Value;
        _logger  = logger;

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Current key signs new tokens; current + previous keys all validate, so a
        // signing-key rotation can be rolled out without invalidating live tokens.
        SecurityKey[] validationKeys =
        [
            key,
            .. _options.PreviousSigningKeys
                .Where(k => !string.IsNullOrWhiteSpace(k))
                .Select(k => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(k))),
        ];

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = _options.Issuer,
            ValidateAudience         = true,
            ValidAudience            = _options.Audience,
            ValidateLifetime         = true,
            ClockSkew                = TimeSpan.FromSeconds(30),
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys        = validationKeys,
        };

        // TokenValidationParameters is not a record type — clone then override.
        _validationParametersIgnoreExpiry = _validationParameters.Clone();
        _validationParametersIgnoreExpiry.ValidateLifetime = false;
    }

    // ── Issue ─────────────────────────────────────────────────────────────────

    public string Issue(BrdpTokenClaims claims, DateTimeOffset accessTokenExpiry)
    {
        var now = DateTimeOffset.UtcNow;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer   = _options.Issuer,
            Audience = _options.Audience,
            Subject  = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub,       claims.Sub),
                new Claim("userCode",                        claims.UserCode),
                new Claim("username",                        claims.Username),
                new Claim("firstName",                       claims.FirstName),
                new Claim("lastName",                        claims.LastName),
            ]),
            NotBefore          = now.UtcDateTime,
            Expires            = accessTokenExpiry.UtcDateTime,
            SigningCredentials = _signingCredentials,
        };

        var token = _handler.CreateToken(tokenDescriptor);
        return _handler.WriteToken(token);
    }

    // ── Validate ──────────────────────────────────────────────────────────────

    public BrdpTokenClaims? Validate(string token) =>
        ValidateInternal(token, _validationParameters);

    public BrdpTokenClaims? ValidateIgnoringExpiry(string token) =>
        ValidateInternal(token, _validationParametersIgnoreExpiry);

    private BrdpTokenClaims? ValidateInternal(string token, TokenValidationParameters parameters)
    {
        try
        {
            _handler.ValidateToken(token, parameters, out var validated);

            if (validated is not JwtSecurityToken jwt)
                return null;

            return new BrdpTokenClaims
            {
                Sub       = jwt.Subject,
                UserCode  = jwt.Claims.First(c => c.Type == "userCode").Value,
                Username  = jwt.Claims.First(c => c.Type == "username").Value,
                FirstName = jwt.Claims.First(c => c.Type == "firstName").Value,
                LastName  = jwt.Claims.First(c => c.Type == "lastName").Value,
            };
        }
        catch (SecurityTokenExpiredException)
        {
            // Caller decides what to do with expired tokens (e.g. refresh flow)
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "BrdpToken validation failed.");
            return null;
        }
    }
}
