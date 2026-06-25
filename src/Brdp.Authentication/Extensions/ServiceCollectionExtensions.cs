using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Infrastructure;
using Brdp.Authentication.Security;
using Brdp.Authentication.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace Brdp.Authentication.Extensions;

/// <summary>
/// Fluent registration of all BFF authentication services.
/// Usage in <c>Program.cs</c>:
/// <code>
///   builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);
/// </code>
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddBrdpAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        // ── Configuration ─────────────────────────────────────────────────────
        services
            .AddOptions<AuthenticationOptions>()
            .Bind(configuration.GetSection(AuthenticationOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddOptions<SsoAuthenticationOptions>()
            .Bind(configuration.GetSection(SsoAuthenticationOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var authSection = configuration.GetSection(AuthenticationOptions.SectionName);

        // ── Redis (resilient connection) ───────────────────────────────────────
        var redisConnection = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException(
                "Redis connection string 'Redis' is required in ConnectionStrings.");

        // AbortOnConnectFail=false: the app boots even if Redis is briefly unavailable
        // and reconnects in the background instead of crashing at startup.
        var redisConfig = ConfigurationOptions.Parse(redisConnection);
        redisConfig.AbortOnConnectFail = false;
        redisConfig.ConnectRetry       = 3;
        redisConfig.ConnectTimeout     = 5_000;

        var multiplexer = ConnectionMultiplexer.Connect(redisConfig);
        services.AddSingleton<IConnectionMultiplexer>(multiplexer);

        // ── Encryption + Data Protection key ring ──────────────────────────────
        var encryptAtRest = authSection.GetValue<bool>("EncryptTokensAtRest");

        if (encryptAtRest || environment.IsProduction())
        {
            // Persist keys to Redis (shared application name) so encrypted sessions
            // survive restarts and are decryptable across every instance.
            services
                .AddDataProtection()
                .SetApplicationName("Brdp.Authentication")
                .PersistKeysToStackExchangeRedis(multiplexer, "auth:dataprotection-keys");

            services.AddSingleton<ITokenEncryptionService, DataProtectionTokenEncryptionService>();
        }
        else
        {
            services.AddSingleton<ITokenEncryptionService, NoOpTokenEncryptionService>();
        }

        // ── Infrastructure ────────────────────────────────────────────────────
        services.AddSingleton<RedisSessionStore>();

        // ── Services ──────────────────────────────────────────────────────────
        services.AddScoped<IAuthenticatedUserContextAccessor, AuthenticatedUserContextAccessor>();
        services.AddScoped<ISessionService, SessionService>();
        services.AddSingleton<IBrdpTokenService, BrdpTokenService>();
        services.AddScoped<ISsoTokenService, SsoTokenService>();
        services.AddScoped<IBranchService, BranchService>();

        // ── SSO HTTP Client ───────────────────────────────────────────────────
        var ssoClientBuilder = services
            .AddHttpClient<SsoHttpClient>(client =>
            {
                var authority = configuration
                    .GetSection(SsoAuthenticationOptions.SectionName)
                    .GetValue<string>("Authority")
                    ?? throw new InvalidOperationException("SsoAuthentication:Authority is required.");

                client.BaseAddress = new Uri(authority);
                client.Timeout = TimeSpan.FromSeconds(15);
            });

        // Same untrusted-CA bypass for the SSO HTTP client (token refresh / revoke calls).
        if (!environment.IsProduction())
            ssoClientBuilder.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            });

        // ── Forwarded headers (BFF runs behind a gateway / reverse proxy) ──────
        // Honours X-Forwarded-For / X-Forwarded-Proto so RemoteIpAddress and the
        // HTTPS scheme reflect the real client rather than the proxy.
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            // The gateway is trusted; clear the default loopback-only restriction.
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
        });

        // ── CORS (so the SPA can read X-New-BrdpToken / X-Correlation-ID) ──────
        // The policy is always registered (so UseCors is always safe). When no origins
        // are configured the policy simply allows none — i.e. same-origin only.
        var allowedOrigins = authSection.GetSection("AllowedCorsOrigins").Get<string[]>() ?? [];
        services.AddCors(options => options.AddPolicy(BrdpAuthConstants.CorsPolicy, policy =>
            policy
                .WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials()
                .WithExposedHeaders(
                    Middleware.CorrelationMiddleware.HeaderName,
                    Middleware.TokenRefreshMiddleware.NewTokenHeader,
                    Middleware.TokenRefreshMiddleware.AuthErrorHeader)));

        // ── Rate limiting on the auth surface ──────────────────────────────────
        // A global limiter keyed by client IP that only throttles "/auth/*"; every
        // other path gets a no-op partition. This avoids any dependency on endpoint
        // routing order in the host pipeline.
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                if (!httpContext.Request.Path.StartsWithSegments("/auth", StringComparison.OrdinalIgnoreCase))
                    return RateLimitPartition.GetNoLimiter("unlimited");

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 60,
                        Window      = TimeSpan.FromMinutes(1),
                        QueueLimit  = 0,
                    });
            });
        });

        // ── OIDC / Cookie Authentication ──────────────────────────────────────
        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = SsoAuthenticationDefaults.CookieScheme;
                options.DefaultChallengeScheme = SsoAuthenticationDefaults.OidcScheme;
            })
            .AddCookie(SsoAuthenticationDefaults.CookieScheme, options =>
            {
                options.Cookie.Name = "brdp_session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = environment.IsProduction()
                    ? CookieSecurePolicy.Always
                    : CookieSecurePolicy.SameAsRequest;
            })
            .AddOpenIdConnect(SsoAuthenticationDefaults.OidcScheme, options =>
            {
                var sso = configuration.GetSection(SsoAuthenticationOptions.SectionName);

                options.Authority = sso["Authority"];
                options.MetadataAddress = sso["MetadataAddress"];
                options.ClientId = sso["ClientId"];
                options.ClientSecret = sso["ClientSecret"];
                options.ResponseType = sso["ResponseType"] ?? "code";
                options.CallbackPath = sso["CallbackPath"] ?? "/signin-oidc";
                options.SignedOutCallbackPath = sso["SignedOutCallbackPath"] ?? "/signout-callback-oidc";
                options.SaveTokens = true;  // Required: tokens stored in cookie for /auth/SignInCallback
                options.GetClaimsFromUserInfoEndpoint = true;

                // PKCE on by default; some confidential-client servers reject the
                // client_secret + code_verifier combination, so it can be disabled.
                options.UsePkce = sso.GetValue("UsePkce", true);

                var scopes = sso.GetSection("Scopes").Get<string[]>() ?? [];
                options.Scope.Clear();
                foreach (var s in scopes.Where(s => !string.IsNullOrWhiteSpace(s)))
                    options.Scope.Add(s);

                options.RequireHttpsMetadata = environment.IsProduction();

                // Some SSO servers compute the id_token's at_hash claim incorrectly,
                // making the compliant .NET validator reject a valid login (IDX21348).
                // When configured, swap in a validator that skips only the at_hash check;
                // the id_token signature is still fully validated.
                if (sso.GetValue<bool>("SkipAtHashValidation"))
                {
                    // Preserve the handler's default validator settings (ASP.NET Core sets
                    // RequireStateValidation=false and NonceLifetime=60m) — only at_hash changes.
                    var defaults = options.ProtocolValidator;
                    options.ProtocolValidator = new NoAtHashProtocolValidator
                    {
                        RequireStateValidation = defaults.RequireStateValidation,
                        RequireNonce           = defaults.RequireNonce,
                        NonceLifetime          = defaults.NonceLifetime,
                    };
                }

                // In non-production the SSO server may use an internal/self-signed CA.
                // Bypass TLS validation only for the OIDC backchannel (metadata + token endpoint).
                if (!environment.IsProduction())
                {
                    options.BackchannelHttpHandler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback =
                            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };
                }

                // The SSO client is registered with token_endpoint_auth_method =
                // client_secret_jwt. Instead of sending the secret as a plain form
                // field (client_secret_post, the .NET default), authenticate with a
                // short-lived JWT client assertion signed (HS256) with the client
                // secret. Without this the token endpoint rejects the request.
                if (sso.GetValue<bool>("UseClientSecretJwt"))
                {
                    options.Events.OnAuthorizationCodeReceived = async ctx =>
                    {
                        if (ctx.TokenEndpointRequest is null) return;

                        var oidcConfig = await ctx.Options.ConfigurationManager!
                            .GetConfigurationAsync(ctx.HttpContext.RequestAborted)
                            .ConfigureAwait(false);

                        // Audience defaults to the discovered token endpoint (RFC 7523 §3);
                        // override via ClientAssertionAudience if the SSO expects the issuer.
                        var configuredAudience = sso["ClientAssertionAudience"];
                        var audience = !string.IsNullOrWhiteSpace(configuredAudience)
                            ? configuredAudience
                            : oidcConfig.TokenEndpoint;

                        var assertion = BuildClientSecretJwt(
                            ctx.Options.ClientId!, ctx.Options.ClientSecret!, audience!);

                        // Swap client_secret_post for client_secret_jwt on the token request.
                        ctx.TokenEndpointRequest.ClientSecret        = null;
                        ctx.TokenEndpointRequest.ClientAssertionType = ClientAssertionJwtBearer;
                        ctx.TokenEndpointRequest.ClientAssertion     = assertion;

                        // Diagnostic: log what we send so the audience/claims can be matched
                        // against the SSO's expectations when it returns invalid_client.
                        ctx.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Brdp.Authentication.Oidc")
                            .LogInformation(
                                "client_secret_jwt → token_endpoint={TokenEndpoint}, issuer={Issuer}, " +
                                "assertion aud={Audience}, iss=sub={ClientId}, alg=HS256",
                                oidcConfig.TokenEndpoint, oidcConfig.Issuer, audience, ctx.Options.ClientId);
                    };
                }

                // Capture the non-standard refresh_expires_in so the Redis session TTL
                // reflects the SSO's real refresh-token lifetime instead of a guess.
                options.Events.OnTokenResponseReceived = ctx =>
                {
                    var refreshExpiresIn = ctx.TokenEndpointResponse?.GetParameter("refresh_expires_in");
                    if (!string.IsNullOrEmpty(refreshExpiresIn) && ctx.Properties is not null)
                        ctx.Properties.Items["sso.refresh_expires_in"] = refreshExpiresIn;
                    return Task.CompletedTask;
                };

                // When SSO returns an error (access_denied, invalid_request, server_error…)
                // the OIDC middleware fires OnRemoteFailure before our action runs.
                // Without this handler the exception surfaces as a 500. Instead: log it
                // and redirect to the SPA callback page so the user sees a friendly message.
                options.Events.OnRemoteFailure = ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices
                        .GetRequiredService<ILoggerFactory>()
                        .CreateLogger("Brdp.Authentication.Oidc");

                    // The OIDC handler buries the OAuth error code inside the exception
                    // message as: "Message contains error: '<code>', error_description: '…'"
                    // Extract it so the diagnostics page gets a clean code, not the full sentence.
                    var rawMessage = ctx.Failure?.Message ?? string.Empty;
                    var errorCode  = ExtractOidcErrorCode(rawMessage);
                    var errorDesc  = ExtractOidcErrorDescription(rawMessage);

                    logger.LogError(ctx.Failure,
                        "SSO remote failure — error: {OidcError}, description: {OidcErrorDescription}",
                        errorCode, errorDesc);

                    // Detect whether the failure came from the token endpoint (step 5 — code exchange)
                    // or from the authorization response itself (step 3 — SSO user auth).
                    var failedStep = ctx.Failure?.StackTrace?.Contains("RedeemAuthorizationCode") == true ? 5 : 3;

                    // Redirect to the SPA diagnostics page with enough context for the admin
                    // to identify which step failed without reading server logs.
                    var cid = ctx.HttpContext.Response.Headers["X-Correlation-ID"].FirstOrDefault();
                    var ts  = Uri.EscapeDataString(DateTimeOffset.UtcNow.ToString("O"));
                    var url = $"/error.html?error={Uri.EscapeDataString(errorCode)}&flow=auth&step={failedStep}&ts={ts}";
                    if (!string.IsNullOrEmpty(errorDesc)) url += $"&desc={Uri.EscapeDataString(errorDesc)}";
                    if (!string.IsNullOrEmpty(cid))       url += $"&cid={Uri.EscapeDataString(cid)}";

                    ctx.Response.Redirect(url);
                    ctx.HandleResponse();
                    return Task.CompletedTask;
                };
            });

        // ── Health checks (readiness probe — verifies Redis connectivity) ──────
        services.AddHealthChecks()
            .AddAsyncCheck("redis", async () =>
            {
                try
                {
                    await multiplexer.GetDatabase().PingAsync().ConfigureAwait(false);
                    return HealthCheckResult.Healthy();
                }
                catch (Exception ex)
                {
                    return HealthCheckResult.Unhealthy("Redis unreachable.", ex);
                }
            });

        // ── MVC Controllers ───────────────────────────────────────────────────
        services.AddControllers()
            .AddApplicationPart(typeof(ServiceCollectionExtensions).Assembly);

        return services;
    }

    // ── OIDC error extraction helpers ─────────────────────────────────────────
    // The ASP.NET Core OIDC handler formats remote failures as:
    //   "Message contains error: '<code>', error_description: '<desc>', error_uri: '…'"
    // These helpers pull the clean OAuth error code and description out of that sentence.

    private static string ExtractOidcErrorCode(string message)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            message, @"error:\s*'([^']+)'");
        return match.Success ? match.Groups[1].Value : "sso_error";
    }

    private static string? ExtractOidcErrorDescription(string message)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            message, @"error_description:\s*'([^']+)'");
        return match.Success ? match.Groups[1].Value : null;
    }

    // ── client_secret_jwt assertion ───────────────────────────────────────────

    private const string ClientAssertionJwtBearer =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /// <summary>
    /// Builds a short-lived JWT client assertion (RFC 7523) signed HS256 with the
    /// client secret, used for the <c>client_secret_jwt</c> token-endpoint auth method.
    /// </summary>
    private static string BuildClientSecretJwt(string clientId, string clientSecret, string audience)
    {
        var key   = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now   = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            issuer:   clientId,
            audience: audience,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            ],
            notBefore:          now,
            expires:            now.AddMinutes(5),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
