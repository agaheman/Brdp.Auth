using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Infrastructure;
using Brdp.Authentication.Security;
using Brdp.Authentication.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
        IConfiguration          configuration,
        IHostEnvironment        environment)
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

        // ── Redis ─────────────────────────────────────────────────────────────
        var redisConnection = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException(
                "Redis connection string 'Redis' is required in ConnectionStrings.");

        services.AddSingleton<IConnectionMultiplexer>(
            ConnectionMultiplexer.Connect(redisConnection));

        // ── Encryption ────────────────────────────────────────────────────────
        var encryptAtRest = configuration
            .GetSection(AuthenticationOptions.SectionName)
            .GetValue<bool>("EncryptTokensAtRest");

        if (encryptAtRest || environment.IsProduction())
        {
            services.AddDataProtection();
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
        services.AddScoped<ISessionService,                   SessionService>();
        services.AddSingleton<IBrdpTokenService,              BrdpTokenService>();
        services.AddScoped<ISsoTokenService,                  SsoTokenService>();
        services.AddScoped<IBranchService,                    BranchService>();

        // ── SSO HTTP Client ───────────────────────────────────────────────────
        services
            .AddHttpClient<SsoHttpClient>(client =>
            {
                var authority = configuration
                    .GetSection(SsoAuthenticationOptions.SectionName)
                    .GetValue<string>("Authority")
                    ?? throw new InvalidOperationException("SsoAuthentication:Authority is required.");

                client.BaseAddress = new Uri(authority);
                client.Timeout     = TimeSpan.FromSeconds(15);
            });

        // ── OIDC / Cookie Authentication ──────────────────────────────────────
        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme          = SsoAuthenticationDefaults.CookieScheme;
                options.DefaultChallengeScheme = SsoAuthenticationDefaults.OidcScheme;
            })
            .AddCookie(SsoAuthenticationDefaults.CookieScheme, options =>
            {
                options.Cookie.Name     = "brdp_session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.Cookie.SecurePolicy = environment.IsProduction()
                    ? Microsoft.AspNetCore.Http.CookieSecurePolicy.Always
                    : Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
            })
            .AddOpenIdConnect(SsoAuthenticationDefaults.OidcScheme, options =>
            {
                var sso = configuration.GetSection(SsoAuthenticationOptions.SectionName);

                options.Authority            = sso["Authority"];
                options.MetadataAddress      = sso["MetadataAddress"];
                options.ClientId             = sso["ClientId"];
                options.ClientSecret         = sso["ClientSecret"];
                options.ResponseType         = sso["ResponseType"] ?? "code";
                options.CallbackPath         = sso["CallbackPath"] ?? "/signin-oidc";
                options.SignedOutCallbackPath = sso["SignedOutCallbackPath"] ?? "/signout-callback-oidc";
                options.SaveTokens           = true;  // Required: tokens stored in cookie for /auth/callback
                options.GetClaimsFromUserInfoEndpoint = true;

                var scopes = sso.GetSection("Scopes").Get<string[]>() ?? ["openid", "profile"];
                options.Scope.Clear();
                foreach (var scope in scopes)
                    options.Scope.Add(scope);

                options.RequireHttpsMetadata = environment.IsProduction();
            });

        // ── MVC Controllers ───────────────────────────────────────────────────
        services.AddControllers()
            .AddApplicationPart(typeof(ServiceCollectionExtensions).Assembly);

        return services;
    }
}
