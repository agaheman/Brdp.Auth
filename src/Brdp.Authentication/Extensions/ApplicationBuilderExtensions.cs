using Brdp.Authentication.Configuration;
using Brdp.Authentication.Middleware;
using Microsoft.AspNetCore.Builder;

namespace Brdp.Authentication.Extensions;

/// <summary>
/// Registers the BFF authentication middleware pipeline.
/// Usage in <c>Program.cs</c> (call early, before <c>UseAuthentication()</c>):
/// <code>
///   app.UseBrdpAuthentication();
/// </code>
///
/// Middleware order is enforced here:
///   1. <see cref="Microsoft.AspNetCore.Builder.ForwardedHeadersExtensions"/> — restore real client IP / scheme behind the gateway.
///   2. CORS                                       — expose X-New-BrdpToken / X-Correlation-ID to the SPA.
///   3. Rate limiter                               — throttle the /auth surface.
///   4. <see cref="CorrelationMiddleware"/>        — open the correlation/logging scope for the whole request.
///   5. <see cref="TokenRefreshMiddleware"/>       — silently rotate tokens before the auth check.
///   6. <see cref="BrdpAuthenticationMiddleware"/> — validate token + Redis session, set IAuthenticatedUserContextAccessor.
/// </summary>
public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseBrdpAuthentication(this IApplicationBuilder app)
    {
        app.UseForwardedHeaders();
        app.UseCors(BrdpAuthConstants.CorsPolicy);
        app.UseRateLimiter();

        app.UseMiddleware<CorrelationMiddleware>();
        app.UseMiddleware<TokenRefreshMiddleware>();
        app.UseMiddleware<BrdpAuthenticationMiddleware>();
        return app;
    }
}
