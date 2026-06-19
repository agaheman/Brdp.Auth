using Brdp.Authentication.Middleware;
using Microsoft.AspNetCore.Builder;

namespace Brdp.Authentication.Extensions;

/// <summary>
/// Registers the BFF authentication middleware pipeline.
/// Usage in <c>Program.cs</c>:
/// <code>
///   app.UseBrdpAuthentication();
/// </code>
///
/// Middleware order is enforced here:
///   1. <see cref="TokenRefreshMiddleware"/>   — silently rotates tokens before auth check.
///   2. <see cref="BrdpAuthenticationMiddleware"/> — validates token + Redis session, sets IAuthenticatedUserContextAccessor.
/// </summary>
public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseBrdpAuthentication(this IApplicationBuilder app)
    {
        app.UseMiddleware<TokenRefreshMiddleware>();
        app.UseMiddleware<BrdpAuthenticationMiddleware>();
        return app;
    }
}
