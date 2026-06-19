using Brdp.Authentication.Abstractions;

namespace Brdp.Authentication.Services;

/// <summary>
/// Scoped implementation of <see cref="IAuthenticatedUserContextAccessor"/>.
///
/// Lifetime: Scoped — one instance per HTTP request.
/// The authentication middleware sets <see cref="Context"/> early in the pipeline.
/// All downstream services and controllers resolve this via DI and call
/// <see cref="GetRequiredContext"/> — no coupling to <c>HttpContext</c> or <c>IHttpContextAccessor</c>.
/// </summary>
internal sealed class AuthenticatedUserContextAccessor : IAuthenticatedUserContextAccessor
{
    /// <inheritdoc/>
    public IAuthenticatedUserContext? Context { get; set; }

    /// <inheritdoc/>
    public IAuthenticatedUserContext GetRequiredContext()
    {
        if (Context is null)
            throw new InvalidOperationException(
                "IAuthenticatedUserContext has not been set. " +
                "Ensure UseBrdpAuthentication() middleware is registered before any endpoint that " +
                "requires an authenticated user context.");

        return Context;
    }
}
