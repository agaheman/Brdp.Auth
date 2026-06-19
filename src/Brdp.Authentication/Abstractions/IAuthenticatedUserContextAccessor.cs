namespace Brdp.Authentication.Abstractions;

/// <summary>
/// Scoped accessor for the current request's authenticated user context.
///
/// Design rationale:
///   • Services and controllers depend on this interface — never on HttpContext or IHttpContextAccessor.
///   • The middleware pipeline populates <see cref="Context"/> once per request after validating
///     the BrdpToken and reading the Redis session.
///   • Downstream code calls <see cref="GetRequiredContext"/> which throws a clear exception
///     if accessed before the middleware ran (programming error, not a user error).
/// </summary>
public interface IAuthenticatedUserContextAccessor
{
    /// <summary>
    /// The authenticated user context for this request.
    /// <c>null</c> before the authentication middleware has completed.
    /// </summary>
    IAuthenticatedUserContext? Context { get; set; }

    /// <summary>
    /// Returns <see cref="Context"/> or throws <see cref="InvalidOperationException"/>
    /// if called before the authentication middleware has set it.
    /// </summary>
    IAuthenticatedUserContext GetRequiredContext();
}
