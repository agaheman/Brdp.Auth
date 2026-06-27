using Brdp.Authentication.Abstractions;

namespace Brdp.Authentication.Models;

/// <summary>
/// Immutable user context built once per request by the authentication middleware.
/// Constructed by combining BrdpToken claims with Redis session data.
/// </summary>
internal sealed class AuthenticatedUserContext : IAuthenticatedUserContext
{
    public required string  UserCode     { get; init; }
    public required string  Username     { get; init; }
    public required string  FirstName    { get; init; }
    public required string  LastName     { get; init; }
    public          string? BranchCode   { get; init; }
    public required string  ClientIp     { get; init; }
    public required string  SessionId    { get; init; }
    public          bool    IsBranchUser { get; init; }

    /// <summary>
    /// Factory method — creates context from validated Redis session.
    /// The Redis session is the authoritative source; token claims are only used
    /// for the identity verification step (UserCode comparison) before this is called.
    /// </summary>
    public static AuthenticatedUserContext FromSession(RedisSession session) =>
        new()
        {
            // Identity exposed downstream comes from the API Gateway token half
            // (the minimal claims the UI uses); branch flags too.
            UserCode     = session.ApiGateway.UserCode,
            Username     = session.ApiGateway.Username,
            FirstName    = session.ApiGateway.FirstName,
            LastName     = session.ApiGateway.LastName,
            BranchCode   = session.ApiGateway.BranchCode,
            IsBranchUser = session.ApiGateway.IsBranchUser,
            ClientIp     = session.ClientIp,
            SessionId    = session.SessionId,
        };
}
