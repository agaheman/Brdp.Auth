namespace Brdp.Authentication.Configuration;

/// <summary>
/// Shared constant names used to wire up the BFF middleware pipeline
/// (CORS policy, rate-limiter policy, response headers).
/// </summary>
public static class BrdpAuthConstants
{
    /// <summary>Name of the CORS policy registered for the SPA origin(s).</summary>
    public const string CorsPolicy = "BrdpSpaCors";
}
