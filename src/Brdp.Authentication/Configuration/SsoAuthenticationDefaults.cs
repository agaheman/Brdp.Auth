namespace Brdp.Authentication.Configuration;

/// <summary>
/// Authentication scheme name constants used across the application.
/// Centralised here to avoid magic strings in controllers and extension methods.
/// </summary>
public static class SsoAuthenticationDefaults
{
    public const string OidcScheme   = "TpsSso";
    public const string CookieScheme = "TpsSsoCookie";
}
