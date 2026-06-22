using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Brdp.Authentication.Middleware;

/// <summary>
/// First middleware in the BFF pipeline. Establishes a correlation id for the
/// request and opens a logging scope so that <b>every</b> log line emitted while
/// the request is handled — middleware, controllers, services, infrastructure —
/// carries the same <c>CorrelationId</c> and <c>TraceId</c>.
///
/// Behaviour:
///   • Reads an inbound <c>X-Correlation-ID</c> (set by the SPA / upstream gateway)
///     so a single id can span the SPA request and the BFF.
///   • Generates one (preferring the W3C trace id) when the header is absent.
///   • Echoes it back in the <c>X-Correlation-ID</c> response header and adds it to
///     <c>Access-Control-Expose-Headers</c> so a cross-origin SPA can read it.
///
/// Stitching a multi-step flow (login → callback → branch → refresh → logout):
///   1. The SPA replays the same X-Correlation-ID header across the steps it controls.
///   2. <see cref="BrdpAuthenticationMiddleware"/> additionally pushes Username +
///      SessionId into the scope, giving a stable join key even across the OIDC
///      browser redirects where the header cannot be propagated.
/// </summary>
public sealed class CorrelationMiddleware
{
    public const string HeaderName = "X-Correlation-ID";

    private readonly RequestDelegate                _next;
    private readonly ILogger<CorrelationMiddleware> _logger;

    public CorrelationMiddleware(RequestDelegate next, ILogger<CorrelationMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = ResolveCorrelationId(context);

        // Make it reachable to anyone holding the HttpContext and to the SPA.
        context.Items[HeaderName]            = correlationId;
        context.Response.Headers[HeaderName] = correlationId;
        context.Response.Headers.AccessControlExposeHeaders =
            AppendExposedHeader(context.Response.Headers.AccessControlExposeHeaders, HeaderName);

        // Tag the ambient Activity so the id also flows into distributed tracing / APM.
        Activity.Current?.SetTag("brdp.correlation_id", correlationId);

        // Open the scope: all downstream log lines inherit CorrelationId + TraceId.
        using (_logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId,
            ["TraceId"]       = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier,
        }))
        {
            _logger.LogInformation(
                "Request {Method} {Path} started.", context.Request.Method, context.Request.Path);

            await _next(context).ConfigureAwait(false);

            _logger.LogInformation(
                "Request {Method} {Path} completed with {StatusCode}.",
                context.Request.Method, context.Request.Path, context.Response.StatusCode);
        }
    }

    private static string ResolveCorrelationId(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(HeaderName, out var inbound) &&
            !string.IsNullOrWhiteSpace(inbound))
            return inbound.ToString();

        // Prefer the W3C trace id so BFF logs line up with upstream distributed traces.
        return Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N");
    }

    private static string AppendExposedHeader(string? existing, string header)
    {
        if (string.IsNullOrWhiteSpace(existing))
            return header;

        return existing.Contains(header, StringComparison.OrdinalIgnoreCase)
            ? existing
            : $"{existing}, {header}";
    }
}
