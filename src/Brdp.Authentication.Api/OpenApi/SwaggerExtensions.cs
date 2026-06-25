using Microsoft.AspNetCore.OpenApi;

namespace Brdp.Authentication.Api.OpenApi;

/// <summary>
/// Registers and configures OpenAPI + Swagger UI for the Brdp Authentication API.
/// See SWAGGER.md in this folder for usage and integration notes.
/// </summary>
public static class SwaggerExtensions
{
    private const string OpenApiRoute = "/openapi/v1.json";

    // ── Service registration ──────────────────────────────────────────────────

    public static IServiceCollection AddBrdpSwagger(this IServiceCollection services)
    {
        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer((doc, _, _) =>
            {
                doc.Info.Title       = "Brdp Authentication API";
                doc.Info.Version     = "v1";
                doc.Info.Description =
                    "BFF (Backend-For-Frontend) authentication gateway.\n\n" +
                    "**Authentication is automatic** — if you have signed in via `/index.html` " +
                    "your BrdpToken is already in `localStorage` and every request from this UI " +
                    "will include `Authorization: Bearer <token>` automatically.\n\n" +
                    "If you need to set the token manually, run in the browser console:\n" +
                    "`localStorage.getItem('dotin.brdpToken')`";

                return Task.CompletedTask;
            });
        });

        return services;
    }

    // ── Middleware pipeline ───────────────────────────────────────────────────

    public static WebApplication UseBrdpSwagger(this WebApplication app)
    {
        // Built-in OpenAPI document endpoint: GET /openapi/v1.json
        app.MapOpenApi();

        // Swagger UI served from unpkg CDN — no extra NuGet packages required.
        // The requestInterceptor auto-attaches the BrdpToken from localStorage so
        // the user never needs to click Authorize and paste a token manually.
        app.MapGet("/swagger", () => Results.Content(SwaggerUiHtml(OpenApiRoute), "text/html"))
           .ExcludeFromDescription();

        return app;
    }

    // ── Swagger UI HTML ───────────────────────────────────────────────────────

    private static string SwaggerUiHtml(string openApiJsonUrl) => $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8"/>
          <meta name="viewport" content="width=device-width, initial-scale=1"/>
          <title>Brdp Authentication API — Swagger UI</title>
          <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
          <style>
            body { margin: 0; }
            .topbar { display: none !important; }
          </style>
        </head>
        <body>
          <div id="swagger-ui"></div>
          <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
          <script>
            const TOKEN_KEY = "dotin.brdpToken";

            SwaggerUIBundle({
              url: "{{openApiJsonUrl}}",
              dom_id: "#swagger-ui",
              presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
              layout: "StandaloneLayout",
              displayRequestDuration: true,
              defaultModelsExpandDepth: -1,
              tryItOutEnabled: true,

              // Auto-inject BrdpToken from localStorage on every request.
              // No need to click Authorize — just sign in via /index.html first.
              requestInterceptor: (request) => {
                const token = localStorage.getItem(TOKEN_KEY);
                if (token) {
                  request.headers["Authorization"] = "Bearer " + token;
                }
                return request;
              },

              // Show the active token status in the UI description area.
              onComplete: () => {
                const token = localStorage.getItem(TOKEN_KEY);
                const banner = document.createElement("div");
                banner.style.cssText =
                  "background:#1a3a1a;border:1px solid #22c55e;border-radius:6px;" +
                  "padding:10px 16px;margin:12px 16px;font-size:13px;color:#86efac;font-family:monospace";
                banner.textContent = token
                  ? "✓ BrdpToken loaded from localStorage — requests are pre-authenticated."
                  : "⚠ No BrdpToken in localStorage. Sign in via /index.html first.";
                const info = document.querySelector(".swagger-ui .information-container");
                if (info) info.after(banner);
              },
            });
          </script>
        </body>
        </html>
        """;
}
