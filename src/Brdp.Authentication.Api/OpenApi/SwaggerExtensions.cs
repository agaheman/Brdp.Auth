using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi.Models;

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
            options.AddDocumentTransformer<BearerSecurityTransformer>();

            options.AddDocumentTransformer((doc, _, _) =>
            {
                doc.Info = new OpenApiInfo
                {
                    Title       = "Brdp Authentication API",
                    Version     = "v1",
                    Description =
                        "BFF (Backend-For-Frontend) authentication gateway.\n\n" +
                        "**How to authenticate:**\n" +
                        "1. Open `/index.html` and complete the SSO sign-in flow.\n" +
                        "2. Copy your BrdpToken from the browser console:\n" +
                        "   `localStorage.getItem('dotin.brdpToken')`\n" +
                        "3. Click **Authorize** (padlock icon), paste the token, click **Authorize**.\n" +
                        "4. All requests from Swagger UI will carry `Authorization: Bearer <token>`.",
                };
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

        // Swagger UI served from CDN — no extra NuGet package required.
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
            SwaggerUIBundle({
              url: "{{openApiJsonUrl}}",
              dom_id: "#swagger-ui",
              presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
              layout: "StandaloneLayout",
              persistAuthorization: true,
              displayRequestDuration: true,
              defaultModelsExpandDepth: -1,
              tryItOutEnabled: true,
            });
          </script>
        </body>
        </html>
        """;
}
