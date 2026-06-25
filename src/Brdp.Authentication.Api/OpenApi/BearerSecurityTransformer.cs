using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi.Models;

namespace Brdp.Authentication.Api.OpenApi;

/// <summary>
/// Injects a global Bearer / JWT security scheme into the OpenAPI document so
/// Swagger UI shows the Authorize button and sends Authorization: Bearer headers.
/// </summary>
internal sealed class BearerSecurityTransformer : IOpenApiDocumentTransformer
{
    private const string SchemeId = "Bearer";

    public Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        document.Components ??= new OpenApiComponents();

        document.Components.SecuritySchemes[SchemeId] = new OpenApiSecurityScheme
        {
            Name        = "Authorization",
            Type        = SecuritySchemeType.Http,
            Scheme      = "bearer",
            BearerFormat = "JWT",
            In          = ParameterLocation.Header,
            Description =
                "Paste your **BrdpToken** (HS256 JWT issued by `/auth/signin-callback`).\n\n" +
                "Do **not** include the `Bearer ` prefix — Swagger UI adds it automatically.\n\n" +
                "Get the token from the browser console after signing in:\n" +
                "`localStorage.getItem('dotin.brdpToken')`",
        };

        // Add global security requirement — every endpoint requires Bearer unless
        // overridden individually. Anonymous endpoints still work without a token;
        // this only affects Swagger UI display (shows the lock icon on all operations).
        var requirement = new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id   = SchemeId,
                    }
                },
                []
            }
        };

        document.SecurityRequirements.Add(requirement);

        return Task.CompletedTask;
    }
}
