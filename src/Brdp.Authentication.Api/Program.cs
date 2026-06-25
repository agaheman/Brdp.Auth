using Brdp.Authentication.Api.OpenApi;
using Brdp.Authentication.Extensions;

// Allow Persian / Arabic / other multi-byte characters to render correctly
// in the console instead of appearing as '????'.
Console.OutputEncoding = System.Text.Encoding.UTF8;

var builder = WebApplication.CreateBuilder(args);
// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

if (builder.Environment.IsDevelopment())
    builder.Services.AddBrdpSwagger();

// ── Build ─────────────────────────────────────────────────────────────────────
var app = builder.Build();

// ── Middleware pipeline ───────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseBrdpSwagger();
}

app.UseHttpsRedirection();

// Serve the static "Dotin Authentication Sample" SPA from wwwroot. Registered
// before the BFF middleware so static assets are returned without an auth check.
app.UseDefaultFiles();
app.UseStaticFiles();

// 1. ASP.NET Core cookie/OIDC scheme (handles /signin-oidc callback internally).
app.UseAuthentication();

// 2. BFF middleware: forwarded headers → CORS → rate limiter → correlation
//    → token refresh → auth context build. Authorization is enforced inside
//    BrdpAuthenticationMiddleware against the Redis session (not the ASP.NET
//    authorization stack), so UseAuthorization() is intentionally absent.
app.UseBrdpAuthentication();

// 3. Controllers.
app.MapControllers();

// 4. Health/readiness probe (verifies Redis connectivity).
app.MapHealthChecks("/health");

app.Run();
