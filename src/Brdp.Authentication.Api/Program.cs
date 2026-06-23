using Brdp.Authentication.Extensions;

var builder = WebApplication.CreateBuilder(args);
Console.WriteLine(builder.Environment.EnvironmentName);
// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);
builder.Services.AddOpenApi();

// ── Build ─────────────────────────────────────────────────────────────────────
var app = builder.Build();

// ── Middleware pipeline ───────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.MapOpenApi();
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
