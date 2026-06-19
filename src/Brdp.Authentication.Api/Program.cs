using Brdp.Authentication.Extensions;

var builder = WebApplication.CreateBuilder(args);

// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddBrdpAuthentication(builder.Configuration, builder.Environment);

// ── Build ─────────────────────────────────────────────────────────────────────
var app = builder.Build();

// ── Middleware pipeline ───────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();

app.UseHttpsRedirection();

// Order matters:
// 1. ASP.NET Core cookie/OIDC scheme (handles /signin-oidc callback internally).
app.UseAuthentication();

// 2. BFF middleware: refresh → auth context build.
app.UseBrdpAuthentication();

// 3. Authorization (if [Authorize] attributes are used).
app.UseAuthorization();

// 4. Controllers.
app.MapControllers();

// 5. Health check (anonymous).
app.MapGet("/health", () => Results.Ok(new { status = "healthy", utc = DateTimeOffset.UtcNow }));

app.Run();
