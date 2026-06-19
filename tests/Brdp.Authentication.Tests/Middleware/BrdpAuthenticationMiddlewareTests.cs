using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Middleware;
using Brdp.Authentication.Models;
using Brdp.Authentication.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Brdp.Authentication.Tests.Middleware;

public sealed class BrdpAuthenticationMiddlewareTests
{
    private readonly Mock<ISessionService>   _sessions   = new();
    private readonly BrdpTokenService        _brdpTokens;
    private readonly AuthenticatedUserContextAccessor _accessor = new();

    private static readonly AuthenticationOptions Opts = new()
    {
        SigningKey = "middleware-test-signing-key-32chars!!",
        Issuer    = "TestIssuer",
        Audience  = "TestAudience",
    };

    public BrdpAuthenticationMiddlewareTests()
        => _brdpTokens = new BrdpTokenService(
               Options.Create(Opts),
               NullLogger<BrdpTokenService>.Instance);

    private BrdpAuthenticationMiddleware BuildSut(RequestDelegate? next = null)
        => new(
            next ?? (_ => Task.CompletedTask),
            _brdpTokens,
            _sessions.Object,
            Options.Create(Opts),
            NullLogger<BrdpAuthenticationMiddleware>.Instance);

    private string ValidToken() => _brdpTokens.Issue(new BrdpTokenClaims
    {
        Sub       = "99",
        UserCode  = "99",
        Username  = "testuser",
        FirstName = "Test",
        LastName  = "User",
    }, DateTimeOffset.UtcNow.AddHours(1));

    private static RedisSession MatchingSession() => new()
    {
        UserCode           = "99",
        Username           = "testuser",
        FirstName          = "Test",
        LastName           = "User",
        ClientIp           = "127.0.0.1",
        SsoAccessToken     = "access",
        SsoRefreshToken    = "refresh",
        AccessTokenExpiry  = DateTimeOffset.UtcNow.AddHours(1),
        RefreshTokenExpiry = DateTimeOffset.UtcNow.AddHours(8),
    };

    [Fact]
    public async Task ValidToken_WithSession_PopulatesAccessor()
    {
        _sessions.Setup(s => s.GetByUsernameAsync("testuser", default))
                 .ReturnsAsync(MatchingSession());

        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = $"Bearer {ValidToken()}";

        await BuildSut().InvokeAsync(ctx, _accessor);

        ctx.Response.StatusCode.Should().Be(200);
        _accessor.Context.Should().NotBeNull();
        _accessor.Context!.UserCode.Should().Be("99");
    }

    [Fact]
    public async Task MissingToken_Returns401()
    {
        var ctx = new DefaultHttpContext();

        await BuildSut().InvokeAsync(ctx, _accessor);

        ctx.Response.StatusCode.Should().Be(401);
        _accessor.Context.Should().BeNull();
    }

    [Fact]
    public async Task ValidToken_NoSession_Returns401()
    {
        _sessions.Setup(s => s.GetByUsernameAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((RedisSession?)null);

        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = $"Bearer {ValidToken()}";

        await BuildSut().InvokeAsync(ctx, _accessor);

        ctx.Response.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task AnonymousPath_SkipsAuthentication()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/auth/login";

        await BuildSut().InvokeAsync(ctx, _accessor);

        ctx.Response.StatusCode.Should().Be(200);
        _accessor.Context.Should().BeNull();
        _sessions.Verify(s => s.GetByUsernameAsync(It.IsAny<string>(), default), Times.Never);
    }

    [Fact]
    public async Task UserCodeMismatch_Returns401()
    {
        var tamperedSession = MatchingSession() with { };
        // Simulate a session belonging to a different userCode.
        var mismatchSession = new RedisSession
        {
            UserCode           = "DIFFERENT",
            Username           = "testuser",
            FirstName          = "Test",
            LastName           = "User",
            ClientIp           = "127.0.0.1",
            SsoAccessToken     = "x",
            SsoRefreshToken    = "x",
            AccessTokenExpiry  = DateTimeOffset.UtcNow.AddHours(1),
            RefreshTokenExpiry = DateTimeOffset.UtcNow.AddHours(8),
        };

        _sessions.Setup(s => s.GetByUsernameAsync("testuser", default))
                 .ReturnsAsync(mismatchSession);

        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = $"Bearer {ValidToken()}";

        await BuildSut().InvokeAsync(ctx, _accessor);

        ctx.Response.StatusCode.Should().Be(401);
    }
}
