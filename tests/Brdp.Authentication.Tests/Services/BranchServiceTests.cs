using Brdp.Authentication.Abstractions;
using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Brdp.Authentication.Services;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Brdp.Authentication.Tests.Services;

public sealed class BranchServiceTests
{
    private readonly Mock<ISessionService>   _sessions   = new();
    private readonly Mock<ISsoTokenService>  _ssoTokens  = new();
    private readonly BrdpTokenService        _brdpTokens;
    private readonly BranchService           _sut;

    private static readonly AuthenticationOptions Options = new()
    {
        SigningKey = "branch-service-test-key-32-chars!!",
        Issuer    = "TestIssuer",
        Audience  = "TestAudience",
    };

    public BranchServiceTests()
    {
        _brdpTokens = new BrdpTokenService(
            Options.Create(Options),
            NullLogger<BrdpTokenService>.Instance);

        _sut = new BranchService(
            _sessions.Object,
            _ssoTokens.Object,
            _brdpTokens,
            NullLogger<BranchService>.Instance);
    }

    private static RedisSession SampleSession() => new()
    {
        UserCode           = "12345",
        Username           = "jdoe",
        FirstName          = "John",
        LastName           = "Doe",
        IsBranchUser       = true,
        ClientIp           = "10.1.1.1",
        SsoAccessToken     = "old-access",
        SsoRefreshToken    = "old-refresh",
        AccessTokenExpiry  = DateTimeOffset.UtcNow.AddHours(1),
        RefreshTokenExpiry = DateTimeOffset.UtcNow.AddHours(8),
    };

    private static SsoTokenResponse SampleUpgradeResponse() => new()
    {
        AccessToken      = "new-access-token",
        RefreshToken     = "new-refresh-token",
        ExpiresIn        = 3600,
        RefreshExpiresIn = 28800,
    };

    [Fact]
    public async Task SelectBranchAsync_HappyPath_ReturnsNewBrdpToken()
    {
        _sessions.Setup(s => s.GetByUsernameAsync("jdoe", default))
                 .ReturnsAsync(SampleSession());

        _ssoTokens.Setup(s => s.UpgradeAsync("old-access", "1001", default))
                  .ReturnsAsync(SampleUpgradeResponse());

        var result = await _sut.SelectBranchAsync("jdoe", "1001");

        result.BranchCode.Should().Be("1001");
        result.BrdpToken.Should().NotBeNullOrWhiteSpace();
        _sessions.Verify(s => s.UpdateAsync(It.Is<RedisSession>(r =>
            r.BranchCode == "1001" &&
            r.SsoAccessToken == "new-access-token"), default), Times.Once);
    }

    [Fact]
    public async Task SelectBranchAsync_NoSession_Throws()
    {
        _sessions.Setup(s => s.GetByUsernameAsync("jdoe", default))
                 .ReturnsAsync((RedisSession?)null);

        var act = () => _sut.SelectBranchAsync("jdoe", "1001");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*No active session*");
    }

    [Fact]
    public async Task SelectBranchAsync_UpgradeFails_Throws()
    {
        _sessions.Setup(s => s.GetByUsernameAsync("jdoe", default))
                 .ReturnsAsync(SampleSession());

        _ssoTokens.Setup(s => s.UpgradeAsync(It.IsAny<string>(), It.IsAny<string>(), default))
                  .ReturnsAsync((SsoTokenResponse?)null);

        var act = () => _sut.SelectBranchAsync("jdoe", "9999");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*SSO upgrade token call failed*");
    }

    [Fact]
    public async Task SelectBranchAsync_NewBrdpTokenExpiryAligned()
    {
        _sessions.Setup(s => s.GetByUsernameAsync("jdoe", default))
                 .ReturnsAsync(SampleSession());

        var upgradeResponse = SampleUpgradeResponse();
        _ssoTokens.Setup(s => s.UpgradeAsync("old-access", "1001", default))
                  .ReturnsAsync(upgradeResponse);

        var result = await _sut.SelectBranchAsync("jdoe", "1001");

        // The returned expiry must match what came back from SSO.
        result.AccessTokenExpiry.Should()
            .BeCloseTo(upgradeResponse.AccessTokenExpiry, precision: TimeSpan.FromSeconds(2));
    }
}
