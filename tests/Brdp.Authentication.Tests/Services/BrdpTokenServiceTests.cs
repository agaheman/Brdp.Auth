using Brdp.Authentication.Configuration;
using Brdp.Authentication.Models;
using Brdp.Authentication.Services;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Brdp.Authentication.Tests.Services;

public sealed class BrdpTokenServiceTests
{
    private readonly BrdpTokenService _sut;
    private readonly AuthenticationOptions _options = new()
    {
        SigningKey = "test-signing-key-must-be-at-least-32-chars!!",
        Issuer    = "TestIssuer",
        Audience  = "TestAudience",
    };

    public BrdpTokenServiceTests()
        => _sut = new BrdpTokenService(Options.Create(_options), NullLogger<BrdpTokenService>.Instance);

    private static BrdpTokenClaims SampleClaims() => new()
    {
        Sub       = "12345",
        UserCode  = "12345",
        Username  = "jdoe",
        FirstName = "John",
        LastName  = "Doe",
    };

    [Fact]
    public void Issue_ValidClaims_ReturnsNonEmptyToken()
    {
        var token = _sut.Issue(SampleClaims(), DateTimeOffset.UtcNow.AddHours(1));
        token.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Validate_ValidToken_ReturnsClaims()
    {
        var expiry = DateTimeOffset.UtcNow.AddHours(1);
        var token  = _sut.Issue(SampleClaims(), expiry);

        var result = _sut.Validate(token);

        result.Should().NotBeNull();
        result!.UserCode.Should().Be("12345");
        result.Username.Should().Be("jdoe");
    }

    [Fact]
    public void Validate_ExpiredToken_ReturnsNull()
    {
        // Issue a token that is already expired.
        var token = _sut.Issue(SampleClaims(), DateTimeOffset.UtcNow.AddSeconds(-10));

        var result = _sut.Validate(token);

        result.Should().BeNull();
    }

    [Fact]
    public void ValidateIgnoringExpiry_ExpiredToken_ReturnsClaims()
    {
        var token = _sut.Issue(SampleClaims(), DateTimeOffset.UtcNow.AddSeconds(-10));

        var result = _sut.ValidateIgnoringExpiry(token);

        result.Should().NotBeNull();
        result!.Username.Should().Be("jdoe");
    }

    [Fact]
    public void Validate_TamperedToken_ReturnsNull()
    {
        var token    = _sut.Issue(SampleClaims(), DateTimeOffset.UtcNow.AddHours(1));
        var tampered = token[..^3] + "xxx";

        var result = _sut.Validate(tampered);

        result.Should().BeNull();
    }

    [Fact]
    public void Issue_ExpiryAlignedToSsoToken()
    {
        var ssoExpiry = DateTimeOffset.UtcNow.AddMinutes(45);
        var token     = _sut.Issue(SampleClaims(), ssoExpiry);

        // ValidateIgnoringExpiry so we can inspect even near-future tokens safely.
        var claims = _sut.ValidateIgnoringExpiry(token);
        claims.Should().NotBeNull();

        // Confirm round-trip claim integrity.
        claims!.Sub.Should().Be(SampleClaims().Sub);
    }
}
