using Brdp.Authentication.Infrastructure;
using FluentAssertions;

namespace Brdp.Authentication.Tests;

public sealed class RedisKeyHelperTests
{
    [Fact]
    public void SessionKey_StartsWithAuthPrefix()
    {
        var key = RedisKeyHelper.SessionKey("jdoe");
        key.Should().StartWith("auth:");
    }

    [Fact]
    public void SessionKey_SameUsername_SameKey()
    {
        var key1 = RedisKeyHelper.SessionKey("jdoe");
        var key2 = RedisKeyHelper.SessionKey("jdoe");
        key1.Should().Be(key2);
    }

    [Fact]
    public void SessionKey_CaseInsensitive()
    {
        var lower = RedisKeyHelper.SessionKey("jdoe");
        var upper = RedisKeyHelper.SessionKey("JDOE");
        lower.Should().Be(upper);
    }

    [Fact]
    public void SessionKey_DifferentUsernames_DifferentKeys()
    {
        var key1 = RedisKeyHelper.SessionKey("jdoe");
        var key2 = RedisKeyHelper.SessionKey("jsmith");
        key1.Should().NotBe(key2);
    }

    [Fact]
    public void SessionKey_EmptyUsername_Throws()
    {
        var act = () => RedisKeyHelper.SessionKey(string.Empty);
        act.Should().Throw<ArgumentException>();
    }
}
