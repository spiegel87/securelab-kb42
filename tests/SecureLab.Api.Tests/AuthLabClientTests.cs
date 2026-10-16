namespace SecureLab.Api.Tests;

public sealed class AuthLabClientTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Theory]
    [InlineData("innerHTML")]
    [InlineData("outerHTML")]
    [InlineData("insertAdjacentHTML")]
    [InlineData("localStorage")]
    [InlineData("sessionStorage")]
    [InlineData("document.cookie")]
    [InlineData("console.")]
    public async Task AuthLabScript_DoesNotUseForbiddenSinksOrBrowserStorage(string forbidden)
    {
        using var client = factory.CreateClient();
        var script = await client.GetStringAsync("/auth-lab.js");

        Assert.DoesNotContain(forbidden, script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthLabScript_RendersAsText_AndSendsSameOriginCredentialsOnly()
    {
        using var client = factory.CreateClient();
        var script = await client.GetStringAsync("/auth-lab.js");

        Assert.Contains("textContent", script, StringComparison.Ordinal);
        Assert.Contains("same-origin", script, StringComparison.Ordinal);
    }
}