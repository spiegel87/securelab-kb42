namespace SecureLab.Api.Tests;

public sealed class SecurityHeadersTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly string[] BaselineHeaders =
        ["X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"];

    [Theory]
    [InlineData("/")]
    [InlineData("/health")]
    public async Task Baseline_Headers_ArePresent_ExactlyOnce(string path)
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync(path);

        foreach (var name in BaselineHeaders)
        {
            Assert.True(response.Headers.TryGetValues(name, out var values), $"{name} відсутній для {path}");
            Assert.Single(values);
        }
    }
}