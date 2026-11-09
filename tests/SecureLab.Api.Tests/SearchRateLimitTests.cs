using System.Net;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class SearchRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static async Task<HttpStatusCode> SearchAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/incidents/search?q=test");
        return response.StatusCode;
    }

    [Fact]
    public async Task Search_ExhaustedQuota_Returns429_OtherPrincipalUnaffected()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        // У межах quota поведінка не ламається.
        for (var i = 0; i < SearchRateLimiting.PermitLimit; i++)
        {
            Assert.Equal(HttpStatusCode.OK, await SearchAsync(alice));
        }

        // Наступна спроба вичерпує quota.
        Assert.Equal(HttpStatusCode.TooManyRequests, await SearchAsync(alice));

        // Інший partition має власний лічильник.
        Assert.Equal(HttpStatusCode.OK, await SearchAsync(morgan));
    }
}