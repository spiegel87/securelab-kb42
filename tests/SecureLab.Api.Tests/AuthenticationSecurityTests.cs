using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationSecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01: анонімний запит до захищеного endpoint -> 401, а не redirect і не Bearer-challenge.
    [Fact]
    public async Task A01_Anonymous_Me_Returns401_NotRedirect_NotBearerChallenge()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await anonymous.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: login -> /api/me повертає поточного користувача з principal, лише безпечні поля.
    [Fact]
    public async Task A02_Login_ThenMe_ReturnsCurrentUser_WithSafeFieldsOnly()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.Equal(DbSeeder.ReporterRole, root.GetProperty("role").GetString());
        // Рівно три дозволені поля: ні hash, ні security stamp, ні email.
        Assert.Equal(3, root.EnumerateObject().Count());
    }

    // A-03: чинна cookie Alice + header із id Bob -> профіль лишається Alice.
    [Fact]
    public async Task A03_ForgedDemoHeader_WithValidCookie_DoesNotChangeCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, document.RootElement.GetProperty("id").GetGuid());
        Assert.NotEqual(DbSeeder.BobId, document.RootElement.GetProperty("id").GetGuid());
    }

    // A-06: login -> захищений запит 200 -> logout -> той самий клієнт -> 401.
    [Fact]
    public async Task A06_Logout_ThenSameClient_Me_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using (var before = await alice.GetAsync("/api/me"))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        using (var logout = await alice.PostAsync("/api/auth/logout", content: null))
        {
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        }

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07: невідомий користувач і неправильний пароль -> однаковий зовнішній результат.
    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_GiveSameExternalResult()
    {
        using var client = factory.CreateClient();
        var unknownName = "nobody" + Guid.NewGuid().ToString("N")[..8];

        using var unknown = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = unknownName, password = StudyPassword });
        using var wrong = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword + "-wrong" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.MediaType,
            wrong.Content.Headers.ContentType?.MediaType);
        Assert.Empty(unknown.Headers.WwwAuthenticate);
        Assert.Empty(wrong.Headers.WwwAuthenticate);
        // type, title, status, detail (разом із наявністю); traceId свідомо не порівнюємо.
        Assert.Equal(await ProblemShape.ReadAsync(unknown), await ProblemShape.ReadAsync(wrong));
    }
}