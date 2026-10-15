using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class CookieFlagsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string CookiePrefix = ".AspNetCore.Identity.Application=";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Повертає лише атрибути; пара «назва=значення» не читається і не друкується.
    private async Task<string[]> LoginCookieAttributesAsync(string baseAddress)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            AllowAutoRedirect = false
        });
        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(CookiePrefix, StringComparison.Ordinal))
            .ToArray();
        Assert.True(matching.Length == 1);
        return matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant()).ToArray();
    }

    [Fact]
    public async Task Login_OverHttps_Cookie_IsHttpOnly_Secure_SameSiteLax_AndSessionOnly()
    {
        var attributes = await LoginCookieAttributesAsync("https://localhost");

        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("path=/", attributes);
        // Сеансова cookie: без expires і max-age.
        Assert.DoesNotContain(attributes, a => a.StartsWith("expires", StringComparison.Ordinal));
        Assert.DoesNotContain(attributes, a => a.StartsWith("max-age", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Login_OverPlainHttp_Development_Cookie_HasNoSecureAttribute()
    {
        var attributes = await LoginCookieAttributesAsync("http://localhost");

        Assert.Contains("httponly", attributes);
        Assert.Contains("samesite=lax", attributes);
        // SameAsRequest: Secure лише на HTTPS-запиті. Це межа локального HTTP, а не доказ Secure.
        Assert.DoesNotContain("secure", attributes);
    }
}