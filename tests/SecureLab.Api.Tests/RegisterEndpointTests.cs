using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class RegisterEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Нове ім'я й email для кожного запуску: повторний запуск на тій самій БД не дає duplicate.
    private static (string UserName, string Email) NewIdentity()
    {
        var suffix = Guid.NewGuid().ToString("N")[..10];
        return ($"reg{suffix}", $"reg{suffix}@example.test");
    }

    private static object Body(string userName, string email, string password) =>
        new { userName, email, displayName = "Тестовий користувач", password };

    [Fact]
    public async Task Register_ValidRequest_Returns201_AndOnlySafeFields()
    {
        using var client = factory.CreateClient();
        var (userName, email) = NewIdentity();

        using var response = await client.PostAsJsonAsync(
            "/api/auth/register", Body(userName, email, StudyPassword));
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.True(root.GetProperty("id").TryGetGuid(out _));
        Assert.Equal(userName, root.GetProperty("userName").GetString());
        // Рівно три дозволені поля: нічого зайвого (hash, stamp, роль, пароль).
        Assert.Equal(3, root.EnumerateObject().Count());
    }

    [Fact]
    public async Task Register_DuplicateUserNameOrEmail_ReturnsSameConflict()
    {
        using var client = factory.CreateClient();
        var (userName, email) = NewIdentity();
        using var first = await client.PostAsJsonAsync(
            "/api/auth/register", Body(userName, email, StudyPassword));
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var (otherName, otherEmail) = NewIdentity();
        using var sameUserName = await client.PostAsJsonAsync(
            "/api/auth/register", Body(userName, otherEmail, StudyPassword));
        using var sameEmail = await client.PostAsJsonAsync(
            "/api/auth/register", Body(otherName, email, StudyPassword));

        Assert.Equal(HttpStatusCode.Conflict, sameUserName.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
        // Зовні не видно, що саме зайнято: тіла однакові.
        Assert.Equal(
            await sameUserName.Content.ReadAsStringAsync(),
            await sameEmail.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Register_WeakPassword_Returns400_AndCreatesNoAccount()
    {
        using var client = factory.CreateClient();
        var (userName, email) = NewIdentity();
        const string weak = "Weak1!";

        using var response = await client.PostAsJsonAsync(
            "/api/auth/register", Body(userName, email, weak));
        var json = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("password", out _));
        Assert.DoesNotContain(weak, json, StringComparison.Ordinal);

        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await users.FindByNameAsync(userName));
    }

    [Fact]
    public async Task Register_ExtraRoleAndIdFields_AreIgnored()
    {
        using var client = factory.CreateClient();
        var (userName, email) = NewIdentity();
        var forgedId = Guid.NewGuid();

        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName, email, displayName = "Тестовий користувач", password = StudyPassword,
            role = "Administrator", id = forgedId
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var created = await users.FindByNameAsync(userName);
        Assert.NotNull(created);
        Assert.NotEqual(forgedId, created!.Id);
        var roles = await users.GetRolesAsync(created);
        Assert.Equal(new[] { DbSeeder.ReporterRole }, roles.ToArray());
    }
}