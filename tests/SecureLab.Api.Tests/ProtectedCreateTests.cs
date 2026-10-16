using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class ProtectedCreateTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static string NewTitle() => $"Auth-{Guid.NewGuid():N}";

    private static object ValidBody(string title) => new
    {
        title,
        description = "Опис для перевірки власника нового запису.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow
    };

    // Фактичний власник читається з БД, а не з відповіді API (вона owner не віддає).
    private async Task<Guid> OwnerOfAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == incidentId);
        return incident.OwnerUserId;
    }

    private static async Task<Guid> ReadIdAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Anonymous_Create_Returns401_AndStoresNothing()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var title = NewTitle();

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", ValidBody(title));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        Assert.False(await db.Incidents.AnyAsync(item => item.Title == title));
    }

    // A-04: у DTO немає власника -> owner береться з principal (Bob, а не константа Alice).
    [Fact]
    public async Task A04_Create_WithoutOwnerField_UsesOwnerFromPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        using var response = await bob.PostAsJsonAsync("/api/incidents", ValidBody(NewTitle()));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var id = await ReadIdAsync(response);

        Assert.Equal(DbSeeder.BobId, await OwnerOfAsync(id));
    }

    // A-05: підроблений ownerUserId (Alice) у JSON нічого не змінює; фактичний owner = Bob.
    [Fact]
    public async Task A05_Create_WithForgedOwnerUserId_IgnoresItAndUsesPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var forged = new
        {
            title = NewTitle(),
            description = "Опис для перевірки підробленого власника.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = DbSeeder.AliceId
        };

        using var response = await bob.PostAsJsonAsync("/api/incidents", forged);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var id = await ReadIdAsync(response);

        var owner = await OwnerOfAsync(id);
        Assert.Equal(DbSeeder.BobId, owner);
        Assert.NotEqual(DbSeeder.AliceId, owner);
    }
}