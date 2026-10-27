using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentAccessTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Для A-10: тіло без полів, що відрізняються між запитами (traceId, requestId).
    private static async Task<string> NormalizedBodyAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return string.Join("|", document.RootElement.EnumerateObject()
            .Where(property => property.Name is not ("traceId" or "requestId"))
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .Select(property => $"{property.Name}={property.Value.GetRawText()}"));
    }

    private async Task<HashSet<Guid>> IncidentIdsOwnedByAsync(Guid ownerUserId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var ids = await db.Incidents.AsNoTracking()
            .Where(incident => incident.OwnerUserId == ownerUserId)
            .Select(incident => incident.Id)
            .ToListAsync();
        return ids.ToHashSet();
    }

    // A-01: анонімний доступ до list і details -> 401, а не redirect.
    [Fact]
    public async Task A01_Anonymous_ListAndDetails_Return401_NotRedirect()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        foreach (var path in new[] { "/api/incidents", $"/api/incidents/{DbSeeder.BobIncidentId}" })
        {
            using var response = await anonymous.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }
    }

    // A-02: власник читає власний інцидент.
    [Fact]
    public async Task A02_Owner_ReadsOwnIncident_Returns200()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceIncidentId, document.RootElement.GetProperty("id").GetGuid());
    }

    // A-03: Reporter читає чужий інцидент (id Bob) -> 404 і жодних чужих даних.
    [Fact]
    public async Task A03_Reporter_ReadsForeignIncident_Returns404_AndNoForeignData()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain("Невідома спроба входу", body, StringComparison.Ordinal);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }

    // A-03R: Analyst читає будь-який інцидент для аналізу (entry-контракт ЛР 5).
    [Fact]
    public async Task A03R_Analyst_ReadsAnyIncident_Returns200()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        foreach (var id in new[] { DbSeeder.AliceIncidentId, DbSeeder.BobIncidentId })
        {
            using var response = await morgan.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    // Administrator: право на incidents не опубліковано -> як для чужого ресурсу.
    [Fact]
    public async Task Administrator_ReadsIncident_Returns404_NoPublishedRight()
    {
        using var admin = await factory.LoginAsync("admin", StudyPassword);
        using var response = await admin.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // A-05: список Reporter містить лише власні інциденти.
    [Fact]
    public async Task A05_Reporter_List_ContainsOnlyOwnIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var list = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var aliceOwned = await IncidentIdsOwnedByAsync(DbSeeder.AliceId);   // знімок ПІСЛЯ списку

        Assert.NotNull(list);
        Assert.Contains(list, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(list, item => item.Id == DbSeeder.BobIncidentId);
        Assert.All(list, item => Assert.Contains(item.Id, aliceOwned));
    }

    [Fact]
    public async Task Analyst_List_ContainsAllSeededIncidents()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var list = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(list);
        Assert.Contains(list, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(list, item => item.Id == DbSeeder.BobIncidentId);
    }

    // A-10: чужий і неіснуючий id неможливо відрізнити (status, Content-Type, тіло без traceId).
    [Fact]
    public async Task A10_ForeignAndUnknownIncident_AreIndistinguishable()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(foreign.StatusCode, unknown.StatusCode);
        Assert.Equal(
            foreign.Content.Headers.ContentType?.MediaType,
            unknown.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await NormalizedBodyAsync(foreign), await NormalizedBodyAsync(unknown));
    }
}