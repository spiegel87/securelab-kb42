using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class IncidentChangeTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private sealed record IncidentState(string Title, Guid Owner, IncidentStatus Status, IncidentSeverity Severity);

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static async Task<Guid> CreateIncidentAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"Chg-{Guid.NewGuid():N}",
            description = "Опис достатньої довжини для перевірки змін інциденту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    // Фактичний стан читається з БД, а не з відповіді API.
    private async Task<IncidentState?> StateAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id);
        return incident is null
            ? null
            : new IncidentState(incident.Title, incident.OwnerUserId, incident.Status, incident.Severity);
    }

    private static object NewContent() => new
    {
        title = $"Upd-{Guid.NewGuid():N}",
        description = "Оновлений опис достатньої довжини для перевірки."
    };

    [Fact]
    public async Task Owner_UpdatesAndDeletesOwnNewIncident()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var id = await CreateIncidentAsync(alice);
        var content = NewContent();

        using (var update = await alice.PutAsJsonAsync($"/api/incidents/{id}", content))
        {
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        }
        var changed = await StateAsync(id);
        Assert.NotNull(changed);
        Assert.StartsWith("Upd-", changed!.Title, StringComparison.Ordinal);

        using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        Assert.Null(await StateAsync(id));
    }

    // A-04: підміна id чужого ресурсу в update/delete -> 404, нічого не змінено.
    [Fact]
    public async Task A04_Reporter_UpdateAndDeleteForeignIncident_Return404_AndChangeNothing()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var bobIncident = await CreateIncidentAsync(bob);
        var before = await StateAsync(bobIncident);

        using var update = await alice.PutAsJsonAsync($"/api/incidents/{bobIncident}", NewContent());
        using var delete = await alice.DeleteAsync($"/api/incidents/{bobIncident}");

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.Equal(before, await StateAsync(bobIncident));
    }

    // A-06: звичайний Reporter не може виконати привілейований transition.
    [Fact]
    public async Task A06_Reporter_Triage_OwnIncident_Returns403_ForeignReturns404_StatusUnchanged()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var id = await CreateIncidentAsync(alice);

        using var ownerTriage = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);
        using var foreignTriage = await bob.PostAsync($"/api/incidents/{id}/triage", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, ownerTriage.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, foreignTriage.StatusCode);
        Assert.Equal(IncidentStatus.New, (await StateAsync(id))!.Status);
    }

    // A-07: дозволена привілейована дія Analyst за контекстом (лише New -> Triaged).
    [Fact]
    public async Task A07_Analyst_Triage_NewIncident_Returns200_RecordsHistory_ThenNonNewIsForbidden()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var id = await CreateIncidentAsync(alice);

        using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(IncidentStatus.Triaged, (await StateAsync(id))!.Status);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var history = await db.IncidentStatusHistory.AsNoTracking()
                .SingleAsync(entry => entry.IncidentId == id);
            Assert.Equal(DbSeeder.MorganId, history.ChangedByUserId);
            Assert.Equal(IncidentStatus.New, history.OldStatus);
            Assert.Equal(IncidentStatus.Triaged, history.NewStatus);
        }

        // Не зі статусу New: transition заборонено; Analyst також не редагує зміст; власник не видаляє не-New.
        using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
        using var analystUpdate = await morgan.PutAsJsonAsync($"/api/incidents/{id}", NewContent());
        using var ownerDelete = await alice.DeleteAsync($"/api/incidents/{id}");

        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, analystUpdate.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, ownerDelete.StatusCode);
        Assert.NotNull(await StateAsync(id));
    }

    // A-08a: зайві поля (owner, status, severity) у regular update ігноруються контрактом.
    [Fact]
    public async Task A08a_Update_IgnoresForgedProtectedFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var id = await CreateIncidentAsync(alice);

        using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
        {
            title = $"Upd-{Guid.NewGuid():N}",
            description = "Оновлений опис достатньої довжини для перевірки.",
            ownerUserId = DbSeeder.BobId,
            status = "Closed",
            severity = "Critical",
            role = "Administrator"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var state = await StateAsync(id);
        Assert.Equal(DbSeeder.AliceId, state!.Owner);
        Assert.Equal(IncidentStatus.New, state.Status);
        Assert.Equal(IncidentSeverity.Low, state.Severity);
    }

    // A-09: відмова привілейованого запиту лишає аудиторську подію без секретів.
    [Fact]
    public async Task A09_DeniedPrivilegedRequest_WritesAuthorizationDeniedEvent()
    {
        var provider = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging => logging.AddProvider(provider)));
        using var alice = host.CreateClient();
        using var login = await alice.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        var id = await CreateIncidentAsync(alice);

        using var denied = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        using var deniedBody = JsonDocument.Parse(await denied.Content.ReadAsStringAsync());
        var responseTrace = deniedBody.RootElement.GetProperty("traceId").GetString();
        var events = provider.Messages
            .Where(message => message.StartsWith(AuthorizationEvents.Category + "|", StringComparison.Ordinal))
            .ToArray();
        Assert.Contains(events, e =>
            e.Contains("authorization.denied", StringComparison.Ordinal)
            && e.Contains("action incident.triage", StringComparison.Ordinal)
            && e.Contains($"actor {DbSeeder.AliceId}", StringComparison.Ordinal)
            && e.Contains($"resource {id}", StringComparison.Ordinal));
        Assert.DoesNotContain(provider.Messages, m => m.Contains(StudyPassword, StringComparison.Ordinal));
        Assert.Contains(events, e => e.Contains($"trace {responseTrace}", StringComparison.Ordinal));
        Assert.Contains(events, e => e.Contains("result denied", StringComparison.Ordinal));        
    }
}