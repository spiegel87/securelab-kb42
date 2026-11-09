using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object NewIncident() => new
    {
        title = $"csrf regression {Guid.NewGuid():N}",
        description = "synthetic",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
    };

    private static async Task<Guid> CreateIncidentAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", NewIncident());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task<(string Title, string Status)> ReadAsync(HttpClient client, Guid id)
    {
        using var document = JsonDocument.Parse(await client.GetStringAsync($"/api/incidents/{id}"));
        return (document.RootElement.GetProperty("title").GetString()!,
                document.RootElement.GetProperty("status").GetString()!);
    }

    private static async Task<int> CountAsync(HttpClient client) =>
        (await client.GetFromJsonAsync<List<JsonElement>>("/api/incidents"))!.Count;

    // REG-CSRF-01: типовий маршрут (PUT). Перевіряється стан ресурсу, а не лише status code.
    [Fact]
    public async Task REG_CSRF_01_Put_WithoutOrInvalidToken_IsRejected_StateUnchanged_ValidPairSucceeds()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var id = await CreateIncidentAsync(alice);
        var before = await ReadAsync(alice, id);
        var changed = new { title = before.Title + " changed", description = "changed by regression" };

        // Негативна частина 1: auth-cookie є, request header немає.
        alice.DefaultRequestHeaders.Remove(AntiforgeryContract.HeaderName);
        using var missing = await alice.PutAsJsonAsync($"/api/incidents/{id}", changed);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(before, await ReadAsync(alice, id));

        // Негативна частина 2: header є, але значення недійсне.
        alice.DefaultRequestHeaders.Add(AntiforgeryContract.HeaderName, "invalid-token");
        using var invalid = await alice.PutAsJsonAsync($"/api/incidents/{id}", changed);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal(before, await ReadAsync(alice, id));

        // Позитивна частина: валідна пара токенів, очікувана зміна стану.
        await alice.UseAntiforgeryTokenAsync();
        using var accepted = await alice.PutAsJsonAsync($"/api/incidents/{id}", changed);
        Assert.True(accepted.IsSuccessStatusCode);
        Assert.Equal(changed.title, (await ReadAsync(alice, id)).Title);
    }

    // REG-CSRF-02: усі cookie-authenticated мутації периметра без токена дають той самий 4xx
    // і нічого не змінюють.
    [Fact]
    public async Task REG_CSRF_02_Perimeter_WithoutToken_IsRejected_AndChangesNothing()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var id = await CreateIncidentAsync(alice);
        var before = await ReadAsync(alice, id);
        var countBefore = await CountAsync(alice);
        alice.DefaultRequestHeaders.Remove(AntiforgeryContract.HeaderName);
        morgan.DefaultRequestHeaders.Remove(AntiforgeryContract.HeaderName);

        using var create = await alice.PostAsJsonAsync("/api/incidents", NewIncident());
        using var update = await alice.PutAsJsonAsync($"/api/incidents/{id}", new { title = "x", description = "y" });
        using var triage = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
        using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
        using var logout = await alice.PostAsync("/api/auth/logout", null);

        foreach (var response in new[] { create, update, triage, delete, logout })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        // Стан не змінився: той самий запис, той самий статус, нових записів немає, сеанс чинний.
        Assert.Equal(before, await ReadAsync(alice, id));
        Assert.Equal(countBefore, await CountAsync(alice));
        using var me = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    // Рішення scope: logout без чинного сеансу лишається ідемпотентним.
    [Fact]
    public async Task Logout_WithoutSession_StaysIdempotent_204()
    {
        using var anonymous = factory.CreateClient();
        using var response = await anonymous.PostAsync("/api/auth/logout", null);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }
}