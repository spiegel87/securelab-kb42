using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=навчальн");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Search_WithLegitimateApostrophe_ReturnsExpectedRecordWithoutError()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        var json = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(json);
        var ids = document.RootElement.EnumerateArray()
            .Select(element => element.GetProperty("id").GetGuid())
            .ToList();
        Assert.Contains(Lab02Seed.OBrienIncidentId, ids);
    }

    [Fact]
    public async Task Search_WithSqliControlPayload_DoesNotExpandResultSet()
    {
        var payload = Uri.EscapeDataString("zz-no-match' OR TRUE -- ");
        using var response = await _client.GetAsync($"/api/incidents/search?q={payload}");
        var incidents = await response.Content.ReadFromJsonAsync<List<JsonElement>>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(incidents);
        Assert.Empty(incidents);
    }

    [Fact]
    public async Task Search_WithPercentCharacter_IsTreatedAsLiteralNotWildcard()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=" + Uri.EscapeDataString("%"));
        var incidents = await response.Content.ReadFromJsonAsync<List<JsonElement>>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(incidents);
        Assert.Empty(incidents);
    }

    [Fact]
    public async Task Search_WithUnknownSortBy_ReturnsValidationProblem()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=USB&sortBy=unknown");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Search_WithoutSortBy_DefaultsToCreatedAtDescending()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=");
        var incidents = await response.Content.ReadFromJsonAsync<List<JsonElement>>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(incidents);
        var createdDates = incidents!.Select(i => i.GetProperty("createdAtUtc").GetDateTimeOffset()).ToList();
        Assert.Equal(createdDates.OrderByDescending(d => d), createdDates);
    }

    [Fact]
    public async Task CreateIncident_ValidRequest_ThenDuplicateActiveTitle_ReturnsConflict()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var request = new
        {
            title,
            description = "Достатньо довгий опис для регресійного тесту створення.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        using var firstResponse = await _client.PostAsJsonAsync("/api/incidents", request);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        using var secondResponse = await _client.PostAsJsonAsync("/api/incidents", request);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
    }

    [Fact]
    public async Task CreateIncident_NumericSeverityString_ReturnsValidationProblem()
    {
        var request = new
        {
            title = $"Regression-{Guid.NewGuid():N}",
            description = "Опис для перевірки некоректного числового severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", request);
        var json = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("severity", json, StringComparison.OrdinalIgnoreCase);
    }
}