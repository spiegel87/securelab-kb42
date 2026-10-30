using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentCommentAccessTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Seed: comment-1 і comment-2 публічні (на інцидентах Alice і Bob), comment-3 internal на інциденті Alice.
    private static readonly Guid PublicOnAliceIncident = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid PublicOnBobIncident = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalOnAliceIncident = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private const string PublicAliceText = "Заголовки листа передано аналітику.";
    private const string PublicBobText = "Розпочато перевірку журналу автентифікації.";
    private const string InternalText = "Внутрішня нотатка аналітика для тесту доступу (синтетичні дані).";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static async Task<JsonDocument> ReadAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    private static async Task<string?> TextAsync(HttpResponseMessage response)
    {
        using var document = await ReadAsync(response);
        return document.RootElement.GetProperty("text").GetString();
    }

    private static async Task<bool> HasTextPropertyAsync(HttpResponseMessage response)
    {
        using var document = await ReadAsync(response);
        return document.RootElement.TryGetProperty("text", out _);
    }

    // A-12: child endpoint підпорядковується parent; internal прихований від Reporter, details без internal.
    [Fact]
    public async Task A12_Reporter_ChildEndpoint_FollowsParentAccess_AndHidesInternal()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var foreign = await alice.GetAsync($"/api/incident-comments/{PublicOnBobIncident}");
        using var internalOwn = await alice.GetAsync($"/api/incident-comments/{InternalOnAliceIncident}");
        using var publicOwn = await alice.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");
        using var details = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, internalOwn.StatusCode);
        Assert.False(await HasTextPropertyAsync(foreign));
        Assert.False(await HasTextPropertyAsync(internalOwn));

        // Позитивна регресія: свій публічний коментар доступний.
        Assert.Equal(HttpStatusCode.OK, publicOwn.StatusCode);
        Assert.Equal(PublicAliceText, await TextAsync(publicOwn));

        // Details Reporter не містить internal-тексту.
        using var document = await ReadAsync(details);
        var texts = document.RootElement.GetProperty("comments").EnumerateArray()
            .Select(comment => comment.GetProperty("text").GetString()).ToArray();
        Assert.DoesNotContain(InternalText, texts);
        Assert.Contains(PublicAliceText, texts);
    }

    [Fact]
    public async Task A12_Analyst_ReadsInternalAndAnyPublicComment()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        using var internalComment = await morgan.GetAsync($"/api/incident-comments/{InternalOnAliceIncident}");
        using var bobComment = await morgan.GetAsync($"/api/incident-comments/{PublicOnBobIncident}");

        Assert.Equal(HttpStatusCode.OK, internalComment.StatusCode);
        Assert.Equal(InternalText, await TextAsync(internalComment));
        Assert.Equal(HttpStatusCode.OK, bobComment.StatusCode);
        Assert.Equal(PublicBobText, await TextAsync(bobComment));
    }

    [Fact]
    public async Task ChildEndpoint_Anonymous_Returns401_AndAdministrator_Returns404()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var unauthenticated = await anonymous.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        using var admin = await factory.LoginAsync("admin", StudyPassword);
        using var adminResponse = await admin.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");
        Assert.Equal(HttpStatusCode.NotFound, adminResponse.StatusCode);
    }
}