using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

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

    private static async Task<string[]> FieldNamesAsync(HttpResponseMessage response)
    {
        using var document = await ReadAsync(response);
        return document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
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

    // Захист: child-доступ визначає parent scope, а не збіг автора коментаря. Seed не змінюємо.
    [Fact]
    public async Task C2_ChildAccess_FollowsParentScope_NotAuthorMatch_WithC1Control()
    {
        // Факти беремо з БД: автор і власник parent для C2 та C1 (перевірка, що seed не підроблено).
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var facts = await db.IncidentComments.AsNoTracking()
            .Where(comment => comment.Id == PublicOnBobIncident || comment.Id == PublicOnAliceIncident)
            .Select(comment => new
            {
                comment.Id, comment.AuthorUserId, comment.IsInternal,
                ParentOwner = comment.Incident.OwnerUserId
            })
            .ToDictionaryAsync(row => row.Id);
        var c2 = facts[PublicOnBobIncident];
        var c1 = facts[PublicOnAliceIncident];

        Assert.Equal(DbSeeder.MorganId, c2.AuthorUserId);   // автор C2: Morgan
        Assert.Equal(DbSeeder.BobId, c2.ParentOwner);       // parent C2 належить Bob
        Assert.Equal(DbSeeder.MorganId, c1.AuthorUserId);   // контроль: автор C1 теж Morgan
        Assert.Equal(DbSeeder.AliceId, c1.ParentOwner);     // але parent належить Alice
        Assert.False(c2.IsInternal);
        Assert.False(c1.IsInternal);

        using var bob = await factory.LoginAsync("bob", StudyPassword);
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        // C2 (parent I2 Bob): Bob allow як owner, Alice deny, Morgan allow через Analyst parent-read.
        using var c2Bob = await bob.GetAsync($"/api/incident-comments/{PublicOnBobIncident}");
        using var c2Alice = await alice.GetAsync($"/api/incident-comments/{PublicOnBobIncident}");
        using var c2Morgan = await morgan.GetAsync($"/api/incident-comments/{PublicOnBobIncident}");

        Assert.Equal(HttpStatusCode.OK, c2Bob.StatusCode);
        Assert.Equal(PublicBobText, await TextAsync(c2Bob));
        Assert.Equal(new[] { "authorDisplayName", "createdAtUtc", "id", "text" }, await FieldNamesAsync(c2Bob));
        Assert.Equal(HttpStatusCode.NotFound, c2Alice.StatusCode);
        Assert.False(await HasTextPropertyAsync(c2Alice));
        Assert.Equal(HttpStatusCode.OK, c2Morgan.StatusCode);
        Assert.Equal(PublicBobText, await TextAsync(c2Morgan));

        // Контрприклад: author-only для Bob дав би "false", тоді як коректний parent scope дає 200.
        var authorOnlyBob = c2.AuthorUserId == DbSeeder.BobId;
        Assert.NotEqual(authorOnlyBob, c2Bob.StatusCode == HttpStatusCode.OK);

        // C1 (parent I1 Alice), автор лишається Morgan: Alice allow, Bob deny, Morgan allow.
        using var c1Alice = await alice.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");
        using var c1Bob = await bob.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");
        using var c1Morgan = await morgan.GetAsync($"/api/incident-comments/{PublicOnAliceIncident}");

        Assert.Equal(HttpStatusCode.OK, c1Alice.StatusCode);
        Assert.Equal(PublicAliceText, await TextAsync(c1Alice));
        Assert.Equal(HttpStatusCode.NotFound, c1Bob.StatusCode);
        Assert.Equal(HttpStatusCode.OK, c1Morgan.StatusCode);
        // Результат Morgan не змінився, а Alice і Bob помінялися місцями: рішення йде через parent.
        Assert.NotEqual(c2.AuthorUserId == DbSeeder.AliceId, c1Alice.StatusCode == HttpStatusCode.OK);
    } 
}