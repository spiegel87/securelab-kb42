using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SecureLab.Api.Tests;

public sealed class ProductionProfileTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Окремий host: початковий factory і Development-тести лишаються у своєму profile.
    // У Production appsettings.Development.json не читається, тому connection string задано явно.
    private WebApplicationFactory<Program> CreateProduction() =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;"
                + "Password=local-study-password;Include Error Detail=false");
        });

    [Fact]
    public void Host_IsReallyProduction()
    {
        using var production = CreateProduction();

        Assert.Equal("Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
    }

    [Fact]
    public async Task Production_AllowedGet_Returns200()
    {
        using var production = CreateProduction();
        using var alice = await production.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Production_UnknownStatus_Returns400_ValidationProblemDetails()
    {
        using var production = CreateProduction();
        using var alice = await production.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync("/api/incidents?status=Unknown");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.True(document.RootElement.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task Production_UnknownIncident_Returns404_ProblemDetails()
    {
        using var production = CreateProduction();
        using var alice = await production.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync("/api/incidents/99999999-9999-9999-9999-999999999999");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Production_Anonymous_Returns401_NotRedirect()
    {
        using var production = CreateProduction();
        using var anonymous = production.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });
        using var response = await anonymous.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}