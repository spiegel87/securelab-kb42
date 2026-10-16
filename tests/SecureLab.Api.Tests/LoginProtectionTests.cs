using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class LoginProtectionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Окремий host зі своїми лічильниками; невелике вікно робить перевірку швидкою.
    private static Action<IWebHostBuilder> Configure(
        int permitLimit, int windowSeconds, ILoggerProvider? logProvider = null) => builder =>
    {
        builder.UseSetting("LoginRateLimit:PermitLimit", permitLimit.ToString());
        builder.UseSetting("LoginRateLimit:WindowSeconds", windowSeconds.ToString());
        if (logProvider is not null)
        {
            builder.ConfigureLogging(logging => logging.AddProvider(logProvider));
        }
    };

    [Fact]
    public async Task Login_AfterLimit_Returns429_ThenRecovers_AndNewHostIsIndependent()
    {
        var provider = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(Configure(permitLimit: 3, windowSeconds: 5, provider));
        using var first = host.CreateClient();
        using var second = host.CreateClient(); // інший клієнт того самого host: та сама квота

        for (var i = 0; i < 3; i++)
        {
            using var attempt = await first.PostAsJsonAsync(
                "/api/auth/login", new { userName = "alice", password = StudyPassword + "-wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        // Ліміт вичерпано: навіть правильні дані та невідоме ім’я дають однаковий 429.
        using var limitedKnown = await second.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        using var limitedUnknown = await second.PostAsJsonAsync(
            "/api/auth/login", new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = StudyPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedKnown.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);
        Assert.Equal(
            limitedKnown.Content.Headers.ContentType?.MediaType,
            limitedUnknown.Content.Headers.ContentType?.MediaType);

        // Новий host має власні лічильники.
        using var freshHost = factory.WithWebHostBuilder(Configure(permitLimit: 3, windowSeconds: 5));
        using var third = freshHost.CreateClient();
        using var independent = await third.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, independent.StatusCode);

        // Після вікна (з запасом) вхід знову можливий.
        await Task.Delay(TimeSpan.FromSeconds(5.5));
        using var recovered = await second.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);

        Assert.Contains(provider.Messages, m => m.Contains("result rate_limited", StringComparison.Ordinal));
        Assert.DoesNotContain(provider.Messages, m => m.Contains(StudyPassword, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AuthenticationEvents_AreLogged_WithoutCredentials()
    {
        var provider = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(Configure(permitLimit: 100, windowSeconds: 60, provider));
        using var client = host.CreateClient();
        var unknownName = "nobody" + Guid.NewGuid().ToString("N")[..8];

        using var failure = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = unknownName, password = StudyPassword + "-wrong" });
        using var success = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, failure.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, success.StatusCode);

        var prefix = AuthenticationEvents.Category + "|AuthEvent";
        var events = provider.Messages.Where(m => m.StartsWith(prefix, StringComparison.Ordinal)).ToArray();

        Assert.Contains(events, e => e.Contains("login: result failure", StringComparison.Ordinal));
        Assert.Contains(events, e =>
            e.Contains("login: result success", StringComparison.Ordinal)
            && e.Contains(DbSeeder.AliceId.ToString(), StringComparison.Ordinal));
        Assert.All(events, e => Assert.Contains("trace ", e, StringComparison.Ordinal));
        // Ані пароль, ані введене невідоме ім’я не потрапляють до подій; пароль — і до жодного запису журналу.
        Assert.DoesNotContain(events, e => e.Contains(unknownName, StringComparison.Ordinal));
        Assert.DoesNotContain(provider.Messages, m => m.Contains(StudyPassword, StringComparison.Ordinal));
    }
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Messages);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(string category, ConcurrentQueue<string> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter) =>
            sink.Enqueue($"{category}|{formatter(state, exception)}");
    }
}