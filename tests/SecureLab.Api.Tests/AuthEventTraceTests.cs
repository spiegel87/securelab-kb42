using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

public sealed class AuthEventTraceTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Перехоплювач повідомлень журналу: лише в пам'яті тесту.
    private sealed class CaptureProvider : ILoggerProvider, ILogger
    {
        public List<string> Messages { get; } = [];
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Messages) Messages.Add(formatter(state, exception));
        }

        public void Dispose() { }
    }

    [Fact]
    public async Task FailedLogin_Event_HasUtcTime_AndSameTraceIdAsProblemDetails()
    {
        var provider = new CaptureProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services => services.AddSingleton<ILoggerProvider>(provider)));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "Wrong-Synthetic-Password-1!" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var traceId = body.RootElement.GetProperty("traceId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(traceId));

        string authEvent;
        lock (provider.Messages)
        {
            authEvent = Assert.Single(provider.Messages,
                message => message.StartsWith("AuthEvent login: result failure", StringComparison.Ordinal));
        }

        // Час події і той самий trace, який віддала відповідь: за цим оператор знайде запис.
        Assert.Matches(@"utc \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", authEvent);
        Assert.Contains($"trace {traceId}", authEvent);
        Assert.DoesNotContain("Wrong-Synthetic-Password-1!", authEvent);
    }
}