using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace SecureLab.Api.Security;

public static class LoginRateLimiting
{
    public const string PolicyName = "login";
    private const int DefaultPermitLimit = 10;
    private const int DefaultWindowSeconds = 60;

    public static void AddLoginRateLimiting(this WebApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = (context, _) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        Math.Ceiling(retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
                }

                // Політику має лише login, тому відхилення належить саме йому.
                AuthenticationEvents.Write(context.HttpContext, "login", "rate_limited", "n/a");
                return ValueTask.CompletedTask;
            };

            options.AddPolicy(PolicyName, httpContext =>
            {
                // Значення читаються під час запиту: тест може підставити свої.
                var settings = httpContext.RequestServices.GetRequiredService<IConfiguration>();
                var permitLimit = settings.GetValue<int?>("LoginRateLimit:PermitLimit") ?? DefaultPermitLimit;
                var windowSeconds = settings.GetValue<int?>("LoginRateLimit:WindowSeconds") ?? DefaultWindowSeconds;

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permitLimit,
                        Window = TimeSpan.FromSeconds(windowSeconds),
                        QueueLimit = 0
                    });
            });
        });
    }
}