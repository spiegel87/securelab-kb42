using System.Security.Claims;
using System.Threading.RateLimiting;

namespace SecureLab.Api.Security;

public static class SearchRateLimiting
{
    public const string PolicyName = "search-per-principal";
    public const int PermitLimit = 30;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    public static void AddSearchRateLimiting(this WebApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(PolicyName, httpContext =>
            {
                // Partition key: перевірена ідентичність з cookie-автентифікації;
                // для анонімних запитів запасний ключ за IP (він може бути спільним).
                var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var key = userId is not null
                    ? $"user:{userId}"
                    : $"ip:{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";

                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = PermitLimit,
                    Window = Window,
                    QueueLimit = 0
                });
            });
        });
    }
}