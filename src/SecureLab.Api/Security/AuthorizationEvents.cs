namespace SecureLab.Api.Security;

// Аудит відмов авторизації. Без тіла запиту, cookie, паролів, hash і email.
public static class AuthorizationEvents
{
    public const string Category = "SecureLab.Api.Security.Authorization";

    public static void Denied(HttpContext httpContext, string action, Guid actorId, string role, Guid resourceId)
    {
        var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(Category);
        // Той самий trace, що Problem Details віддає у відповіді (traceId).
        var traceId = System.Diagnostics.Activity.Current?.Id ?? httpContext.TraceIdentifier;
        logger.LogWarning(
            "AuthzEvent authorization.denied: action {Action}, actor {ActorId}, role {Role}, resource {ResourceId}, result {Result}, utc {Utc}, trace {TraceId}",
            action, actorId, role, resourceId, "denied", DateTimeOffset.UtcNow.ToString("O"), traceId);
    }
}