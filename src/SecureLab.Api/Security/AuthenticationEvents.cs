namespace SecureLab.Api.Security;

// Мінімальні події автентифікації. До події НЕ входять: пароль, cookie, hash пароля, token,
// заголовок Authorization, тіло запиту, email і введене ім’я користувача при невдалому вході.
public static class AuthenticationEvents
{
    public const string Category = "SecureLab.Api.Security.Authentication";

    public static void Write(HttpContext httpContext, string eventType, string result, string userRef)
    {
        var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(Category);
        var source = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        // Той самий trace, що Problem Details віддає у відповіді (traceId), як у AuthorizationEvents.
        var traceId = System.Diagnostics.Activity.Current?.Id ?? httpContext.TraceIdentifier;
        logger.LogInformation(
            "AuthEvent {EventType}: result {Result}, user {UserRef}, source {Source}, utc {Utc}, trace {TraceId}",
            eventType, result, userRef, source, DateTimeOffset.UtcNow.ToString("O"), traceId);
    }
}