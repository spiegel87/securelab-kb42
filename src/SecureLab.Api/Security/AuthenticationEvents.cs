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
        logger.LogInformation(
            "AuthEvent {EventType}: result {Result}, user {UserRef}, source {Source}, trace {TraceId}",
            eventType, result, userRef, source, httpContext.TraceIdentifier);
    }
}