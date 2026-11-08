using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

// Контракт між сервером і клієнтом: назва header і маршрут видачі request token.
public static class AntiforgeryContract
{
    public const string HeaderName = "X-SecureLab-CSRF";
    public const string TokenRoute = "/api/auth/csrf-token";
}

// Єдине місце, де викликається ValidateRequestAsync і де відмова
// перетворюється на один точний 4xx у форматі Problem Details.
public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;

        // Перевіряємо запити, де автентифікаційна cookie справді авторизує дію.
        // Захищені маршрути відхиляє authorization (401) ще раніше; анонімний logout
        // лишається ідемпотентним, бо немає чинного сеансу, яким можна зловживати.
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return await next(context);
        }

        try
        {
            await antiforgery.ValidateRequestAsync(http);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                title: "Antiforgery token is missing or invalid.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}