using System.Security.Claims;

namespace SecureLab.Api.Application.Incidents;

// Виконавець запиту, сформований лише з перевіреного principal (cookie), не з body чи header.
public sealed record IncidentActor(Guid UserId, string Role)
{
    public static IncidentActor? From(ClaimsPrincipal principal)
    {
        var id = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var role = principal.FindFirst(ClaimTypes.Role)?.Value;
        return Guid.TryParse(id, out var userId) && !string.IsNullOrEmpty(role)
            ? new IncidentActor(userId, role)
            : null;
    }
}