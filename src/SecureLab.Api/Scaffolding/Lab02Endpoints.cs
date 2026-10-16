using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Application.Incidents;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.

public static class Lab02Endpoints
{
    private const char LikeEscapeChar = '\\';
    private static readonly string[] AllowedSortBy = ["createdAtUtc", "severity", "status"];

    private static string EscapeLikePattern(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch == LikeEscapeChar || ch == '%' || ch == '_')
            {
                builder.Append(LikeEscapeChar);
            }
            builder.Append(ch);
        }
        return builder.ToString();
    }

    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var effectiveSortBy = string.IsNullOrEmpty(sortBy) ? "createdAtUtc" : sortBy;
            if (!AllowedSortBy.Contains(effectiveSortBy))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });
            }

            var escapeString = LikeEscapeChar.ToString();
            var pattern = $"%{EscapeLikePattern(q ?? string.Empty)}%";

            var query = db.Incidents.AsNoTracking().Where(incident =>
                EF.Functions.ILike(incident.Title, pattern, escapeString) ||
                EF.Functions.ILike(incident.Description, pattern, escapeString));

            query = effectiveSortBy switch
            {
                "severity" => query.OrderBy(i =>
                    i.Severity == IncidentSeverity.Critical ? 0
                    : i.Severity == IncidentSeverity.High ? 1
                    : i.Severity == IncidentSeverity.Medium ? 2
                    : 3),
                "status" => query.OrderBy(i =>
                    i.Status == IncidentStatus.New ? 0
                    : i.Status == IncidentStatus.Triaged ? 1
                    : i.Status == IncidentStatus.InProgress ? 2
                    : i.Status == IncidentStatus.Resolved ? 3
                    : 4),
                _ => query.OrderByDescending(i => i.CreatedAtUtc)
            };

            var rows = await query.Take(50).ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });

        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext httpContext, IncidentCommands commands, CancellationToken ct) =>
        {
            // Власник нового інциденту: лише з верифікованого principal, не з body і не з header.
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userId, out var ownerUserId))
            {
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
            }

            var result = await commands.CreateAsync(request, ownerUserId, ct);
            return result switch
            {
                CreateIncidentResult.ValidationFailed failed => Results.ValidationProblem(failed.Errors),
                CreateIncidentResult.Conflict conflict => Results.Conflict(new { detail = conflict.Detail }),
                CreateIncidentResult.Created created => Results.Created($"/api/incidents/{created.Response.Id}", created.Response),
                _ => throw new InvalidOperationException("Unknown CreateIncidentResult case")
            };
        }).RequireAuthorization();
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);
