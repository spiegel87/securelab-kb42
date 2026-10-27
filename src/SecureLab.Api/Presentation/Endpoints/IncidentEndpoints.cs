using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
	    .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken,
        HttpContext httpContext)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(actor, parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }

        // Чужий і неіснуючий ресурс неможливо відрізнити: однакова відповідь, id у тілі немає.
        var incident = await queries.GetDetailsAsync(actor, id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Ресурс не знайдено",
                detail: "Запитаний ресурс не знайдено.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
         if (status is not null)
         {
             if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                 || !Enum.IsDefined(candidate))
             {
                 return Results.ValidationProblem(new Dictionary<string, string[]>
                 {
                     ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                 });
             }

             parsedStatus = candidate;
         }

    return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, cancellationToken));
    }
}
