using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Security;

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

        group.MapPut("/{id:guid}", UpdateAsync)
            .AddEndpointFilter<AntiforgeryFilter>()
            .WithName("UpdateIncident")
            .Produces<IncidentListItemResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .AddEndpointFilter<AntiforgeryFilter>()        
            .WithName("DeleteIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .AddEndpointFilter<AntiforgeryFilter>()
            .WithName("TriageIncident")
            .Produces<IncidentListItemResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
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
        return incident is null ? NotFoundProblem() : Results.Ok(incident);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, UpdateIncidentRequest request, HttpContext httpContext,
        IncidentChanges changes, CancellationToken cancellationToken)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }

        return ToHttp(await changes.UpdateContentAsync(actor, id, request, cancellationToken),
            httpContext, "incident.update", actor, id);
    }

    private static async Task<IResult> DeleteAsync(
        Guid id, HttpContext httpContext, IncidentChanges changes, CancellationToken cancellationToken)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }

        return ToHttp(await changes.DeleteAsync(actor, id, cancellationToken),
            httpContext, "incident.delete", actor, id);
    }

    private static async Task<IResult> TriageAsync(
        Guid id, HttpContext httpContext, IncidentChanges changes, CancellationToken cancellationToken)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }

        return ToHttp(await changes.TriageAsync(actor, id, cancellationToken),
            httpContext, "incident.triage", actor, id);
    }

    // Єдина відповідь для «не знайдено / не видно»: ту саму використовує і details (A-10).
    internal static IResult NotFoundProblem() => Results.Problem(
        title: "Ресурс не знайдено",
        detail: "Запитаний ресурс не знайдено.",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult ToHttp(
        IncidentChangeResult result, HttpContext httpContext, string action, IncidentActor actor, Guid id)
    {
        switch (result)
        {
            case IncidentChangeResult.NotFound:
                return NotFoundProblem();
            case IncidentChangeResult.Forbidden:
                AuthorizationEvents.Denied(httpContext, action, actor.UserId, actor.Role, id);
                return Results.Problem(
                    title: "Дію заборонено",
                    detail: "Для цієї дії недостатньо прав.",
                    statusCode: StatusCodes.Status403Forbidden);
            case IncidentChangeResult.ValidationFailed failed:
                return Results.ValidationProblem(failed.Errors);
            case IncidentChangeResult.Conflict conflict:
                return Results.Conflict(new { detail = conflict.Detail });
            case IncidentChangeResult.Changed changed:
                return Results.Ok(changed.Response);
            case IncidentChangeResult.Removed:
                return Results.NoContent();
            default:
                throw new InvalidOperationException("Unknown IncidentChangeResult case");
        }
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
