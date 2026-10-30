using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentCommentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incident-comments")
            .WithTags("Incident comments")
            .RequireAuthorization();

        group.MapGet("/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id, HttpContext httpContext, IncidentQueries queries, CancellationToken cancellationToken)
    {
        var actor = IncidentActor.From(httpContext.User);
        if (actor is null)
        {
            return Results.Unauthorized();
        }

        // Чужий parent, internal для не-Analyst і неіснуючий id: однакова відповідь.
        var comment = await queries.GetCommentAsync(actor, id, cancellationToken);
        return comment is null ? IncidentEndpoints.NotFoundProblem() : Results.Ok(comment);
    }
}