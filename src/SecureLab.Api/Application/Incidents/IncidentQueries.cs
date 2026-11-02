using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentActor actor,
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = IncidentAccessPolicy.VisibleTo(dbContext.Incidents.AsNoTracking(), actor);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(IncidentActor actor, Guid id, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return IncidentAccessPolicy.VisibleTo(dbContext.Incidents.AsNoTracking(), actor)
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

       public Task<IncidentCommentResponse?> GetCommentAsync(
        IncidentActor actor, Guid commentId, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident comment {CommentId}", commentId);
        // PARENT-READ: parent-інциденти, які actor має право бачити; з них складається доступ до коментаря.
        var visibleIncidents = IncidentAccessPolicy.VisibleTo(dbContext.Incidents.AsNoTracking(), actor);
        return IncidentAccessPolicy.VisibleCommentsTo(
                dbContext.IncidentComments.AsNoTracking(), visibleIncidents, actor)
            .Where(comment => comment.Id == commentId)
            .Select(comment => new IncidentCommentResponse(
                comment.Id, comment.Author.DisplayName, comment.Text, comment.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);
    } 

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
      IncidentStatus? status,
      CancellationToken cancellationToken)
    {
      logger.LogInformation("Building severity summary with status filter {Status}", status);

      var query = dbContext.Incidents.AsNoTracking();
      if (status is not null)
      {
          query = query.Where(incident => incident.Status == status);
      }

      var summary = await query
          .GroupBy(incident => incident.Severity)
          .Select(group => new IncidentSeveritySummaryResponse(
              group.Key.ToString(),
              group.Count()))
              .ToListAsync(cancellationToken);

      var ordered = summary
        .OrderByDescending(item => (int)Enum.Parse<IncidentSeverity>(item.Severity))
        .ToList();

      logger.LogInformation("Severity summary produced {GroupCount} groups", ordered.Count);

      return ordered;
    }

   
}
