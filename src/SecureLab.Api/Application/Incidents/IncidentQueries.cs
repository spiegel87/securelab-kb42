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

        var query = VisibleTo(dbContext.Incidents.AsNoTracking(), actor);
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

        return VisibleTo(dbContext.Incidents.AsNoTracking(), actor)
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

     // Єдине місце правила видимості (query scoping): що саме користувач може побачити.
    private static IQueryable<Incident> VisibleTo(IQueryable<Incident> query, IncidentActor actor)
    {
        if (actor.Role == DbSeeder.AnalystRole)
        {
            return query;                                   // аналітик бачить усе для аналізу
        }

        if (actor.Role == DbSeeder.ReporterRole)
        {
            var userId = actor.UserId;
            return query.Where(incident => incident.OwnerUserId == userId);
        }

        return query.Where(incident => false);              // Administrator: право не опубліковано
    }   
}
