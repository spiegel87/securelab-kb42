using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentChanges(SecureLabDbContext dbContext, ILogger<IncidentChanges> logger)
{
    private const int TitleMaxLength = 160;
    private const int DescriptionMaxLength = 4000;
    private const int HighSeverityDescriptionMinLength = 40;

    private static readonly IncidentStatus[] NotClosedStatuses =
    [
        IncidentStatus.New, IncidentStatus.Triaged, IncidentStatus.InProgress, IncidentStatus.Resolved
    ];

    // Чужий і неіснуючий ресурс дають однаковий NotFound завдяки query scoping.
    private Task<Incident?> FindVisibleAsync(IncidentActor actor, Guid id, CancellationToken cancellationToken) =>
        IncidentAccessPolicy.VisibleTo(dbContext.Incidents, actor)
            .SingleOrDefaultAsync(incident => incident.Id == id, cancellationToken);

    private static IncidentListItemResponse ToResponse(Incident incident) => new(
        incident.Id, incident.Title, incident.Severity.ToString(), incident.Status.ToString(),
        incident.OccurredAtUtc, incident.CreatedAtUtc);

    public async Task<IncidentChangeResult> UpdateContentAsync(
        IncidentActor actor, Guid id, UpdateIncidentRequest request, CancellationToken cancellationToken)
    {
        var incident = await FindVisibleAsync(actor, id, cancellationToken);
        if (incident is null)
        {
            return new IncidentChangeResult.NotFound();
        }

        if (!IncidentAccessPolicy.CanEditContent(actor, incident))
        {
            return new IncidentChangeResult.Forbidden();
        }

        var errors = new Dictionary<string, string[]>();
        var title = (request.Title ?? string.Empty).Trim();
        if (title.Length == 0)
        {
            errors["title"] = ["Поле title є обов'язковим."];
        }
        else if (title.Length > TitleMaxLength)
        {
            errors["title"] = [$"Довжина title не може перевищувати {TitleMaxLength} символів."];
        }

        var description = (request.Description ?? string.Empty).Trim();
        if (description.Length == 0)
        {
            errors["description"] = ["Поле description є обов'язковим."];
        }
        else if (description.Length > DescriptionMaxLength)
        {
            errors["description"] = [$"Довжина description не може перевищувати {DescriptionMaxLength} символів."];
        }
        else if (incident.Severity is IncidentSeverity.High or IncidentSeverity.Critical
                 && description.Length < HighSeverityDescriptionMinLength)
        {
            errors["description"] =
                [$"Для severity High або Critical опис має містити щонайменше {HighSeverityDescriptionMinLength} символів після Trim()."];
        }

        if (errors.Count > 0)
        {
            return new IncidentChangeResult.ValidationFailed(errors);
        }

        var duplicateExists = await dbContext.Incidents.AsNoTracking().AnyAsync(
            other => other.Id != id && other.Title == title && NotClosedStatuses.Contains(other.Status),
            cancellationToken);
        if (duplicateExists)
        {
            return new IncidentChangeResult.Conflict($"Активний інцидент із заголовком «{title}» вже існує.");
        }

        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Incident {IncidentId} content updated", incident.Id);
        return new IncidentChangeResult.Changed(ToResponse(incident));
    }

    public async Task<IncidentChangeResult> DeleteAsync(
        IncidentActor actor, Guid id, CancellationToken cancellationToken)
    {
        var incident = await FindVisibleAsync(actor, id, cancellationToken);
        if (incident is null)
        {
            return new IncidentChangeResult.NotFound();
        }

        if (!IncidentAccessPolicy.CanDelete(actor, incident))
        {
            return new IncidentChangeResult.Forbidden();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Incident {IncidentId} deleted", id);
        return new IncidentChangeResult.Removed();
    }

    public async Task<IncidentChangeResult> TriageAsync(
        IncidentActor actor, Guid id, CancellationToken cancellationToken)
    {
        var incident = await FindVisibleAsync(actor, id, cancellationToken);
        if (incident is null)
        {
            return new IncidentChangeResult.NotFound();
        }

        if (!IncidentAccessPolicy.CanTriage(actor, incident))
        {
            return new IncidentChangeResult.Forbidden();
        }

        var now = DateTimeOffset.UtcNow;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actor.UserId,
            OldStatus = incident.Status,
            NewStatus = IncidentStatus.Triaged,
            Note = "Переведено до Triaged аналітиком.",
            CreatedAtUtc = now
        });
        incident.Status = IncidentStatus.Triaged;       // наступний статус визначає сервер, не клієнт
        incident.UpdatedAtUtc = now;
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Incident {IncidentId} triaged", incident.Id);
        return new IncidentChangeResult.Changed(ToResponse(incident));
    }
}

public abstract record IncidentChangeResult
{
    public sealed record NotFound : IncidentChangeResult;
    public sealed record Forbidden : IncidentChangeResult;
    public sealed record ValidationFailed(IDictionary<string, string[]> Errors) : IncidentChangeResult;
    public sealed record Conflict(string Detail) : IncidentChangeResult;
    public sealed record Changed(IncidentListItemResponse Response) : IncidentChangeResult;
    public sealed record Removed : IncidentChangeResult;
}