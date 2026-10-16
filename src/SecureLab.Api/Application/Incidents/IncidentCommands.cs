using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentCommands(SecureLabDbContext dbContext, ILogger<IncidentCommands> logger)
{
    private const int TitleMaxLength = 160;
    private const int DescriptionMaxLength = 4000;
    private const int HighSeverityDescriptionMinLength = 40;
    private static readonly TimeSpan OccurredAtClockSkew = TimeSpan.FromMinutes(5);

    private static readonly IncidentStatus[] NotClosedStatuses =
    [
        IncidentStatus.New, IncidentStatus.Triaged, IncidentStatus.InProgress, IncidentStatus.Resolved
    ];

    public async Task<CreateIncidentResult> CreateAsync(
        CreateIncidentRequest request,
        Guid ownerUserId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
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

        var severityParsed = Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
            && Enum.IsDefined(severity);
        if (!severityParsed)
        {
            errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
        }

        if (request.OccurredAtUtc is null)
        {
            errors["occurredAtUtc"] = ["Поле occurredAtUtc є обов'язковим."];
        }
        else if (request.OccurredAtUtc > now + OccurredAtClockSkew)
        {
            errors["occurredAtUtc"] =
                ["occurredAtUtc не може випереджати поточний час сервера більш ніж на 5 хвилин."];
        }

        // Cross-field правило перевіряємо лише на вже валідних severity й description.
        if (severityParsed
            && description.Length > 0 && description.Length <= DescriptionMaxLength
            && severity is IncidentSeverity.High or IncidentSeverity.Critical
            && description.Length < HighSeverityDescriptionMinLength)
        {
            errors["description"] =
                [$"Для severity High або Critical опис має містити щонайменше {HighSeverityDescriptionMinLength} символів після Trim()."];
        }

        if (errors.Count > 0)
        {
            logger.LogInformation("Incident create rejected by validation, {ErrorCount} field errors", errors.Count);
            return new CreateIncidentResult.ValidationFailed(errors);
        }

        var duplicateExists = await dbContext.Incidents
            .AsNoTracking()
            .AnyAsync(incident => incident.Title == title && NotClosedStatuses.Contains(incident.Status), cancellationToken);

        if (duplicateExists)
        {
            logger.LogInformation("Incident create rejected: duplicate active title");
            return new CreateIncidentResult.Conflict($"Активний інцидент із заголовком «{title}» вже існує.");
        }

        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = ownerUserId,
            Title = title,
            Description = description,
            Severity = severity,
            Status = IncidentStatus.New,
            OccurredAtUtc = request.OccurredAtUtc!.Value,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        dbContext.Incidents.Add(incident);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Incident {IncidentId} created", incident.Id);

        return new CreateIncidentResult.Created(new CreatedIncidentResponse(
            incident.Id, incident.Title, incident.Severity.ToString(), incident.Status.ToString(),
            incident.OccurredAtUtc, incident.CreatedAtUtc));
    }
}

public abstract record CreateIncidentResult
{
    public sealed record ValidationFailed(IDictionary<string, string[]> Errors) : CreateIncidentResult;
    public sealed record Conflict(string Detail) : CreateIncidentResult;
    public sealed record Created(CreatedIncidentResponse Response) : CreateIncidentResult;
}