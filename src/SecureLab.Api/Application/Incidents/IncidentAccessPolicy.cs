using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// Єдине місце правил доступу до incidents (відповідає docs/access-matrix.md).
public static class IncidentAccessPolicy
{
    // Query scoping: що користувач взагалі може побачити.
    public static IQueryable<Incident> VisibleTo(IQueryable<Incident> query, IncidentActor actor)
    {
        if (actor.Role == DbSeeder.AnalystRole)
        {
            return query;                                       // аналітик бачить усе для аналізу
        }

        if (actor.Role == DbSeeder.ReporterRole)
        {
            var userId = actor.UserId;
            return query.Where(incident => incident.OwnerUserId == userId);
        }

        return query.Where(incident => false);                  // Administrator: право не опубліковано
    }

    // Child-ресурс: коментар видимий лише разом із видимим parent incident.
    // Internal-коментар бачить лише Analyst.
    public static IQueryable<IncidentComment> VisibleCommentsTo(
        IQueryable<IncidentComment> comments, IQueryable<Incident> visibleIncidents, IncidentActor actor)
    {
        var scoped = comments.Where(comment => visibleIncidents.Any(incident => incident.Id == comment.IncidentId));
        return actor.Role == DbSeeder.AnalystRole
            ? scoped
            : scoped.Where(comment => !comment.IsInternal);
    }    

    // Редагування змісту: лише власник-Reporter.
    public static bool CanEditContent(IncidentActor actor, Incident incident) =>
        actor.Role == DbSeeder.ReporterRole && incident.OwnerUserId == actor.UserId;

    // Видалення: лише власник-Reporter, поки статус New.
    public static bool CanDelete(IncidentActor actor, Incident incident) =>
        CanEditContent(actor, incident) && incident.Status == IncidentStatus.New;

    // Transition: лише Analyst і лише New -> Triaged.
    public static bool CanTriage(IncidentActor actor, Incident incident) =>
        actor.Role == DbSeeder.AnalystRole && incident.Status == IncidentStatus.New;
}