namespace SecureLab.Api.Presentation.Contracts;

// Лише поля, які клієнт має право змінювати. Власника, статус і severity тут немає навмисно.
public sealed record UpdateIncidentRequest(string? Title, string? Description);