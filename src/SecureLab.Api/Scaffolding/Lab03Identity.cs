using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;
using SecureLab.Api.Security;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    private const int UserNameMaxLength = 256;
    private const int EmailMaxLength = 256;
    private const int DisplayNameMaxLength = 120;
    
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = new Dictionary<string, string[]>();

            // Нормалізуємо лише поля профілю; пароль не чіпаємо і не логуємо.
            var userName = (input.UserName ?? string.Empty).Trim();
            var email = (input.Email ?? string.Empty).Trim();
            var displayName = (input.DisplayName ?? string.Empty).Trim();

            if (userName.Length == 0)
                errors["userName"] = ["Поле userName є обов'язковим."];
            else if (userName.Length > UserNameMaxLength)
                errors["userName"] = [$"Довжина userName не може перевищувати {UserNameMaxLength} символів."];

            if (email.Length == 0)
                errors["email"] = ["Поле email є обов'язковим."];
            else if (email.Length > EmailMaxLength)
                errors["email"] = [$"Довжина email не може перевищувати {EmailMaxLength} символів."];

            if (displayName.Length == 0)
                errors["displayName"] = ["Поле displayName є обов'язковим."];
            else if (displayName.Length > DisplayNameMaxLength)
                errors["displayName"] = [$"Довжина displayName не може перевищувати {DisplayNameMaxLength} символів."];

            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Поле password є обов'язковим."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = userName, Email = email, DisplayName = displayName
            };
            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToHashSet();

                // Один однаковий результат для зайнятих userName і email.
                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                    return Results.Conflict(new { message = "Користувач із такими даними вже існує." });

                var fieldErrors = new Dictionary<string, string[]>();
                if (codes.Contains("InvalidUserName"))
                    fieldErrors["userName"] = ["userName містить недозволені символи."];
                if (codes.Contains("InvalidEmail"))
                    fieldErrors["email"] = ["email має неправильний формат."];
                if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
                    fieldErrors["password"] = ["Пароль має містити щонайменше 10 символів, велику й малу літеру, цифру та спецсимвол."];
                if (fieldErrors.Count == 0)
                    fieldErrors["registration"] = ["Не вдалося зареєструвати користувача."];
                return Results.ValidationProblem(fieldErrors);
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new RegisteredUserResponse(user.Id, user.UserName!, user.DisplayName));
        });
        
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
            UserManager<ApplicationUser> users, HttpContext httpContext) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                AuthenticationEvents.Write(httpContext, "login", "failure", "unidentified");
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (!result.Succeeded)
            {
                // Однакова подія й однакова відповідь для невідомого імені та хибного пароля.
                AuthenticationEvents.Write(httpContext, "login", "failure", "unidentified");
                return Results.Unauthorized();
            }

            var user = await users.FindByNameAsync(input.UserName);
            AuthenticationEvents.Write(httpContext, "login", "success", user?.Id.ToString() ?? "unknown");
            return Results.NoContent();
        }).RequireRateLimiting(LoginRateLimiting.PolicyName);

        // Logout ідемпотентний: 204 і для користувача без чинної cookie. Видалення cookie робить Identity.
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn, HttpContext httpContext) =>
        {
            var userRef = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
            await signIn.SignOutAsync();
            AuthenticationEvents.Write(httpContext, "logout", "success", userRef);
            return Results.NoContent();
        });

        // Навмисно хибна навчальна довіра: ЛР 03 замінює заявлений id на verified principal.
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        // Єдине джерело ідентичності: principal, який сформувала cookie-автентифікація.
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;
        return Results.Ok(new CurrentUserResponse(verifiedUserId, userName, role));
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegisteredUserResponse(Guid Id, string UserName, string DisplayName);
public sealed record CurrentUserResponse(Guid Id, string UserName, string Role);