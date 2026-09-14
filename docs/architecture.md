# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents або GET /api/incidents/{id}
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs
  → PostgreSQL
  → response DTO у Presentation/Contracts/
  → JSON
  → textContent/createTextNode у Client/app.js
```

## Межі довіри

| Межа | Чому даним ще не можна довіряти | Де перевіряємо або обмежуємо |
|---|---|---|
| Користувач → Browser client | Користувач контролює введення (наприклад, значення фільтра `status` у формі) | `filterForm`/`FormData` зчитує значення без валідації на клієнті — валідація навмисно відкладена на сервер |
| Browser client → API | Клієнт і HTTP-запит можна змінити поза UI (curl, DevTools, змінений `fetch`) | Route constraint `:guid` на рівні routing; `Enum.TryParse` + `Enum.IsDefined` allowlist-валідація `status` у `IncidentEndpoints` (перевірено вручну: `?status=Unknown` → 400 Validation Problem) |
| PostgreSQL → API → DOM | У БД може зберігатися раніше введений недорований текст (напр. `description` з буквальним `<script>`) | `IncidentDetailsResponse` — явна проєкція полів (без `OwnerUserId`, internal-коментарів); `renderIncidentDetails` виводить через `createTextElement`/`document.createTextNode`, ніколи `innerHTML`; перевірено вручну — `<script>` відображається як текст, не виконується |
| API → PostgreSQL (severity-summary) | Параметр `status` передається у `Where()` перед `GroupBy` | LINQ-параметризація EF Core (не конкатенація SQL-рядків); перевірено SQL-звіркою `SELECT status, count(*) FROM incidents GROUP BY status` |

## Конфігураційні входи

- `global.json` — версія .NET SDK;
- `src/SecureLab.Api/appsettings*.json` — режим міграцій і локальний connection string;
- `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.

## Реалізована точка розширення: GET /api/incidents/severity-summary

Реалізовано під час ЛР 1 (гілка `lab/1-system`).

### Контракт

- Маршрут: `GET /api/incidents/severity-summary?status={optional}`
- Response DTO: `IncidentSeveritySummaryResponse(string Severity, int Count)` у `Presentation/Contracts/IncidentResponses.cs`
- Query параметр `status` — необов'язковий, allowlist `IncidentStatus` (New/Triaged/InProgress/Resolved/Closed); невалідне значення → `400` Validation Problem Details (той самий патерн, що й у `GET /api/incidents`)

### Архітектурні рішення

- **Політика нульових груп**: включаються лише severity, які реально присутні серед відфільтрованих інцидентів (без доповнення Critical/тощо нулями). Обрано для простоти; альтернатива — повний перелік `Enum.GetValues<IncidentSeverity>()` з нулями для відсутніх груп.
- **Порядок сортування**: за спаданням критичності (Critical → High → Medium → Low), а не лексикографічний. Оскільки `Severity` зберігається як `HasConversion<string>()`, SQL-сортування було б лексикографічним (`Critical, High, Low, Medium`) — тому сортування виконується вже на матеріалізованому списку в пам'яті через `Enum.Parse<IncidentSeverity>` після `ToListAsync()`.

### Наскрізний маршрут

```text
клік «Оновити» у Client/app.js (loadSeveritySummary)
  → GET /api/incidents/severity-summary?status={optional}
  → Presentation/Endpoints/IncidentEndpoints.cs → GetSeveritySummaryAsync
    → Enum.TryParse + Enum.IsDefined allowlist-валідація status
  → Application/Incidents/IncidentQueries.cs → GetSeveritySummaryAsync
    → AsNoTracking().Where(status).GroupBy(Severity).Select(...).ToListAsync()
    → сортування за критичністю в пам'яті
  → Data/SecureLabDbContext.cs → таблиця incidents
  → PostgreSQL (GROUP BY, COUNT виконуються в БД)
  → IncidentSeveritySummaryResponse[] → JSON (200) або ValidationProblem (400)
  → renderSeveritySummary → createTextElement/textContent у Client/app.js
```

### Перевірено вручну (tests/http/incidents.http)

| Сценарій | Запит | Результат |
|---|---|---|
| Без фільтра | `GET /api/incidents/severity-summary` | 200, `[{"High",1},{"Medium",1},{"Low",1}]` |
| Валідний фільтр, є збіги | `?status=New` | 200, `[{"Low",1}]` |
| Валідний фільтр, збігів немає | `?status=Closed` | 200, `[]` |
| Невалідний фільтр | `?status=Unknown` | 400, `errors.status` |
