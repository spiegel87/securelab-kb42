# Звіт до лабораторної роботи № 1

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: `lab/1-system`.
- Фінальний тег: `lab1-complete`.
- Commit hash: `3088c9e` (додатково: `386f4a9`).

## 2. Змінений маршрут

Реалізовано `GET /api/incidents/severity-summary?status={optional}`.

Маршрут: клік «Оновити» у `Client/app.js` (`loadSeveritySummary`) →
`GET /api/incidents/severity-summary` → `IncidentEndpoints.GetSeveritySummaryAsync`
(валідація `status` за allowlist `IncidentStatus`) →
`IncidentQueries.GetSeveritySummaryAsync` (`AsNoTracking().Where(status)
.GroupBy(Severity).Select(...).ToListAsync()`, далі сортування за спаданням
критичності в пам'яті) → `SecureLabDbContext` → PostgreSQL (`GROUP BY`,
`COUNT` виконуються в БД) → `IncidentSeveritySummaryResponse[]` → JSON (200)
або `ValidationProblem` (400) → `renderSeveritySummary` →
`createTextElement`/`textContent` у `Client/app.js`.

Повна схема — у `docs/architecture.md`, розділ «Реалізована точка розширення».

## 3. Виконані зміни

- `Presentation/Contracts/IncidentResponses.cs` — додано
  `IncidentSeveritySummaryResponse(string Severity, int Count)`.
- `Application/Incidents/IncidentQueries.cs` — додано
  `GetSeveritySummaryAsync(IncidentStatus? status, CancellationToken)`:
  групування за severity, опціональний фільтр за status, структуроване
  логування, сортування за критичністю.
- `Presentation/Endpoints/IncidentEndpoints.cs` — замінено `501`-заглушку
  на реальний endpoint з allowlist-валідацією `status` (400 при
  невалідному значенні).
- `Client/index.html`, `Client/app.js` — додано панель підсумку з кнопкою
  «Оновити», станами завантаження/порожньо/помилка, безпечним рендером
  (`createTextElement`, без `innerHTML`).
- `tests/http/incidents.http` — додано 4 сценарії.
- `docs/architecture.md` — задокументовано контракт, архітектурні рішення,
  наскрізний маршрут, доповнено таблицю меж довіри.

## 4. Перевірка

| ID | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|
| T-01 | Seed-дані: High/Medium/Low по 1 інциденту | `GET /api/incidents/severity-summary` | 200, 3 групи, без Critical | 200, `[{"High",1},{"Medium",1},{"Low",1}]` | curl-вивід, п. розмови від {дата} |
| T-02 | Один інцидент зі status=New (Low) | `GET .../severity-summary?status=New` | 200, підмножина | 200, `[{"Low",1}]` | curl-вивід |
| T-03 | Жодного інциденту зі status=Closed | `GET .../severity-summary?status=Closed` | 200, порожній масив | 200, `[]` | curl-вивід |
| T-04 | — | `GET .../severity-summary?status=Unknown` | 400 Validation Problem | 400, `errors.status` з описом допустимих значень | curl-вивід |
| T-05 | Деталі інциденту з `<script>` у description | Відкрити картку в браузері | Текст показано буквально, скрипт не виконується | Підтверджено візуально; `renderIncidentDetails` використовує `createTextElement`/`textContent` | Перегляд коду + скріншот/спостереження в браузері |

## 5. Security-сценарій

Не застосовується до цієї роботи. Starter навмисно не містить внесених
вразливостей (README, розділ «Про репозиторій»); ЛР 1 охоплює лише
реалізацію нового read-only endpoint без зміни моделі загроз. Замість
цього в п. 4 (T-05) підтверджено, що вже наявний захист від XSS
(безпечний DOM sink) не порушено новим кодом.

## 6. Висновок

Реалізовано endpoint `GET /api/incidents/severity-summary` за рівнем
«добрий»: DTO-контракт, опціональний query-параметр з allowlist-валідацією,
задокументовані архітектурні рішення (політика нульових груп, порядок
сортування), 4 перевірені вручну HTTP-сценарії та клієнтський UI з повним
набором станів. Усі перевірки з п. 4 пройшли успішно, наскрізний маршрут
підтверджено від DOM до PostgreSQL і назад.
