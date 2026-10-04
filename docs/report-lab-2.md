# Звіт до лабораторної роботи № 2

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Базовий тег: `v0.1.0` (завершена ЛР 1, commit `fd5a0bc9a7a607294848b515c4ceceb1c503f46b`).
- Scaffold: `lab-02-start-v1`, встановлений через `install.py 02` (checksums перевірено — усі 5 файлів OK).
- Гілка: `lab/2-input-sqli`.
- Vulnerable commit: `5ac83829aae1e79ed1011bee4507bef61975ccb5`.
- Fixed commit: `66067442eb26e5be7edaf92936a1186a5b91616e`.
- Фінальний тег: `v0.2.0`.

## 2. Змінений маршрут

Реалізовано валідацію `POST /api/incidents` і виправлено SQL injection у
`GET /api/incidents/search`.

**Create:** клієнт → `POST /api/incidents` → `Lab02Endpoints.MapPost` →
`IncidentCommands.CreateAsync` (required/length перевірки, `Enum.TryParse` +
`Enum.IsDefined` для severity, перевірка `occurredAtUtc` на 5-хвилинний
допуск, cross-field правило для High/Critical, перевірка дубліката title
через параметризований LINQ-запит) → за відсутності помилок: `Incident`
зберігається через EF Core, повертається `201 Created` з
`CreatedIncidentResponse` (без `description`, `ownerUserId`).

**Search (виправлено):** клієнт → `GET /api/incidents/search?q=...&sortBy=...`
→ `Lab02Endpoints.MapGet` → allowlist-перевірка `sortBy` → `EF.Functions.ILike`
з параметризованим `pattern`/`escapeString` → PostgreSQL виконує
`WHERE title ILIKE @pattern ESCAPE @escapeString OR description ILIKE
@pattern0 ESCAPE @escapeString0` → JSON-відповідь.

Повна схема, root cause і діфф — у `docs/architecture.md` (доповнити) та в
розділі 5 цього звіту.

## 3. Виконані зміни

- `Presentation/Contracts/IncidentResponses.cs` — додано
  `CreatedIncidentResponse(Id, Title, Severity, Status, OccurredAtUtc,
  CreatedAtUtc)` без server-managed внутрішніх полів.
- `Application/Incidents/IncidentCommands.cs` (новий файл) — `CreateAsync`:
  required/length для title (≤160) і description (≤4000); severity через
  `Enum.TryParse` + `Enum.IsDefined`; `occurredAtUtc` обов'язковий, допуск
  5 хв у майбутнє; cross-field правило (High/Critical → description ≥ 40
  символів після Trim()); перевірка дубліката активного title (чутливо до
  регістру, статуси New/Triaged/InProgress/Resolved); `OwnerUserId` завжди
  `DbSeeder.AliceId` (demo context), встановлюється лише сервером.
- `Scaffolding/Lab02Endpoints.cs` — `POST /api/incidents` підключено до
  `IncidentCommands`; `GET /api/incidents/search` переписано: `FromSqlRaw`
  з конкатенацією замінено на `EF.Functions.ILike` з параметризованим
  `pattern`/`escapeString`; додано `EscapeLikePattern` (екранування `%`,
  `_`, `\`); `sortBy` — allowlist (`createdAtUtc`, `severity`, `status`)
  через `switch`, невідоме значення → 400; явне ранжування для
  severity/status (не лексикографічне).
- `Scaffolding/Lab02Seed.cs` — додано іменовані константи
  `OBrienIncidentId`, `UsbIncidentId`.
- `Program.cs` — зареєстровано `IncidentCommands` у DI.
- `tests/SecureLab.Api.Tests/SearchMechanicsTests.cs` — додано 8 тестів
  (SQLi control payload, apostrophe regression, `%` як literal, unknown
  sortBy, default sort order, duplicate title conflict, numeric severity).
- `tests/http/lab-02-search.http` — додано 8 ручних сценаріїв для Create.

## 4. Перевірка

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректне створення | валідний DTO | `POST /api/incidents` | 201, DTO без зайвих полів | 201, тіло без `description`/`ownerUserId` | curl, `/tmp/r2.json` |
| T-02 | Некоректний DTO | `severity: "7"` | `POST /api/incidents` | 400, `application/problem+json` | 400, `errors.severity` | curl, `/tmp/r1.json` |
| T-03 | Предметний конфлікт | існує активний інцидент з тим самим title | повторний `POST` з тим самим title | 409 | 409, `{"detail":"Активний інцидент... вже існує."}` | curl, `/tmp/r5.json` |
| T-09 | Cross-field перевірка | унікальні title | два POST: description 39 і 40 символів, severity High | перший 400 (ключ description), другий 201 | підтверджено обидва | curl, `/tmp/r3.json`, `/tmp/r4.json` |
| S-01 | SQLi до fix | vulnerable commit `5ac8382`, свіжий seed | контрольний read-only тест `q=zz-no-match' OR TRUE --` | небажано розширена вибірка | 200, усі 5 записів замість очікуваних 0 | curl, спостереження в розмові |
| S-02 | Retest SQLi | fixed commit `6606744`, той самий seed | той самий контрольний тест | порожній результат | 200, `[]` | curl, `Search_WithSqliControlPayload_DoesNotExpandResultSet` |
| T-04 | Позитивна регресія | fixed commit | normal search `q=USB` і apostrophe search `q=комп'ютерного` | коректні записи, без 500 | обидва 200; apostrophe раніше був 500, тепер 200 з коректним записом | curl, `Search_WithLegitimateApostrophe_...` |
| T-05 | Невідоме сортування | fixed commit | `sortBy=unknown` | 400 | 400, `errors.sortBy` | curl, `/tmp/s4.json`, `Search_WithUnknownSortBy_...` |
| T-06 | Ресурс не знайдено | успадковано з ЛР 1 | `GET /api/incidents/{неіснуючий id}` | 404 | 404, `application/problem+json` | `GetDetails_ForUnknownId_ReturnsProblemDetails404` (baseline) |
| A-01 | Огляд data-access points | fixed commit | code search за `FromSqlRaw`/`ExecuteSqlRaw`/конкатенацією/`ORDER BY` | кожен збіг класифіковано | 2 збіги, обидва проаналізовано (нижче) | `git grep`, таблиця нижче |

**Автоматизована перевірка:** `dotnet test` після fixed commit і
`--reset-database` → `total: 12, failed: 0, succeeded: 12, skipped: 0,
duration: 10.9s` (4 baseline-тести ЛР 1 + 8 нових тестів ЛР 2).

### Таблиця A-01

| Файл / метод | Конструкція | Категорія | Висновок |
|---|---|---|---|
| `Data/DatabaseBootstrap.cs:29`, метод `InitializeAsync` | `dbContext.Database.ExecuteSqlRawAsync("TRUNCATE TABLE ...")` | Trusted static SQL | Рядок — константний літерал без жодного користувацького вводу чи конкатенації; викликається лише в Development/`--reset-database` для очищення навчальних таблиць; не приймає зовнішні дані жодним чином |
| `Scaffolding/Lab02Endpoints.cs`, `GET /api/incidents/search` | (було: `FromSqlRaw` з конкатенацією `q`/`sortBy`) | Виправлено | Замінено на `EF.Functions.ILike(..., pattern, escapeString)` (параметризовано) + `switch`-allowlist для `sortBy`; жодного SQL-тексту, зібраного з недовіреного вводу |

## 5. Security-сценарій

1. **Контекст і гіпотеза.** Локальний endpoint `GET /api/incidents/search`
   отримував недовірені `q` і `sortBy` напряму в текст SQL-команди; існував
   ризик, що значення увійде до структури запиту, а не лишиться даними.

2. **Стан до.** Vulnerable commit `5ac83829aae1e79ed1011bee4507bef61975ccb5`.
   Метод: `Lab02Endpoints.MapLab02Endpoints`, лямбда для
   `GET /api/incidents/search`. Точне місце: `var sql = "SELECT * FROM
   incidents WHERE title ILIKE '%" + (q ?? "") + "%' OR description ILIKE
   '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";` з подальшим
   `db.Incidents.FromSqlRaw(sql)`.

3. **Мінімальний PoC.** Власний read-only контрольний сценарій, зафіксований
   на Етапі 1 методички (`zz-no-match' OR TRUE --`), виконаний лише локально
   проти штучних seed-даних; жодних DROP/DELETE/UPDATE чи мережевих дій.

4. **Спостереження.** Контрольне значення `zz-no-match` свідомо не існує в
   жодному title/description. Очікувана вибірка — 0 записів. Фактична
   вибірка на vulnerable commit — усі 5 записів з таблиці `incidents`.
   Окремо: легітимний пошук `комп'ютерного` (слово з апострофом із seed)
   повертав `500 Internal Server Error` замість очікуваного `200`.

5. **Першопричина.** Апостроф у `q` передчасно закривав SQL string literal;
   частина контрольного вводу (`OR TRUE`) ставала новою SQL-умовою, істинною
   для кожного рядка; `--` перетворював решту команди (другий `ILIKE`,
   `ORDER BY`) на SQL-коментар. `sortBy` так само підставлявся напряму як
   назва стовпця/напрямок сортування без жодної перевірки.

6. **Виправлення.** Значення `q` передається через `EF.Functions.ILike`,
   що EF Core/Npgsql транслює в параметризований SQL
   (`ILIKE @pattern ESCAPE @escapeString`) — підтверджено логами EF Core
   під час тестового прогону. Спецсимволи мови ILIKE-патернів (`%`, `_`,
   `\`) екрануються через `EscapeLikePattern` для literal substring
   семантики. `sortBy` обирається виключно через `switch` з трьох наперед
   визначених LINQ-виразів (allowlist); невідоме значення відхиляється з
   `400` до будь-якого звернення до БД.

7. **Retest і позитивна регресія.** Fixed commit
   `66067442eb26e5be7edaf92936a1186a5b91616e`. Той самий PoC
   (`zz-no-match' OR TRUE --`) тепер повертає `200` з порожнім масивом.
   Нормальний пошук (`q=USB`) і пошук легітимного апострофа
   (`комп'ютерного`) обидва повертають `200` з очікуваними записами;
   апостроф більше не спричиняє `500`. Автоматизований regression test
   `Search_WithSqliControlPayload_DoesNotExpandResultSet` перевіряє
   порожність результату explicitly (`Assert.Empty`), а не лише відсутність
   виключення.

8. **Залишковий ризик.** Виправлення усуває лише SQL injection і
   відсутність валідації контракту створення в межах цих двох endpoint-ів.
   Воно не замінює: authorization (у ЛР 2 ще немає верифікованого principal,
   власник — фіксований demo-контекст Alice); обмеження/пагінацію ресурсу
   (`LIMIT 50` — фіксоване значення, не захист від зловживання); перевірку
   інших endpoint-ів поза переліченими в A-01; production-політику
   логування (поточні логи — лише для Development-налагодження).

## 6. Висновок

У ході лабораторної роботи №2 встановлено офіційний навчальний scaffold
`lab-02-start-v1` поверх завершеної ЛР 1 (`v0.1.0`), реалізовано серверну
валідацію контракту `POST /api/incidents` (required/length, severity через
`TryParse`+`IsDefined`, допуск для `occurredAtUtc`, cross-field правило,
перевірка предметного дубліката), відтворено й задокументовано контрольований
SQL injection у пошуковому endpoint-і на окремому vulnerable commit, усунено
першопричину через параметризацію (`EF.Functions.ILike`) та allowlist для
`sortBy`, підтверджено retest і позитивну регресію. Огляд інших
data-access points (A-01) показав, що пошук був єдиним небезпечним місцем
у кодовій базі. Усі 12 автоматизованих тестів (4 baseline + 8 нових) зелені
після фінального `--reset-database`. Роботу зафіксовано в гілці
`lab/2-input-sqli`, vulnerable і fixed стани збережено окремими commit,
фінальний тег `v0.2.0` вказує на виправлений стан.