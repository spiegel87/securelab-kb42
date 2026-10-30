# Звіт ЛР04

## Контекст і межа виконання
- Рівень: добрий («Добре»). Виконано вимоги достатнього рівня (A-02, A-03, A-03R) і додатково A-01, A-04–A-07, A-08a, A-09, A-10, A-12. Рядки відмінного рівня (A-11) не виконувалось — рівень «Відмінно».
- Власний baseline 2-A, base tag `v0.3.0`, hash `<результат git rev-parse v0.3.0^{commit}>`.
- Головна action: `GET /api/incidents/{id}`. Політика для чужого ресурсу: `404` (query scoping). Маршрути рівня: `GET /api/incidents`, `GET /api/incidents/{id}`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `GET /api/incident-comments/{id}`.
- ЛР 3 після тегу `v0.3.0` не виправлялась (перевірка: `git log v0.3.0..lab/3-authentication --oneline`); тег не пересунуто. `<якщо є коміти — hash і причина>`

## Матриця і server-side рішення
Матриця: `docs/access-matrix.md`.
- Виконавець запиту формується лише з principal (`IncidentActor.From`: claims `NameIdentifier` і `Role`), не з body чи header.
- Query scoping: `IncidentAccessPolicy.VisibleTo` (list, details, усі зміни) і `VisibleCommentsTo` (child-коментарі): Reporter бачить лише власні інциденти, Analyst — усі, Administrator — нічого (право не опубліковано). Чужий і неіснуючий ресурс дають однаковий `404`.
- Правила дій: `CanEditContent`, `CanDelete` (власник, статус `New`), `CanTriage` (`Analyst`, лише `New → Triaged`) у `IncidentAccessPolicy`. Обробники лише викликають політику.
- Дозволені DTO: `UpdateIncidentRequest(Title, Description)`. Server-managed: власник, статус, severity, id, часи, історія статусів. Наступний статус при triage визначає сервер.

## Вразливий стан і PoC
Vulnerable commit: `c3f02e7f202e62bf24145cf01f9db9f061571e27`. Details у ЛР 3 були захищені лише від зміни власника при створенні: читання за id не перевіряло ні автентифікації, ні права на ресурс.

| Дія | Очікувано за матрицею | Фактично (vulnerable) |
|---|---|---|
| Alice → власний інцидент (details) | allow, `200` | `200` |
| Alice → інцидент Bob | deny, `404` | `200` — IDOR |
| Morgan (Analyst) → інцидент Alice | allow, `200` | `200` |
| Анонім → інцидент Bob | deny, `401` | `200` |
| Alice, список | лише власні | 8 записів, серед них інциденти Bob (`…002`, `…004`) і тестові |

Cookie та пароль у доказах не показано.

## Виправлення та retest
Fixed commit = тег `v0.4.0`: `<hash тегу>` (вписано наступним commit після тегу).

| Дія | До | Після |
|---|---|---|
| Alice → власний | `200` | `200` |
| Alice → інцидент Bob | `200` | `404` |
| Morgan → Alice | `200` | `200` |
| Анонім → Bob | `200` | `401` |
| Alice, список | усі записи | лише власні |

Details для Reporter не розкриває чужих даних, внутрішніх owner fields і internal-коментарів. `404` для чужого й неіснуючого id однаковий на всіх реалізованих маршрутах (A-10).

## Доказова таблиця

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | list, details, child | `401`, не HTML redirect | `401`, без `Location` і `WWW-Authenticate` | IncidentAccessTests, IncidentCommentAccessTests |
| A-02 | достатній | Власний ресурс | Alice, власний seed | details | allow | `200` | IncidentAccessTests |
| A-03 | достатній | Чужий ресурс | Alice, ресурс Bob | details з id Bob | `404` | `404`, у тілі немає даних Bob | IncidentAccessTests + запити |
| A-03R | достатній | Аналітичний read | Morgan, ресурс Alice | `GET /api/incidents/{id}` | allow | `200` (Alice і Bob) | IncidentAccessTests |
| A-04 | добрий | Чужий ресурс, зміни | Alice, ресурс Bob | PUT і DELETE з id Bob | deny, стан без змін | `404`, `404`; стан у БД без змін | IncidentChangeTests |
| A-05 | добрий | List | Alice | list | лише дозволена множина | лише інциденти Alice | IncidentAccessTests |
| A-06 | добрий | Вертикальне підвищення | Reporter | triage | deny, status без змін | `403` (власний), `404` (чужий); status `New` | IncidentChangeTests |
| A-07 | добрий | Дозволена привілейована дія | Morgan, інцидент `New` | triage | allow | `200`; запис історії; повторно `403` | IncidentChangeTests |
| A-08a | добрий | Overposting, контракт ігнорує поле | Alice | PUT із ownerUserId, status, severity, role | protected state без змін | `200`; owner, status, severity без змін | IncidentChangeTests |
| A-09 | добрий | Audit | denied triage | знайти `authorization.denied` | безпечна подія | рядок із action, actor, role, resource, result, utc, trace; trace збігається з відповіддю; без секретів | IncidentChangeTests + вивід API |
| A-10 | добрий, `404` | Нерозрізнюваність `404` | Alice | id Bob і неіснуючий id | однакові status, Content-Type, тіло без traceId | збігаються | IncidentAccessTests |
| A-11 | відмінний | search і severity-summary | — | — | — | не виконувалось — рівень «Відмінно» | див. ризики |
| A-12 | добрий | Child resource, internal | Alice; comment-2 Bob; comment-3 internal | `GET /api/incident-comments/{id}` і details | deny; internal не потрапляє | `404`, `404`; свій публічний `200`; details без internal; Analyst читає internal | IncidentCommentAccessTests |

## Основний finding і залишковий ризик
Контекст: після автентифікації (ЛР 3) сервер знає, хто користувач, але не перевіряв його права на конкретний ресурс. Гіпотеза: підміна id в URL дає доступ до чужих даних (IDOR/BOLA). Стан до: vulnerable commit, Alice читає Bob (`200`). Першопричина: `IncidentQueries.GetDetailsAsync` вибирав інцидент лише за id, а `IncidentEndpoints` не читав principal. Fix: `IncidentAccessPolicy` (query scoping і правила дій), однакові `404`, DTO без server-managed полів. Retest: ті самі запити дають `404`/`401`; позитивна регресія: власний ресурс і Analyst читають як раніше.

Залишкові ризики: (1) `GET /api/incidents/search` не вимагає входу й повертає всі інциденти, а `severity-summary` вимагає вхід, але рахує всі записи (A-11, рівень «Відмінно»); (2) CSRF для cookie-мутацій — задокументований навчальний борг до ЛР 6; (3) Administrator не має опублікованих прав на incidents; (4) видалення інциденту каскадно видаляє коментарі й історію; (5) лічильник rate limit у пам'яті одного процесу.

## Browser flow
Login на `auth-lab.html` (Alice) → головна сторінка → власні details → Bob probe (`loadIncidentDetails` з id Bob). Vulnerable: у списку всі інциденти, probe показує дані Bob. Fixed: список лише власних, probe показує `Помилка: Ресурс не знайдено`. Credentials, cookie і `Set-Cookie` на знімках немає.

## Добрий рівень: роль, transition, child, audit
- Transition: лише `Analyst` і лише `New → Triaged`; наступний статус і запис історії створює сервер; Reporter — `403`, не `New` — `403`.
- Morgan читає коментар на інциденті Bob (`200`). Internal на інциденті Alice: Reporter `404`, Analyst `200` після авторизації parent-інциденту.
- Audit: `authorization.denied` з action, actor, role, resource, result, utc і trace; trace збігається з `traceId` відповіді.

## Відмінний рівень
Не виконувалось — рівень «Добре».

## Перевірки, відтворення і подання
- Середовище: Ubuntu (LXC на Proxmox), .NET 10.0.12, PostgreSQL 18.4 (Docker).
- Команди: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`, `dotnet run --project src/SecureLab.Api -- --reset-database`, `dotnet build tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release`, `dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release`.
- Результат: `<рядок Test summary після reset>`.
- Тег `v0.4.0` = fixed commit: `<hash>`. Гілка: `lab/4-authorization`. Посилання на commit/tag і Moodle: `<…>`.
- Не виконувалось: A-11 (рівень «Відмінно»), відтворюваний сценарій concurrent transitions (не надавався).

## Використання ШІ
Використав дозволеним способом.

| Дата/інструмент | Для чого | Що використано | Що перевірено самостійно |
|---|---|---|---|
| жовтень 2026, Claude (Anthropic) | пояснення методики, структура коду політики доступу й тестів, діагностика помилок збірки | фрагменти коду політики, обробників і тестів | збірка, автотести, ручні HTTP-запити, перегляд у браузері, звірка з методикою |

Паролі, cookie, реальні персональні дані й приватний репозиторій не надсилались.