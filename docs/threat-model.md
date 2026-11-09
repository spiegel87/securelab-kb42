# Модель загроз SecureLab, ЛР 6

| Елемент | Що зафіксувати | Ваш запис |
|---|---|---|
| Версія та середовище | commit початку огляду, профіль запуску, seed/reset, SDK | review-start: 1e032bc14d5c03bbd91e4c3cfed597a4f9250b67 (гілка lab/6-hardening-review від main, нащадка v0.5.0); профілі Development і Production-like (no-launch-profile); локальна БД PostgreSQL у Docker Compose, лише штучні дані; відновлення через dotnet run --project src/SecureLab.Api -- --reset-database у Development; SDK 10.0.401; облікові записи alice, bob (Reporter), morgan (Analyst), admin (Administrator) |
| Компоненти в межах огляду | клієнт, API, БД, конфігурація, журнали | браузерний клієнт (Client/: index.html, app.js, auth-lab.html, browser-lab.html), ASP.NET Core API (.NET 10, EF Core, Identity cookie), PostgreSQL у Docker Compose (127.0.0.1), конфігурація (appsettings*.json, infra/.env.example), консольні журнали. Redis не використовується |
| Активи | облікові дані, власні записи, привілейовані переходи, аудит, секрети | облікові записи (хеші паролів); інциденти та їхній Description; коментарі (публічні та внутрішні); перехід Incident.Status (Triaged); audit events авторизації; cookie сеансу; значення SeedUsers__Password і ConnectionStrings__SecureLab поза Git |
| Суб'єкти | анонім, користувач, moderator/admin, розробник | анонімний відвідувач; Reporter (власні заявки); Analyst (читання всіх, перехід статусу); Administrator (за матрицею ЛР 4 не має прав на incidents, 404); локальний розробник |
| Entry points | HTTP-маршрути, login, форми, конфігурація, restore, журнали | /api/auth/* (login, logout, session-check); /api/incidents (список, деталі, створення, зміна, triage, severity-summary); /api/incident-comments/{id}; пошук (Scaffolding); форми клієнта; завантаження конфігурації при старті; dotnet restore пакетів; консольні журнали. Повний перелік мутацій буде в таблиці периметра (розділ 8 review) |
| Межі довіри | browser→API, API→PostgreSQL, repository→build, environment→configuration | browser→API: текст користувача і cookie недовірені; API→PostgreSQL: параметри запитів недовірені; repository→build: пакети та lockfile; environment→configuration: Development не діє в Production, секрети поза Git |
| Наявні controls | validation, authentication, authorization, DOM, CORS, CSP, antiforgery | validation і ProblemDetails (ЛР 2); параметризований пошук (ЛР 2); Identity cookie, rate limiter логіну (ЛР 3); query scoping, 403/404, audit events (ЛР 4); renderText (textContent), CORS Development-only, CSP і headers (ЛР 5); antiforgery відсутній і додається в ЛР 6 |
| Виключення | що не перевірялося й чому | зовнішній penetration test; production host; реальний TLS і HSTS (локальний HTTP); Redis; соціальна інженерія; DoS у промисловому масштабі; історія Git поза явно переглянутими файлами |

## Схема меж довіри

```text
браузерний клієнт (недовірений ввід, автоматична cookie)
        │  локальний HTTP (Development) / HTTPS у Production
        ▼
ASP.NET Core API (validation, authn/authz, CORS, CSP, antiforgery, журнали)
        │  connection string / EF Core
        ▼
PostgreSQL (дані застосунку, Docker Compose, 127.0.0.1)

репозиторій + NuGet-пакети ──► build/restore
змінні середовища та appsettings ──► запуск API
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Конкретний test або перевірка |
|---|---|---|
| browser→API | змінювальний запит із cookie без валідного токена відхилено без зміни стану; користувацький текст не виконується як код | REG-CSRF-01 (створюється в ЛР 6); REG-XSS-01 (ЛР 5) |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | тест SQLi з ЛР 2 (ID з ЛР 2) |
| repository→build | tracked-файли не містять реальних credentials; restore не змінює lockfile непомітно | git grep (розділ 9 review); dotnet restore --locked-mode |
| environment→configuration | у Production не діє Development-конфігурація, reset заборонено | доказ Hosting environment: Production і відмова --reset-database (крок 1.4) |