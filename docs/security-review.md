# Security review SecureLab, ЛР 6

Рівень: добрий («Добре»); рівні накопичувальні. Commit початку огляду (review-start): 1e032bc14d5c03bbd91e4c3cfed597a4f9250b67. Дата: ДАТА. SDK 10.0.401. Профілі: Development і Production-like (no-launch-profile). Клієнти: браузер і HTTP-клієнт (.http / curl).

## 1. Executive summary
Один абзац: що перевірено, скільки знахідок зафіксовано й виправлено, результат фактичного фінального прогону, головні залишкові ризики.
## 2. Scope та exclusions
У межах: поточні відстежувані Git-файли (код, конфігурація, скрипти, docs), клієнт, API, локальна PostgreSQL у Docker Compose, console-журнали; baseline 2-A. Історія Git: не перевірено, якщо нижче не вказано окремо фактичні файли чи refs. Виключено: зовнішній penetration test, production host, реальний TLS/HSTS, Redis, соціальна інженерія, DoS у промисловому масштабі. Усе перевірялось лише на локальному навчальному стенді зі штучними даними.
## 3. System overview і trust boundaries
Для всіх: див. threat-model.md. Добрий/відмінний: кожна межа → конкретний test; відмінний: asset → threat → control → verification.
## 4. Methodology та test environment
Review-start commit: 1e032bc14d5c03bbd91e4c3cfed597a4f9250b67 (гілка lab/6-hardening-review від main; v0.5.0 не переміщено). Локальна БД: PostgreSQL 127.0.0.1:54329 (Docker Compose), стан відновлено командою reset/seed у Development. Профілі: Development (dotnet run, launch profile http) і Production-like (--no-launch-profile -c Release). Клієнти: браузер (cookie-сеанс) і .http / curl. Кожна перевірка в розділах нижче вказує команду, код завершення й профіль.
## 5. Findings summary
Таблиця: ID / актив / вплив / ймовірність / пріоритет / статус / ID повторної перевірки.
## 6. Detailed findings
Щонайменше одна власна знахідка для достатнього рівня, дві виправлені — для доброго; три виправлені — для відмінного, з них третя поза прямим checklist; кожна в окремому файлі docs/findings/*.md.
## 7. Regression results
Для всіх: мінімальний pack SQLi/authentication/authorization-IDOR/XSS/CSRF. Добрий/відмінний: ще validation/CORS/rate limiting. Відмінний: автоматизований повний REG-CSRF-01 (login/cookie → відмова → незмінний стан → token → успіх → змінений стан), команда й фактичний результат. Початкові ID сценаріїв (T/S/A/E/R/REG), команда або тест, передумова, точний результат, перевірка стану ресурсу, перевірений фінальний commit.
## 8. Hardening controls

### Production-like профіль (no-launch-profile) і безпечна помилка

Профіль: Production, `dotnet run --no-launch-profile -c Release`, http://localhost:5080, відкрите навчальне значення connection string із Include Error Detail=false. Клієнт: curl (HTTP-клієнт). Transport: локальний HTTP, не доказ production transport safety.

| Перевірка | Результат |
|---|---|
| Hosting environment | Production (рядок консолі) |
| /openapi/v1.json | 404 application/problem+json: MapOpenApi лише в Development |
| /scalar/v1 | 200 text/html: fallback на index.html, не Scalar |
| --reset-database у Production | відмова InvalidOperationException, дані не змінено |
| AllowedHosts | "*": фільтрацію Host вимкнено; прийнятно лише для локального стенда, у реальному deployment потребує рішення |
| Несправна БД (порт 54399), POST /api/auth/login | 500 application/problem+json з traceId, без stack trace, SQL, шляхів і connection string |
| Журнал ExceptionHandlerMiddleware | TraceId збігається із середнім сегментом traceId відповіді: СЕГМЕНТ; паролі й connection string у журналі: 0 збігів |
| Відновлення | Development, /health 200, login 204, дозволений GET 200 |

## 9. Dependency and secret audit
**Пошук у tracked-файлах (Git):** `git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .`; кількість збігів: 137. Пошук лише у tracked-файлах поточного стану; не доводить відсутність секретів в untracked-файлах, зовнішніх clone/CI чи в історії Git. Реальних credentials не знайдено; кожен збіг класифіковано нижче (за файлами, з номерами рядків).

| Path:рядок | Контекст | Рішення | Причина й межа |
|---|---|---|---|
| .gitignore:14 | коментар до правил ігнорування local-конфігурації | не секрет | пояснення, значення немає |
| README.md:63 | згадка відкритих навчальних credentials БД | accepted, study-only | README забороняє повторне використання; не поширюється на інші БД і середовища |
| README.md:138; docs/git-workflow.md:124 | перелік того, що не має потрапляти в Git | не секрет | текст правил |
| infra/compose.yaml:9 | пароль локального контейнера PostgreSQL, порт на 127.0.0.1 | accepted, study-only | відкрите навчальне значення; не для інших БД |
| src/SecureLab.Api/appsettings.Development.json:3 | connection string Development | accepted, study-only | читається лише в Development; у Production рядок надається ConnectionStrings__SecureLab поза Git |
| src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10 | design-time connection string для EF | accepted, study-only | той самий локальний стенд |
| src/SecureLab.Api/Client/auth-lab.html:27,36; auth-lab.js:120,136 | поле форми й очищення поля пароля | не секрет | назви полів, значення немає |
| src/SecureLab.Api/Data/DbSeeder.cs:39–55,182–208 | читання SeedUsers:Password з конфігурації, створення локальних користувачів | не секрет; джерело конфігурації | значення задають поза Git; seed лише для локального стенда |
| src/SecureLab.Api/Data/Migrations/*.cs (Lab03Identity:52,210; Designer:197; ModelSnapshot:194) | колонка PasswordHash у схемі, коментар | не секрет | опис схеми; хеші лежать у БД, не в Git |
| src/SecureLab.Api/Scaffolding/Lab03Identity.cs:20,68–113,157–158 | опції Identity, DTO register/login, валідація | не секрет | політика довжини пароля, назви полів |
| tests/SecureLab.Api.Tests/*.cs (StudyPassword, LoginAsync, Body) | пароль береться зі змінної SeedUsers__Password | не секрет | значення в коді немає, змінна поза Git |
| tests/SecureLab.Api.Tests/AuthenticationSecurityTests.cs:114 | синтетичний пароль одноразового користувача в тесті | не секрет, synthetic test value | вигадане значення, не належить жодному реальному обліковому запису; використовується лише для перевірки точного порівняння пароля |
| tests/SecureLab.Api.Tests/packages.lock.json:208,291 | назва пакета Microsoft.Extensions.Configuration.UserSecrets | не секрет | назва залежності |
| tests/http/lab-04-access.http:9,27,37 | {{$processEnv SeedUsers__Password}} | не секрет | посилання на змінну середовища |

Межа висновку: прийняття study-only значень не робить подібне tracked-значення прийнятним для іншої БД чи середовища. Для реального credential видалення з поточного файла недостатньо: потрібні відкликання (rotation), бо значення могло залишитися в історії, clone, cache або fork.

**Додатковий пошук:** `git grep -n -I -i -E 'token|connectionstring|bearer|private key' -- .`; збігів: КІЛЬКІСТЬ2. Реальних credentials, bearer-токенів чи приватних ключів не виявлено.

| Група збігів | Приклади | Рішення | Причина |
|---|---|---|---|
| CancellationToken, IsConcurrencyToken | Application/Incidents/*.cs, Presentation/Endpoints/*.cs, Program.cs, Migrations | не секрет | імена типів .NET (скасування асинхронних операцій) і ознака конкурентності EF |
| identity_user_tokens, IdentityUserToken | DatabaseBootstrap.cs, SecureLabDbContext.cs, Migrations | не секрет | назва таблиці й сутності схеми Identity; значень немає |
| AddDefaultTokenProviders | Scaffolding/Lab03Identity.cs:21 | не секрет | стандартні провайдери Identity, значень немає |
| ConnectionStrings__SecureLab | README.md, docs/architecture.md, SecureLabDesignTimeDbContextFactory.cs, Program.cs:17 | не секрет | посилання на джерело конфігурації; значення задають поза Git; local fallback у design-time factory — відкрите study-only значення (див. таблицю вище) |
| docs/*.md, шаблон F-01, власні таблиці | правила роботи з секретами, текст огляду | не секрет | текстові правила й документація |
| AuthenticationEvents.cs:3; тест A01 | коментар, що події НЕ містять пароль і cookie; назва тесту про Bearer challenge | не секрет | пояснення та назва тесту |


**Огляд відстежуваної конфігурації** (`git ls-files` за шаблонами appsettings, .env, compose, .config):

| Файл | Що містить | Рішення | Причина й межа |
|---|---|---|---|
| infra/.env.example | лише POSTGRES_PORT=54329 і коментар, що .env не додають до Git | не секрет | приклад локальної конфігурації без credentials |
| infra/compose.yaml | POSTGRES_PASSWORD: local-study-password; порт БД на 127.0.0.1 | accepted, study-only | відкрите навчальне значення, БД доступна лише локально; не для інших БД |
| src/SecureLab.Api/appsettings.Development.json | connection string Development із local-study-password | accepted, study-only | читається лише в Development; у Production джерело ConnectionStrings__SecureLab поза Git |
| src/SecureLab.Api/appsettings.json | рівні журналювання (Default: Information), AllowedHosts: "*" | не секрет; AllowedHosts записано як залишковий ризик | credentials немає; фільтрацію Host вимкнено, прийнятно лише для локального стенда |
| .env, appsettings.Local.json | не tracked: правила .gitignore:15 і .gitignore:18 | контроль | локальні файли поза Git (перевірено git check-ignore -v) |

## 10. Residual risks
Неперевірені й тимчасово прийняті ризики, відповідальний і наступна дія.
## 11. Conclusion
Лише фактичні результати.
## 12. Evidence appendix
Для відмінного: доказ відсутності чутливих даних у логах шести сценаріїв етапу 3, п. 4; обґрунтування пріоритетів findings; відтворювані передумови й retest для іншої людини.
Шляхи, точні команди, ID сценаріїв, безпечний зв’язок відповіді з записом журналу через traceId; без паролів, cookie, токенів і connection strings.
## Декларація й журнал ШІ
Використовував/ла / не використовував/ла. Назва сервісу, для чого, що перевірено й змінено автором, власна інтерпретація.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| заповнити або не використовував/ла | | | | |
