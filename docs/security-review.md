# Security review SecureLab, ЛР 6

Рівень: добрий («Добре»); рівні накопичувальні. Commit початку огляду (review-start): 1e032bc14d5c03bbd91e4c3cfed597a4f9250b67. Дата: ДАТА. SDK 10.0.401. Профілі: Development і Production-like (no-launch-profile). Клієнти: браузер і HTTP-клієнт (.http / curl).

## 1. Executive summary
Один абзац: що перевірено, скільки знахідок зафіксовано й виправлено, результат фактичного фінального прогону, головні залишкові ризики.

## 2. Scope та exclusions
У межах: поточні відстежувані Git-файли (код, конфігурація, скрипти, docs), клієнт, API, локальна PostgreSQL у Docker Compose, console-журнали; baseline 2-A. Історія Git: не перевірено, якщо нижче не вказано окремо фактичні файли чи refs. Виключено: зовнішній penetration test, production host, реальний TLS/HSTS, Redis, соціальна інженерія, DoS у промисловому масштабі. Усе перевірялось лише на локальному навчальному стенді зі штучними даними.

## 3. System overview і trust boundaries
Схему та перелік меж дивіться в docs/threat-model.md. Зв'язок кожної межі з перевіркою: browser→API: REG-CSRF-01 і REG-CSRF-02 (токен), REG-XSS-01 (текст не виконується), REG-CORS-01; API→PostgreSQL: S-02 і Search_WithSqliControlPayload_DoesNotExpandResultSet (структура SQL не змінюється); repository→build: git grep секретів і аудит залежностей (розділ 9); environment→configuration: Production-тести (Host_IsReallyProduction, Production_Cookies_AreHttpOnly_Secure_WithSameSite) і відмова --reset-database у Production (розділ 8).

## 4. Methodology та test environment
Review-start commit: 1e032bc14d5c03bbd91e4c3cfed597a4f9250b67 (гілка lab/6-hardening-review від main; v0.5.0 не переміщено). Локальна БД: PostgreSQL 127.0.0.1:54329 (Docker Compose), стан відновлено командою reset/seed у Development. Профілі: Development (dotnet run, launch profile http) і Production-like (--no-launch-profile -c Release). Клієнти: браузер (cookie-сеанс) і .http / curl. Кожна перевірка в розділах нижче вказує команду, код завершення й профіль.

## 5. Findings summary

| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | ID повторної перевірки |
|---|---|---|---|---|---|---|
| F-01 | HTTP-відповіді API (захисні заголовки) | малий: відповіді 500 були без nosniff, Referrer-Policy і CSP; Referrer-Policy дублювався | потрібен збій, що потрапляє в exception handler; на інших відповідях дубль був завжди | P3 | Fixed | REG-HDR-01 |
| F-02 | журнал подій автентифікації | малий: оператор не знаходить запис за traceId відповіді 401, подія без UTC-часу | будь-який вхід | P3 | Fixed | REG-LOG-01 |

Порядок дій. Обидві знахідки мають малий вплив на конфіденційність і цілісність, тому пріоритет P3. F-01 оброблено першою: заголовки стосуються кожного класу відповідей, а доказ і виправлення вимагали лише зміни конвеєра. F-02 друга: це операційна проблема розслідування, її ймовірність висока (кожен вхід), але вплив обмежений. Тимчасово прийнятих ризиків у знахідках немає; прийняті обмеження перелічено в розділі 10.

## 6. Detailed findings
Щонайменше одна власна знахідка для достатнього рівня, дві виправлені — для доброго; три виправлені — для відмінного, з них третя поза прямим checklist; кожна в окремому файлі docs/findings/*.md.

## 7. Regression results

Pack доброго рівня: усі рядки. Автоматизовані сценарії запускаються командою `dotnet test tests/SecureLab.Api.Tests -c Release --filter ...` (або весь набір), ручні процедури описано в docs/browser-security-evidence.md і в розділі 8. Старі ідентифікатори ЛР 2–4 лишаються під своїми іменами; нові REG-* ID введено лише для сценаріїв ЛР 6.

| Рівень | ID у проєкті | Property | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|
| добрий | T-02 (ЛР 2) | server validation | login + чинний токен, POST /api/incidents з severity "7" → 400, errors.severity, ресурс не створено | допустиме input зберігається | `--filter "FullyQualifiedName~CreateIncident_NumericSeverityString\|FullyQualifiedName~CreateIncident_ValidRequest"` | pending |
| достатній | S-02, T-04 (ЛР 2) | query не змінює структуру SQL | Search_WithSqliControlPayload_DoesNotExpandResultSet | Search_WithLegitimateApostrophe_ReturnsExpectedRecordWithoutError; Search_ReturnsJson; Search_WithPercentCharacter_IsTreatedAsLiteralNotWildcard | `--filter "FullyQualifiedName~Search_With\|FullyQualifiedName~Search_ReturnsJson"` | pending |
| достатній | A-* (ЛР 3): A01, A06, A07 | identity lifecycle | A01_Anonymous_Me_Returns401_NotRedirect_NotBearerChallenge; A07_UnknownUser_And_WrongPassword_GiveSameExternalResult; A06_Logout_ThenSameClient_Me_Returns401 | A02_Login_ThenMe_ReturnsCurrentUser_WithSafeFieldsOnly; Login_UsesPasswordExactly_ExactSucceeds_TrimmedFails | `--filter "FullyQualifiedName~AuthenticationSecurityTests"` | pending |
| достатній | A-03, A-04, A-06 (ЛР 4) | server-side ownership / role check | A03_Reporter_ReadsForeignIncident_Returns404_AndNoForeignData; A04_Reporter_UpdateAndDeleteForeignIncident_Return404_AndChangeNothing; A06_Reporter_Triage_OwnIncident_Returns403_ForeignReturns404_StatusUnchanged | A02_Owner_ReadsOwnIncident_Returns200; A07_Analyst_Triage_NewIncident_Returns200_RecordsHistory_ThenNonNewIsForbidden; Owner_UpdatesAndDeletesOwnNewIncident | `--filter "FullyQualifiedName~IncidentAccessTests\|FullyQualifiedName~IncidentChangeTests"` | pending |
| достатній | REG-XSS-01 (ЛР 5) | text не виконується як code | marker: на vulnerable commit 5a5ecb0 виконувався, на fixed поточному стані data-lab05-marker лишається null | звичайний складний текст (лапки, < і >, Unicode, теги b) показується буквально | ручна процедура REG-XSS-01 (docs/browser-security-evidence.md) + автоматично ClientScript_DoesNotUseDangerousInnerHtmlSink, AuthLabScript_DoesNotUseForbiddenSinksOrBrowserStorage | pending |
| добрий | REG-CORS-01 (ЛР 5) | exact browser origin | simple GET з origin 4174 не читається, preflight без Allow-* | allowed origin 4173: 200 і Access-Control-Allow-Origin | ручна процедура з двома probe-origins і curl (розділ 8) | pending |
| достатній | REG-CSRF-01, REG-CSRF-02 (ЛР 6) | token pair required | PUT без / з недійсним токеном → 400, стан не змінено; усі мутації периметра без токена → 400 | валідна пара: очікувана зміна стану; logout без сеансу лишається 204 | `--filter "FullyQualifiedName~CsrfRegressionTests"` | pending |
| добрий | ЗНАЧЕННЯ_ID (ЛР 3) | abuse flow limited (вхід) | Login_AfterLimit_Returns429_ThenRecovers_AndNewHostIsIndependent: перевищення quota → 429 | відновлення після вікна, новий host незалежний | `--filter "FullyQualifiedName~Login_AfterLimit"` | pending |
| добрий | REG-RATE-01 (ЛР 6) | search обмежено для кожного principal окремо | Search_ExhaustedQuota_Returns429_OtherPrincipalUnaffected: 31-й запит → 429, інший користувач 200 | запити в межах quota (30) → 200; відновлення після вікна: ручна перевірка (alice-after-window 200) | `--filter "FullyQualifiedName~SearchRateLimitTests"` + ручна перевірка | pending |
| достатній | REG-HDR-01 (ЛР 6, F-01) | захисні заголовки по одному, у т.ч. на помилці 500 | Baseline_Headers_ArePresent_ExactlyOnce; контрольована 500 (Production, зламана БД) | заголовки на 200 / 400 / 404 | `--filter "FullyQualifiedName~SecurityHeadersTests"` + ручна відповідь 500 | pending |
| достатній | REG-COOKIE-01 (ЛР 6) | cookie мають HttpOnly, SameSite, Secure у Production | Production_Cookies_AreHttpOnly_Secure_WithSameSite | у Development без Secure на HTTP: Login_OverPlainHttp_Development_Cookie_HasNoSecureAttribute | `--filter "FullyQualifiedName~Cookie"` | pending |
| добрий | REG-LOG-01 (ЛР 6, F-02) | подія входу має utc і trace відповіді | FailedLogin_Event_HasUtcTime_AndSameTraceIdAsProblemDetails | AuthenticationEvents_AreLogged_WithoutCredentials | `--filter "FullyQualifiedName~AuthEventTraceTests\|FullyQualifiedName~AuthenticationEvents_AreLogged"` | pending |


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


Периметр змінювальних маршрутів. Джерела зіставлено: git grep серверних Map(Post|Put|Patch|Delete), git grep змінювальних викликів клієнта, OpenAPI /openapi/v1.json; сервер і OpenAPI збігаються (7 операцій). Клієнт викликає лише 3 маршрути; решта лишається browser-accessible через HTTP (.http, curl): CSRF оцінює HTTP-маршрут, а не видимість кнопки.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | POST /api/auth/register | Lab03Identity.cs; OpenAPI; клієнт auth-lab.js | створення облікового запису | ні | так | absent: публічний маршрут не довіряє cookie; ризик account-creation прийнято, окреме рішення в розділі 10 | ручна перевірка UI (register 201) |
| SC-02 | POST /api/auth/login | Lab03Identity.cs; OpenAPI; клієнт auth-lab.js | створення сеансу | ні | так | absent: токен до входу не видається; ризик login-CSRF прийнято, лімітер входу діє | LoginProtectionTests (ЛР 3) |
| SC-03 | POST /api/auth/logout | Lab03Identity.cs; OpenAPI; клієнт auth-lab.js | завершення сеансу | так | так | explicit: AntiforgeryFilter, перевірка до SignOutAsync (для автентифікованих; анонімний logout ідемпотентний) | REG-CSRF-02; Logout_WithoutSession_StaysIdempotent_204 |
| SC-04 | POST /api/incidents | Lab02Endpoints.cs; OpenAPI; клієнт browser-lab.js, auth-lab.js | створення інциденту | так | так | explicit: AntiforgeryFilter | REG-CSRF-02 |
| SC-05 | PUT /api/incidents/{id} | IncidentEndpoints.cs; OpenAPI; DISCREPANCY: виклику в клієнті немає | зміна title і description | так | так | explicit: AntiforgeryFilter | REG-CSRF-01; REG-CSRF-02 |
| SC-06 | DELETE /api/incidents/{id} | IncidentEndpoints.cs; OpenAPI; DISCREPANCY: виклику в клієнті немає | видалення інциденту | так | так | explicit: AntiforgeryFilter | REG-CSRF-02 |
| SC-07 | POST /api/incidents/{id}/triage | IncidentEndpoints.cs; OpenAPI; DISCREPANCY: виклику в клієнті немає | перехід статусу New → Triaged | так | так | explicit: AntiforgeryFilter | REG-CSRF-02 |

DISCREPANCY для SC-05..SC-07: маршрут є в коді й OpenAPI, але клієнт його не викликає. Це не розбіжність документації й коду: API використовується також .http-сценаріями, тому маршрути лишаються browser-accessible й входять до периметра. Узгоджено без змін.

Контракт antiforgery (сервер ↔ клієнт): header X-SecureLab-CSRF; маршрут видачі GET /api/auth/csrf-token (RequireAuthorization, відповідь без кешування); antiforgery-cookie securelab-af (Secure Always поза Development); єдине місце валідації AntiforgeryFilter у Security/AntiforgeryProtection.cs (відмова: 400 Problem Details); клієнт: csrf-helper.js (токен одержується ліниво на кожній сторінці, лише в пам'яті, скидається після login, logout, 400/401 і pageshow). Токен не копіюється в storage; значення токена в докази не потрапляють.

### Транспорт, cookie-профіль і обмеження частоти запитів

**Транспорт (конфігурація).** У launchSettings.json єдиний профіль http (http://localhost:5080); у Program.cs немає UseHttpsRedirection() та UseHsts(). Отже сам baseline не надає доказу HTTPS/HSTS. Local HTTP profile не доводить production transport safety: реальний TLS, HTTP→HTTPS redirect (за замовчуванням 307) і HSTS response на production host не тестувалися. Відсутність Strict-Transport-Security на loopback не класифікується як дефект: за замовчуванням UseHsts не додає його для loopback-хостів. HTTPS, redirect і HSTS виконують різні ролі.

| Cookie | Development (curl, значення приховано) | Production (test host, https://localhost) |
|---|---|---|
| Автентифікації (Identity) | HttpOnly; SameSite=Lax; без Secure (політика SameAsRequest на HTTP) | HttpOnly; Secure; SameSite=Lax (тест Production_Cookies_AreHttpOnly_Secure_WithSameSite) |
| Antiforgery securelab-af | HttpOnly; SameSite=Strict | HttpOnly; Secure (той самий тест) |

TestServer не доводить сертифікат і реальне шифрування. Cookie не є захистом від CSRF сама по собі: SameSite=Lax не замінює antiforgery (localhost:4173 і localhost:5080 належать до одного site).

**Rate limiting.**

| Control | Partition key | Quota / window | Спостереження |
|---|---|---|---|
| POST /api/auth/login (наявний, ЛР 3) | IP | ЗА_КОНФІГУРАЦІЄЮ | відповіді на відомий логін із хибним паролем і на невідомий однакові (статус і розмір тіла: ЗНАЧЕННЯ); після послідовних спроб 429; після вікна вхід знову 204 |
| GET /api/incidents/search (новий) | NameIdentifier з auth-cookie; запасний ключ за IP для анонімних | 30 запитів / 60 с, без черги | 30 відповідей 200 і 429 на 31-ту; інший користувач (morgan) отримав 200; після вікна alice знову 200 |

Quota і partition лімітера не є authorization: 429 не відкриває чужий ресурс, а дозволений запит не стає permitted через наявність quota (повторно перевіряють тести ЛР 4).

**CORS і antiforgery (спостереження).** Політика Lab05BrowserProbe діє лише у Development і дозволяє credentials з origin http://localhost:4173, тож цей origin міг би прочитати відповідь маршруту токена. Це навчальна політика probe-стенда, у Production CORS не реєструється; allowlist із credentials не повинен охоплювати origin, якому не довіряють.

### Журнали й audit trail

Діагностичний журнал допомагає оператору дослідити збій; audit-подія фіксує суб'єкта, дію, ресурс, результат і час. Джерело доказу: консольний журнал із Logging__Console__IncludeScopes=true, записаний у файл поза Git (локальні штучні дані). Висновок стосується лише цих сценаріїв і цього sink.

| Сценарій | Sink / фрагмент | Спостережені поля | Чого немає (перевірено) | Результат |
|---|---|---|---|---|
| Успішний вхід | AuthEvent login, Security/AuthenticationEvents.cs | result success, user id, source, utc, trace | пароль, cookie, token, введене ім'я | пройдено (після F-02) |
| Невдалий вхід | AuthEvent login | result failure, user unidentified, source, utc, trace; відповідь 401 однакова для відомого й невідомого імені | введене ім'я, пароль, причина (акаунт існує чи ні) | пройдено |
| Відмова привілейованої дії | AuthzEvent authorization.denied | action incident.triage, actor, role Reporter, resource, result denied, utc, trace; статус ресурсу не змінився (New → New) | тіло запиту, cookie, email | пройдено |
| Помилка валідації | відповідь 400 Validation Problem Details | errors за полем; у журналі немає запису з тілом запиту | повне тіло запиту | пройдено |
| Неочікувана помилка (Production, зламана БД) | відповідь 500 з traceId; запис ExceptionHandlerMiddleware | traceId відповіді дорівнює середньому сегменту TraceId у журналі | stack trace, SQL, шляхи, connection string у відповіді; секрети в журналі | пройдено |
| Привілейований перехід Incident.Status | таблиця 46 (історія статусів) | перехід New → Triaged, користувач Morgan (Analyst), час; відмова Reporter не створює запис | credential, зайвий dump моделі | пройдено |

Перевірка відсутності чутливого вмісту в журналі (grep -c): пароль із SeedUsers__Password: 0; вигадані паролі WrongPassword1! та NotARealPassword1!: 0; cookie-заголовки: 0; antiforgery-заголовок X-SecureLab-CSRF: 0; параметри EF Core зі справжніми значеннями: ЗНАЧЕННЯ. Log injection: усі виклики журналу використовують шаблони з параметрами, інтерполяції у викликах немає (перевірено пошуком). Мінімізація даних: поле source містить IP-адресу; для локального стенда прийнятно, у реальному середовищі потрібна політика збереження.


### Hardening controls: control, ризик, перевірка, межа

| Control | Ризик | Перевірка | Межа |
|---|---|---|---|
| Antiforgery на всій cookie-мутаційній поверхні (SC-03..SC-07), token route, helper клієнта | CSRF: стороння сторінка надсилає запит з автоматичною cookie користувача | REG-CSRF-01, REG-CSRF-02, ручна перевірка UI | login/register публічні й токеном не захищені (розділ 10) |
| Захисні заголовки, один middleware перед exception handler (OnStarting) | MIME sniffing, витік Referer, embedding; відсутність заголовків на помилці | REG-HDR-01, контрольована 500 | відповіді поза конвеєром (протокольні відмови Kestrel) не охоплено |
| CORS: точний allowlist, лише Development | cross-origin читання відповіді | REG-CORS-01 (4173/4174, curl) | CORS не є authorization і не замінює CSRF |
| Rate limiting входу та пошуку (partition за користувачем/IP) | перебір паролів, зловживання пошуком | Login_AfterLimit_…, Search_ExhaustedQuota_…, ручні перевірки з відновленням | лічильники в пам'яті одного процесу, IP може бути спільним |
| Cookie: HttpOnly, SameSite, Secure у Production | перехоплення/витік cookie | Production_Cookies_AreHttpOnly_Secure_WithSameSite | TestServer не доводить сертифікат і реальний TLS |
| Безпечна 500 з traceId | розкриття стека, SQL, шляхів | відповідь і запис ExceptionHandlerMiddleware, traceId збігається | лише сценарій недосяжної БД |

Змістові відмінності Development і Production: у Development OpenAPI /openapi/v1.json доступний (200), у Production 404 Problem Details; політика CORS Lab05BrowserProbe діє лише у Development, у Production Access-Control-Allow-Origin для 4173 немає; --reset-database у Production відхиляється InvalidOperationException; auth-cookie й antiforgery-cookie мають Secure лише поза Development (SameAsRequest). Шлях /scalar/v1 у Production віддає 200 text/html через fallback клієнта (Scalar не доступний).

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

### Аудит залежностей

SDK 10.0.401, дата ДАТА. Команди: `dotnet restore` restore exit: 0 та `dotnet package list --vulnerable --include-transitive` The given project `SecureLab.Api` has no vulnerable packages given the current sources.
The given project `SecureLab.Api.Tests` has no vulnerable packages given the current sources, з кореня solution. Результат: для проєктів SecureLab.Api та SecureLab.Api.Tests джерело api.nuget.org не повідомило про відомі advisories для версій із packages.lock.json (прямі й транзитивні пакети). Межа висновку: лише відомі на цю дату advisories цього джерела; досяжність коду й невідомі вразливості не оцінювалися.

| Package | Version | Direct / transitive | Advisory / severity | Чи використовується relevant functionality | Доступне оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| (немає записів) | | | не виявлено | | | жодних дій; повторити перед релізом |


**Межі пошуку секретів:** перевірено всі поточні tracked files 98 на дату ДАТА; історія Git 45, stash, інші клони, віддалені копії та зовнішній CI не перевірялися. Реальних credentials не знайдено; рішення для кожного збігу наведено вище. Якби реальний credential знайшовся, він не вносився б у finding card: поширення значення припиняється, повідомляється викладач і розглядається rotation.

## 10. Residual risks

| Ризик | Статус | Відповідальний | Наступна дія |
|---|---|---|---|
| AllowedHosts: "*" (фільтрацію Host вимкнено) | прийнято для локального стенда | автор (студент) | у реальному deployment обмежити перелік хостів |
| login і register без antiforgery-токена (login-CSRF, створення облікових записів) | прийнято; діє limiter входу | автор (студент) | розглянути токен до входу або іншу перевірку при подальшому розвитку |
| Lab05BrowserProbe дозволяє credentials з origin 4173, тож цей origin міг би прочитати відповідь маршруту токена | лише Development, у Production не реєструється | автор (студент) | прибрати політику перед будь-яким deployment |
| Локальний HTTP-профіль: TLS, HTTP→HTTPS redirect і HSTS не тестувалися | не перевірено | автор (студент) | перевірити на production host із сертифікатом |
| IP-адреса в audit-подіях автентифікації | прийнято для навчального стенда | автор (студент) | політика збереження й мінімізації журналів |
| Пошук (Lab02Endpoints) повертає Description; клієнт його не рендерить | залишковий | автор (студент) | будь-який майбутній клієнт має виводити через textContent |
| Відкриті навчальні credentials у tracked-файлах (local-study-password) | accepted, study-only | автор (студент) | не використовувати для інших БД; при реальному credential, rotation |
| Аудит залежностей актуальний на дату запуску | прийнято | автор (студент) | повторити перед релізом |
| Історія Git, stash, інші клони не скануються | не перевірено | автор (студент) | розширити межі пошуку секретів за потреби |
| Лічильники rate limiting у пам'яті процесу; ключі antiforgery ефемерні | прийнято (один процес) | автор (студент) | для кількох екземплярів: спільний store та спільні ключі Data Protection |

## 11. Conclusion

Executive summary. Перевірено поточні відстежувані файли власного SecureLab v0.5.0 (baseline 2-A) на локальному стенді зі штучними даними. Зафіксовано й виправлено дві знахідки (F-01, F-02; обидві P3), додано antiforgery-перевірку на всій cookie-мутаційній поверхні (REG-CSRF-01, REG-CSRF-02), обмеження частоти пошуку на двох partitions, перевірено профілі Development і Production, залежності, секрети та журнали. Результат прогону на гілці перед злиттям: ЗНАЧЕННЯ_ТЕСТІВ з ЗНАЧЕННЯ_ТЕСТІВ автоматизованих тестів пройдено, ручні сценарії REG-XSS-01, REG-CORS-01, 500 і лімітерів виконано ДАТА. Хеш прийнятого merge commit і результат фінального прогону на ньому додає експорт PDF. Головні залишкові ризики: login/register без токена, AllowedHosts "*", локальний HTTP без перевірки TLS і HSTS.

## 12. Evidence appendix
Для відмінного: доказ відсутності чутливих даних у логах шести сценаріїв етапу 3, п. 4; обґрунтування пріоритетів findings; відтворювані передумови й retest для іншої людини.
Шляхи, точні команди, ID сценаріїв, безпечний зв’язок відповіді з записом журналу через traceId; без паролів, cookie, токенів і connection strings.
## Декларація й журнал ШІ
Використовував/ла / не використовував/ла. Назва сервісу, для чого, що перевірено й змінено автором, власна інтерпретація.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| заповнити або не використовував/ла | | | | |


Висновок. Лише фактичні результати: виявлено й виправлено дві знахідки (заголовки безпеки на помилці 500 і час/trace у події автентифікації), реалізовано й перевірено antiforgery на периметрі з семи операцій, rate limiting пошуку з відновленням, підтверджено відсутність паролів, cookie й токенів у журналі за шістьма сценаріями. Не перевірено: реальний TLS і HSTS, історію Git, вплив залежностей за межами відомих advisories на дату запуску.