# Докази безпеки браузера (DEL-01)

Рівень: добрий («Добре») 

## Стенд і Git-стан (Для всіх)

ОС, browser/version, API/probe origins: API http://localhost:5080, probes 4173 і 4174, release: lab-05-start-v1, base_commit, entry_parent

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080): назва cookie, Domain, Path, HttpOnly, SameSite, Secure — без Value: …

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: … Гіпотеза source → storage → response → sink/context: … Передумови, локальний користувач, Guid запису, marker із resources/lab05-marker.txt, команди reset/start і create/read: …

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | | | |
| DOM основного Description | | | |
| Дія marker | | | |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | | | |
| Довжина за власними правилами ЛР 2 | | | |
| Вікно Morgan: GET і перевірка marker; контроль Bob | | | |

Finding: актив; передумови; першопричина; safe DOM diff; retest; залишковий ризик: … Повторювана REG-XSS-01, негативний контроль і очікування: …

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповніть до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | | | |
| simple GET 4173 → API | | | |
| simple GET 4174 → API | | | |
| curl/.http → API | | не застосовується | |
| preflighted 4173 → API («Добре / Відмінно») | | | |

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | | | |
| Allowed 4173 | | | |
| Disallowed 4174 | | | |
| Direct HTTP / curl | | | |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … safe-url.js / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавайте. Перед поданням повторіть чекліст для свого накопичувального рівня.

## PoC до виправлення (stored XSS, без CSP)

- Vulnerable commit: 5a5ecb0. Marker-record створила Alice, Guid: 87e11e29-932d-42dd-94ed-eaa8bc7f6bed.
- Alice (автор): GET 200, marker виконано, перевірка повертає executed.
- Morgan (Analyst): GET 200, перевірка повертає executed, тобто код виконано в сеансі привілейованого глядача.
- Bob (контроль): GET 404, перевірка повертає null.
- Класифікація: stored XSS. Значення збережено в БД і виконується під час пізнішого перегляду.
- Вплив: код працює від імені глядача (Analyst) і має ті права доступу, які ЛР 4 надає цій ролі.