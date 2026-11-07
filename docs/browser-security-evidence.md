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


## CORS: прогноз до зміни конфігурації

| Сценарій | Чи доходить request до API? | Чи може JS прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 | так | так | CORS не потрібен, той самий origin |
| simple GET з probe 4173 | так | ні без policy | SOP/CORS у браузері |
| запит із заголовком з 4173 | спочатку лише OPTIONS | ні без успішного preflight | browser preflight |
| simple GET з probe 4174 | так | ні (origin не в allowlist) | SOP/CORS |
| curl | так | не застосовується | це не JavaScript у браузері |


## CORS: фактичні результати

- Policy Lab05BrowserProbe: навчальний Development-стенд; origin лише http://localhost:4173, метод GET, заголовок X-Lab-Cors-Probe, AllowCredentials. У Production не реєструється. Штатна топологія: same-origin http://localhost:5080.
- Probes: python3 -m http.server 4173 (і 4174) --bind localhost --directory demonstrations/cors-probe.
- До policy: simple і preflighted запити з 4173 та 4174 блоковані браузером; запит до API доходив (Origin, немає Allow-Origin).
- Після policy: 4173 simple GET 200 з Allow-Origin; з заголовком OPTIONS 204 і GET 200; 4174 simple GET блокується для JS (запит дійшов), preflight без Allow-* і actual GET не надсилається.
- Cookie: без AllowCredentials браузер відхиляє credentialed response; з AllowCredentials 4173 читає 200 зі списком, 4174 response не отримує, але запит із cookie виконано.
- curl: Origin 4173 -> Allow-Origin присутній; Origin 4174 -> відсутній; статус 200 в обох: це не SOP.
- Review: CORS керує лише тим, чи браузер надає cross-origin response JavaScript. Він не є authorization (401/403 діють незалежно) і не замінює CSRF-захист: state-changing request з cookie потребує antiforgery, це ЛР 6. Wildcard і AllowAnyOrigin заборонені.


## CSP та browser headers

| Директива | Фактична потреба застосунку | Обране джерело | Що обмежує |
|---|---|---|---|
| default-src | усі ресурси клієнта з власного origin | 'self' | неявні типи ресурсів |
| script-src (fallback) | лише власні JS-файли | 'self' | inline і сторонні скрипти |
| connect-src (fallback) | fetch до API того ж origin | 'self' | сторонні браузерні з'єднання |
| frame-ancestors | вбудовування не потрібне | 'none' | clickjacking через embedding |

Аудит Client/ (grep): inline style, inline-обробників і зовнішніх хостів немає, усі script мають src. Навчальні origins 4173/4174 до постійної CSP не входять. Виняток: /scalar лише в Development (сторонній UI-пакет); це залишковий ризик, у ЛР 6 перевіряється окремо. Третіх сторін у дослідженому flow немає.

| Header | Політика | Ризик, який зменшує | Чого не замінює |
|---|---|---|---|
| X-Content-Type-Options | nosniff (baseline) | небажане MIME sniffing | правильний Content-Type і validation |
| Referrer-Policy | no-referrer (baseline) | витік URL через Referer; клієнт не потребує referrer | заборону секретів в URL |
| CSP frame-ancestors | 'none' | embedding/clickjacking | авторизацію і виправлення XSS |

Спостереження: заголовки видно у відповіді browser-lab.html (200, один CSP-заголовок); керований порушник new Image() заблоковано з повідомленням про default-src.

## REG-XSS-01

| Поле | Вміст |
|---|---|
| Передумови | fixed commit лишається поточним; vulnerable 5a5ecb0; reset: dotnet run --project src/SecureLab.Api -- --reset-database; акаунти alice (автор) і morgan (Analyst); origin http://localhost:5080 |
| Вхід | marker з resources/lab05-marker.txt (однорядковий, без зовнішніх хостів) |
| Кроки | Alice створює запис із marker в Description через browser-lab.html; Morgan відкриває за Guid; відкрити інцидент Alice з comment-5 |
| Очікуваний результат | перевірка data-lab05-marker повертає null; #description містить один текстовий вузол без дочірніх елементів; в #comments немає img; звичайний текст (лапки, < і >, Unicode, теги b) показується буквально |
| Негативний контроль | на vulnerable 5a5ecb0 marker ставив executed (Alice і Morgan) |
| Доказ | Network, Elements, Console; файл Client/browser-lab.js (helper renderText) |

Значення description у БД і в JSON відповіді API однакове до і після fix; змінилось лише відображення в DOM.

## REG-CORS-01

Browser: probes 4173 (дозволений) і 4174 (контрольний), API 5080; код сторінки на 4174 response не отримує, у Network є запит до http://localhost:5080 з Origin. HTTP: curl з Origin 4173 повертає Access-Control-Allow-Origin: http://localhost:4173 і Access-Control-Allow-Credentials: true; з Origin 4174 жодного Access-Control-*; статус 200 в обох, бо curl не застосовує SOP.

## Підсумок: до -> першопричина -> fix -> retest -> залишковий ризик

| Об'єкт | До | Першопричина | Fix | Retest | Залишковий ризик |
|---|---|---|---|---|---|
| Incident.Description | marker виконано (Alice, Morgan) | innerHTML для збереженого значення | renderText (textContent) | null, текстовий вузол, API без змін | CSRF для POST /api/incidents до ЛР 6 |
| IncidentComment.Text | marker виконано | innerHTML | той самий helper | в #comments немає img, null | інші клієнти, що самі рендерять HTML |
| CORS | без policy браузер блокує 4173 і 4174 | немає Allow-Origin | Development-only Lab05BrowserProbe, точний origin 4173 | 4173 читає response, 4174 ні, preflight 204 | CORS не замінює CSRF і авторизацію |
| CSP | відсутня | немає другого шару проти XSS | default-src 'self'; frame-ancestors 'none' | клієнт працює, new Image() заблоковано | виняток /scalar у Development |



## Захист ЛР 5: три CORS-проби (прогноз до запуску)

Зафіксовано тимчасовий logger пише лише method, path, Origin (query у журнал не потрапляє). Allowlist без змін: 4173, GET, X-Lab-Cors-Probe.

| Проба | Origin | Запит | Прогноз fetch | Прогноз рядків журналу | Actual GET на сервері (прогноз) | Факт fetch | Факт журналу |
|---|---|---|---|---|---|---|---|
| a | 4174 | /health?case=kb42-a + X-Lab-Cors-Probe: stage-3 | TypeError: Failed to fetch (preflight не пройшов) | 1 рядок: OPTIONS /health Origin=http://localhost:4174 | ні | | |
| b | 4174 | /health?case=kb42-b без custom header | TypeError: Failed to fetch (response без Allow-Origin) | 1 рядок: GET /health Origin=http://localhost:4174 | так | | |
| c | 4173 | /health?case=kb42-c + X-Lab-Cors-Probe: stage-3 | resolve: status 200, body {"status":"ready"} | 2 рядки: OPTIONS, потім GET, обидва Origin=http://localhost:4173 | так | | |