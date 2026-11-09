# F-01. Захисні заголовки відсутні на помилці 500 і дублюються на решті відповідей

**Статус:** Fixed  
**Актив:** HTTP-відповіді API (браузерні захисні заголовки)  
**Компонент:** конвеєр middleware в Program.cs (UseExceptionHandler і блоки app.Use)  
**Пріоритет:** P3

## Передумови і межі огляду

Review-start commit (див. розділ 4 review), профіль Production (no-launch-profile) із навмисно недосяжною БД, клієнт curl, анонімний запит; reset не застосовувався. Дослідження лише локальне, зі штучними даними.

## Відтворення

1. Запустити production-скрипт у режимі broken (БД на порту 54399).
2. Надіслати POST /api/auth/login з вигаданим паролем (Accept: application/problem+json).
3. Очікувано: 500 із заголовками nosniff, Referrer-Policy, CSP. Фактично: лише Content-Type, інших заголовків немає.
4. Окремо у Development: GET / і GET /health дають по два рядки Referrer-Policy.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Відповіді 500 лишалися без nosniff, Referrer-Policy і CSP; на інших відповідях Referrer-Policy дублювався. Практичний вплив малий (відповіді 500 мають тип application/problem+json, повторне значення no-referrer не змінює політику), але контроль мав діяти на всіх класах відповідей. Умова: збій, який потрапляє в exception handler.

## Першопричина

UseExceptionHandler зареєстровано першим, а заголовки виставляли два блоки app.Use нижче за конвеєром: при винятку handler очищає відповідь і формує Problem Details, тож заголовки втрачаються. Окремо, один із двох блоків додавав Referrer-Policy через Append, а другий присвоєнням, тому значення дублювалося.

## Виправлення

Один middleware перед UseExceptionHandler, який через Response.OnStarting виставляє nosniff, Referrer-Policy і CSP присвоєнням; обидва старі блоки видалено. Fixed commit: 97c1cf9.

## Retest

Повторено той самий broken-сценарій: 500 application/problem+json з рівно одним nosniff, Referrer-Policy і CSP. У Development GET / і GET /health дають по одному Referrer-Policy.

## Positive regression

Клієнт працює (вхід, читання, створення), CSP без порушень у Console; повний набір тестів проходить; тест SecurityHeadersTests перевіряє три заголовки рівно по одному разу на / і /health.

## Залишковий ризик

Заголовки на 500 доведено лише для сценарію з недосяжною БД; відповіді, сформовані до конвеєра (наприклад, відмови Kestrel на рівні протоколу), цим контролем не охоплюються. CSP на JSON-відповіді має обмежену цінність. /scalar у Development навмисно виключено з CSP.

## Доказ

Команда: curl -s -o /dev/null -D - -X POST http://localhost:5080/api/auth/login ... (Production, broken). Тест: SecurityHeadersTests.Baseline_Headers_ArePresent_ExactlyOnce. Паролів, cookie й токенів у доказах немає.