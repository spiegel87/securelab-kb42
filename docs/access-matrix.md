# Матриця доступу ЛР04

Рівень: добрий («Добре»). Головна action: перегляд деталей `GET /api/incidents/{id}`.
Політика відмови для чужого ресурсу: **404** (query scoping).

## Політика відмов
1. Немає authentication → `401` (не redirect).
2. Автентифікований користувач **не має права бачити** ресурс (чужий інцидент для `Reporter`; будь-який інцидент для `Administrator`, бо право не опубліковано) → `404`. Тіло збігається з відповіддю для неіснуючого id.
3. Користувач **бачить** ресурс, але дія заборонена роллю чи станом (`Analyst`: update/delete; `Reporter`: transition; transition не зі статусу `New`) → `403`.
4. Некоректні дані → `400`, конфлікт стану → `409` за контрактом ЛР 2.

## Матриця
| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, `401` | own: лише власні | all: усі для аналізу | deny, `404`: право не опубліковано | Так для `Reporter` | не реалізовано (vulnerable) |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | — | — | — | — | — | не виконувалось — рівень «Відмінно» |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | — | — | — | — | — | не виконувалось — рівень «Відмінно» |
| Перегляд деталей `GET /api/incidents/{id}` | достатній, головна action | deny, `401` | owner — allow `200`; non-owner — deny `404` | allow `200` для аналізу | deny, `404` | Так | не реалізовано (vulnerable) |
| Створення інциденту | успадкований baseline | deny, `401` | allow, власник = principal | allow, власник = principal | не змінюється в ЛР 4 | Сервер призначає власника | перевірено в ЛР 3 |
| Update content (`title`, `description`) | добрий | deny, `401` | owner — allow `200`; non-owner — deny `404` | deny `403` | deny `404` | Так | IncidentAccessPolicy; тести A-04, A-06, A-07, A-08a, A-09 |
| Delete | добрий | deny, `401` | owner — allow `204` лише при статусі `New`, інакше `403`; non-owner — `404` | deny `403` | deny `404` | Так | IncidentAccessPolicy; тести A-04, A-06, A-07, A-08a, A-09 |
| Зміна status (`POST /api/incidents/{id}/triage`) | добрий | deny, `401` | deny `403` (owner), `404` (non-owner) | allow лише `New → Triaged`, інакше `403`; наступний status ставить сервер | deny `404` | Ні: роль + поточний status; ресурс має бути видимий | IncidentAccessPolicy; тести A-04, A-06, A-07, A-08a, A-09 |
| Internal comment `GET /api/incident-comments/{id}` | добрий | deny, `401` | чужий parent або `IsInternal` — `404`; свій не-internal — allow | allow після авторизації parent incident | deny `404` | Ні для internal; parent перевіряється окремо | IncidentAccessPolicy.VisibleCommentsTo; тести A-12 |
| Export/audit | відмінний | — | — | — | — | — | не застосовується — flow відсутній |

Allow означає право на цю дію над цим ресурсом, а не лише успішний login. `Administrator` не має невизначених дозволів.