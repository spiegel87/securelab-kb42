# Власна карта source-to-sink

Стан/commit: 5a5ecb0 (vulnerable, scaffold lab-05-start-v1 поверх v0.4.0). Guid marker-record: див. docs/browser-security-evidence.md.

## Потік 1: Incident.Description

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Client/browser-lab.html, form#edit | поле description | контрольоване користувачем |
| Request | Client/browser-lab.js, submit-обробник; DTO CreateIncidentRequest (Scaffolding/Lab02Endpoints.cs) | POST /api/incidents, JSON-поле description | Network, request payload; контрольоване користувачем |
| Validation/mapping | Application/Incidents/IncidentCommands.cs (create), IncidentChanges.cs (PUT) | Trim, довжина <= 4000, для High/Critical >= 40; Description = description | HTML не фільтрується; значення не стає довіреним через validation |
| Storage | Data/Entities/Incident.cs, SecureLabDbContext.cs:37 | Incident.Description, колонка description, максимум 4000 | збережене значення користувача |
| Response | IncidentQueries.GetDetailsAsync; IncidentDetailsResponse | JSON-поле description у GET /api/incidents/{id} | JSON escape не є захистом HTML sink |
| Client transform | Client/browser-lab.js, load() | current.description | без перетворень |
| Sink/context | Client/browser-lab.js:10 | #description.innerHTML = current.description | HTML parser; НЕБЕЗПЕЧНО |

## Потік 2: IncidentComment.Text

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Data/DbSeeder.cs, коментар 30000000-...-0005 (Автор morgan, IsInternal=false) | Text | у навчальному потоці seed; у продукті текст вводить користувач |
| Request | Client/browser-lab.js, load() | GET /api/incidents/{id}, поле comments[] | Network |
| Validation/mapping | IncidentAccessPolicy.VisibleCommentsTo, IncidentQueries.cs:53-56 | comment.Text -> IncidentCommentResponse | авторизація перевіряє право, не вміст |
| Storage | Data/Entities/IncidentComment.cs, SecureLabDbContext.cs:57 | колонка text, максимум 2000 | збережене значення користувача |
| Response | IncidentCommentResponse | JSON-поле text | JSON escape не є захистом HTML sink |
| Client transform | Client/browser-lab.js, цикл по current.comments | comment.text | без перетворень |
| Sink/context | Client/browser-lab.js:14 | paragraph.innerHTML = comment.text | HTML parser; НЕБЕЗПЕЧНО |

## Інвентаризація sinks (Client/)

| Місце | Категорія даних | Контекст | Рішення |
|---|---|---|---|
| browser-lab.js:10, #description.innerHTML | збережене значення користувача | HTML parser | потрібно safe DOM rendering (textContent) |
| browser-lab.js:14, paragraph.innerHTML | збережене значення користувача | HTML parser | потрібно safe DOM rendering (textContent) |
| browser-lab.js, #title.textContent | збережене значення користувача | текстовий вузол | допустимо |
| browser-lab.js, elements.description.value | збережене значення користувача | властивість value | допустимо (HTML не парситься) |
| app.js, auth-lab.js | пошук innerHTML/outerHTML/insertAdjacentHTML/eval/inline handlers: влучань немає | | допустимо |

Залишковий ризик: Scaffolding/Lab02Endpoints.cs (пошук) теж повертає Description, але жоден клієнт його не рендерить.


## Стан після виправлення (safe DOM, без CSP)

- Fixed commit (sink): ХЕШ_ТУТ. Helper renderText у Client/browser-lab.js записує значення через textContent; використано в Description і в тексті коментарів.
- Той самий marker, запис Guid: GUID_ТУТ. Перевірка повертає null, #description містить один текстовий вузол і жодного дочірнього елемента.
- Коментар comment-5 (інцидент Alice): img у #comments відсутні, перевірка повертає null.
- Значення description у JSON відповіді API не змінилось: виправлення лише в місці виведення.
- Складний текст (лапки, < і >, Unicode, теги b) показується без пошкоджень, теги видно буквально.