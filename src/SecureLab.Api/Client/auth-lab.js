const sessionState = document.querySelector("#session-state");
const profileList = document.querySelector("#profile");
const output = document.querySelector("#output");
const registerForm = document.querySelector("#register-form");
const loginForm = document.querySelector("#login-form");
const incidentForm = document.querySelector("#incident-form");

// Усі запити йдуть лише на власний origin; cookie додає браузер, скрипт її не бачить.
async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

function postJson(path, payload) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
}

async function readJson(response) {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) {
    return null;
  }
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function createTextElement(tagName, text) {
  const element = document.createElement(tagName);
  element.textContent = text;
  return element;
}

function showOutput(text) {
  output.textContent = text;
}

function describeProblem(problem, fallback) {
  if (problem?.errors) {
    return Object.entries(problem.errors)
      .map(([field, messages]) => `${field}: ${[].concat(messages).join(" ")}`)
      .join("\n");
  }
  return problem?.message ?? problem?.detail ?? problem?.title ?? fallback;
}

function pad(number) {
  return String(number).padStart(2, "0");
}

function nowLocalValue() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function guarded(action) {
  try {
    await action();
  } catch {
    showOutput("Помилка з’єднання із сервером.");
  }
}

function showAnonymous() {
  sessionState.textContent = "Не ввійшли";
  profileList.replaceChildren();
}

function showSignedIn(profile) {
  sessionState.textContent = "Сеанс активний";
  // Лише дозволені поля відповіді; кожне значення потрапляє на сторінку як текст.
  profileList.replaceChildren(
    createTextElement("dt", "Ідентифікатор"), createTextElement("dd", String(profile.id)),
    createTextElement("dt", "Ім’я користувача"), createTextElement("dd", String(profile.userName)),
    createTextElement("dt", "Роль"), createTextElement("dd", String(profile.role)),
  );
}

function showUnknown(text) {
  sessionState.textContent = `Стан невідомий (${text})`;
  profileList.replaceChildren();
}

// Єдине джерело правди про сеанс: відповідь сервера на GET /api/me.
async function refreshSession() {
  let response;
  try {
    response = await apiFetch("/api/me", { headers: { Accept: "application/json" } });
  } catch {
    showUnknown("немає зв’язку із сервером");
    return null;
  }
  if (response.status === 401) {
    showAnonymous();
    return 401;
  }
  const profile = response.ok ? await readJson(response) : null;
  if (!profile) {
    showUnknown(`код ${response.status}`);
    return response.status;
  }
  showSignedIn(profile);
  return 200;
}

registerForm.addEventListener("submit", event => {
  event.preventDefault();
  guarded(async () => {
    const form = event.currentTarget;
    const response = await postJson("/api/auth/register", Object.fromEntries(new FormData(form)));
    form.elements.password.value = "";
    if (response.status === 201) {
      form.reset();
      showOutput("Реєстрація успішна. Тепер увійдіть.");
      return;
    }
    const problem = await readJson(response);
    showOutput(`Реєстрація: ${response.status}\n${describeProblem(problem, "Помилка")}`);
  });
});

loginForm.addEventListener("submit", event => {
  event.preventDefault();
  guarded(async () => {
    const form = event.currentTarget;
    const response = await postJson("/api/auth/login", Object.fromEntries(new FormData(form)));
    form.elements.password.value = "";
    if (response.status === 204) {
      showOutput("Вхід виконано.");
      await refreshSession();
    } else if (response.status === 401) {
      // Однакове повідомлення для невідомого імені й хибного пароля.
      showOutput("Вхід не виконано: неправильне ім’я користувача або пароль.");
    } else if (response.status === 429) {
      showOutput("Забагато спроб входу. Спробуйте пізніше.");
    } else {
      showOutput(`Помилка входу (код ${response.status}).`);
    }
  });
});

document.querySelector("#me").addEventListener("click", () => guarded(async () => {
  const status = await refreshSession();
  showOutput(`Профіль: ${status ?? "немає відповіді"}`);
}));

incidentForm.addEventListener("submit", event => {
  event.preventDefault();
  guarded(async () => {
    const data = Object.fromEntries(new FormData(incidentForm));
    const occurred = new Date(data.occurredAtUtc);
    if (Number.isNaN(occurred.getTime())) {
      showOutput("Вкажіть дату й час події.");
      return;
    }
    // У запиті лише поля request DTO: власника, статус і id визначає сервер.
    const response = await postJson("/api/incidents", {
      title: data.title,
      description: data.description,
      severity: data.severity,
      occurredAtUtc: occurred.toISOString(),
    });
    const body = await readJson(response);
    if (response.status === 201 && body) {
      showOutput(`Створено (201): ${body.id}\n${body.title} · ${body.severity} · ${body.status}`);
    } else if (response.status === 401) {
      showAnonymous();
      showOutput("Сеанс не діє: увійдіть знову.");
    } else {
      showOutput(`Створення: ${response.status}\n${describeProblem(body, "Помилка")}`);
    }
  });
});

document.querySelector("#logout").addEventListener("click", () => guarded(async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  if (response.status !== 204) {
    showOutput(`Вихід не виконано (код ${response.status}).`);
    return;
  }
  showAnonymous();
  incidentForm.reset();
  incidentForm.elements.occurredAtUtc.value = nowLocalValue();
  const status = await refreshSession();
  showOutput(status === 401
    ? "Вихід виконано. Повторний запит профілю: 401."
    : `Увага: після виходу запит профілю дав код ${status}.`);
}));

incidentForm.elements.occurredAtUtc.value = nowLocalValue();
guarded(refreshSession);