(() => {
  const HEADER = "X-SecureLab-CSRF";
  const TOKEN_ROUTE = "/api/auth/csrf-token";
  let token = null;
  let pending = null;
  let generation = 0;

  // Скидання при зміні принципала (login/logout) і при поверненні з bfcache.
  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch(TOKEN_ROUTE, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) {
        throw new Error(`Token request failed: ${response.status}`);
      }
      const data = await response.json();
      if (current !== generation) {
        throw new Error("Session changed; request a fresh token.");
      }
      if (typeof data.token !== "string" || !data.token) {
        throw new Error("Invalid token response.");
      }
      token = data.token;
      return token;
    })();
    pending = operation;
    try {
      return await operation;
    } finally {
      if (pending === operation) pending = null;
    }
  }

  // Єдиний шлях для змінювальних запитів: токен лише на власний origin.
  async function mutate(url, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      throw new Error("Use normal fetch for read requests.");
    }
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) {
      throw new Error("Token must stay on the same origin.");
    }
    const headers = new Headers(options.headers);
    headers.set(HEADER, await ensureToken());
    const response = await fetch(target, { ...options, method, headers, credentials: "same-origin" });
    // 400/401: токен або сеанс більше не дійсні; наступна дія візьме новий. Автоповтору немає.
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = { reset, ensureToken, mutate };
  window.addEventListener("pageshow", reset);
})();