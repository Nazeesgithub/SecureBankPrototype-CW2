// HTTPS is the default for both processes (see scripts/generate_cert.py). Override
// with VITE_API_BASE in frontend/.env if the API is running somewhere else.
const API_BASE = import.meta.env.VITE_API_BASE || "https://localhost:5000/api";

// CSRF protection. The session cookie is SameSite=None so the SPA on a different
// origin can use it, which means the browser also attaches it to requests forged
// by any other site. The defence is a token bound to our session that an attacker
// cannot read across origins, echoed back in a header the server checks.
//
// Fetched once and cached. GET requests do not need it.
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
let csrfToken = null;

async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const response = await fetch(`${API_BASE}/csrf-token`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error("Could not obtain a CSRF token.");
  const body = await response.json();
  csrfToken = body.csrfToken;
  return csrfToken;
}

async function request(path, options = {}, allowCsrfRetry = true) {
  const method = (options.method || "GET").toUpperCase();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (UNSAFE_METHODS.has(method)) {
    headers["X-CSRFToken"] = await getCsrfToken();
  }

  // options is spread first so the headers computed above always win.
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers,
  });

  const isJson = response.headers
    .get("content-type")
    ?.includes("application/json");
  const body = isJson ? await response.json() : null;

  if (!response.ok) {
    // Logging in or out rotates the session, which invalidates a cached token.
    // Drop it, fetch a fresh one, and retry exactly once.
    if (response.status === 400 && body?.csrf === true && allowCsrfRetry) {
      csrfToken = null;
      return request(path, options, false);
    }

    const error = new Error(body?.message || "Request failed.");
    error.status = response.status;
    error.body = body;
    throw error;
  }

  return body;
}

async function download(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    ...options,
  });

  if (!response.ok) {
    const isJson = response.headers
      .get("content-type")
      ?.includes("application/json");
    const body = isJson ? await response.json() : null;
    const error = new Error(body?.message || "Request failed.");
    error.status = response.status;
    error.body = body;
    throw error;
  }

  return response.blob();
}

export const api = {
  session: () => request("/session"),
  register: (payload) =>
    request("/register", { method: "POST", body: JSON.stringify(payload) }),
  login: ({ username, password, portal }) =>
    request("/login", {
      method: "POST",
      body: JSON.stringify({ username, password, portal }),
    }),
  verifyOtp: (otp) =>
    request("/otp/verify", { method: "POST", body: JSON.stringify({ otp }) }),
  logout: async () => {
    const result = await request("/logout", { method: "POST" });
    // The session is gone, so its token is dead too.
    csrfToken = null;
    return result;
  },
  dashboard: () => request("/dashboard"),
  transfer: (payload) =>
    request("/transfer", { method: "POST", body: JSON.stringify(payload) }),
  transactions: () => request("/transactions"),
  profile: () => request("/profile"),
  updateProfile: (payload) =>
    request("/profile", { method: "PATCH", body: JSON.stringify(payload) }),
  changePassword: (payload) =>
    request("/profile/password", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  topUpWallet: (payload) =>
    request("/wallet/topup", { method: "POST", body: JSON.stringify(payload) }),
  securityOverview: () => request("/security/overview"),
  securityEncrypt: (payload) =>
    request("/security/encryption-lab", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  securityAttack: (payload) =>
    request("/security/attack-simulate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  securityDatabase: () => request("/security/database"),
  securityLogs: () => request("/security/logs"),
  securityReport: () => request("/security/report"),
  downloadSecurityReport: () => download("/security/report/download"),
  adminOverview: () => request("/admin/overview"),
  securityBackup: () => request("/security/backup", { method: "POST" }),
  verifySecurityBackup: () =>
    request("/security/backup/verify", { method: "POST" }),
  resetDemoTarget: () =>
    request("/security/reset-demo-target", { method: "POST" }),
  firewallStatus: () => request("/security/firewall-status"),
  firewallConnections: (appOnly = true) =>
    request(`/security/firewall-connections?appOnly=${appOnly}`),
};
