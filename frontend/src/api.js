const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000/api";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  const isJson = response.headers
    .get("content-type")
    ?.includes("application/json");
  const body = isJson ? await response.json() : null;

  if (!response.ok) {
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
  logout: () => request("/logout", { method: "POST" }),
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
