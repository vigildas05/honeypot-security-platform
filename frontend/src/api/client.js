const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const SESSION_KEY = "dashboardSession";

/**
 * The role stored here only decides which controls the UI shows. Every
 * permission is enforced again by the server (demo users get 403 on any
 * mutation and only ever receive masked IPs).
 * @returns {{ token: string, role: "admin" | "demo", username: string } | null}
 */
export function getSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    const s = raw ? JSON.parse(raw) : null;
    return s && typeof s.token === "string" ? s : null;
  } catch {
    return null;
  }
}

export function clearSession() {
  try {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem("dashboardToken"); // pre-SOC dashboard key
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new Event("session-changed"));
}

export class ApiError extends Error {
  /** @param {number} status @param {string} message */
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** @param {Response} response */
async function handle(response) {
  if (response.status === 401) {
    clearSession();
    throw new ApiError(401, "Session expired, please log in again.");
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, typeof body?.error === "string" ? body.error : `Request failed (${response.status})`);
  }
  return body;
}

/** @param {string} username @param {string} password */
export async function login(username, password) {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  if (!response.ok) throw new ApiError(response.status, response.status === 429 ? "Too many attempts, wait a few minutes." : "Invalid credentials");
  const data = await response.json();
  localStorage.setItem(SESSION_KEY, JSON.stringify({ token: data.token, role: data.role, username: data.username }));
  window.dispatchEvent(new Event("session-changed"));
  return data;
}

const authHeaders = () => ({ authorization: `Bearer ${getSession()?.token ?? ""}` });

/**
 * @param {string} path
 * @param {Record<string, string | number | undefined | null>} [params]
 */
export async function apiGet(path, params) {
  const url = new URL(`${API_BASE_URL}${path}`);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  return handle(await fetch(url, { headers: authHeaders() }));
}

/** @param {string} path @param {unknown} body */
export async function apiPost(path, body) {
  return handle(
    await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: { ...authHeaders(), "content-type": "application/json" },
      body: JSON.stringify(body)
    })
  );
}
