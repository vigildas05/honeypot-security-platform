import { cleanRemoteAddress } from "../../common/reporter.js";

const BODY_PREVIEW = 2048;

/**
 * Pull credentials out of a login body (form-encoded or JSON). Bodies are
 * attacker-controlled; this only reads string fields, never evaluates.
 * @param {unknown} body
 * @returns {{ username?: string, password?: string }}
 */
export function extractCredentials(body) {
  /** @type {any} */
  let data = body;
  if (typeof body === "string") {
    const trimmed = body.trim();
    if (trimmed.startsWith("{") && trimmed.length < 65536) {
      try {
        data = JSON.parse(trimmed);
      } catch {
        return {};
      }
    } else {
      data = Object.fromEntries(new URLSearchParams(trimmed));
    }
  }
  if (!data || typeof data !== "object") return {};
  const pick = (/** @type {string[]} */ keys) => {
    for (const key of keys) if (typeof data[key] === "string") return data[key];
    return undefined;
  };
  return {
    username: pick(["username", "user", "login", "email", "log", "uname"]),
    password: pick(["password", "pass", "pwd", "passwd"])
  };
}

/**
 * Build a normalized wire event from an Express request.
 *
 * SECURITY: src_ip comes ONLY from the TCP socket. Forwarding headers
 * (X-Forwarded-For, X-Real-IP, Forwarded) are attacker-controlled and are kept
 * as evidence in headers, never used as the source address — otherwise an
 * attacker could frame any IP and get the agent to propose blocking it.
 * @param {import("express").Request} req
 */
export function buildHttpEvent(req) {
  const body = req.body;
  const bodyText =
    typeof body === "string" ? body : body && Object.keys(body).length ? JSON.stringify(body) : "";
  const { username, password } = extractCredentials(body);

  /** @type {Record<string, string | string[]>} */
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string" || Array.isArray(value)) headers[name] = value;
  }

  return {
    timestamp: new Date().toISOString(),
    protocol: "http",
    event_type: "request",
    src_ip: cleanRemoteAddress(req.socket.remoteAddress),
    src_port: req.socket.remotePort,
    raw: `${req.method} ${req.originalUrl} HTTP/${req.httpVersion}${bodyText ? `\n\n${bodyText.slice(0, BODY_PREVIEW)}` : ""}`,
    http: {
      method: req.method,
      path: req.originalUrl,
      user_agent: typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : undefined,
      username,
      password,
      headers
    }
  };
}
