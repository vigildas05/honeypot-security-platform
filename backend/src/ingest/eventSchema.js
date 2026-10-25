import net from "node:net";
import { z } from "zod";

/**
 * Soft limits: attacker-controlled strings longer than this are truncated
 * (and the event is flagged `truncated`). Stored values never exceed these.
 */
export const FIELD_LIMITS = Object.freeze({
  username: 256,
  password: 256,
  auth_method: 32,
  command: 4096,
  http_method: 16,
  http_path: 2048,
  user_agent: 1024,
  header_name: 64,
  header_value: 512,
  max_headers: 20,
  raw: 2048
});

/** Hard limit: anything longer than this is malformed and rejected outright. */
const HARD_MAX = 16_384;

/** Only these request headers are kept; everything else is dropped. */
export const HEADER_ALLOWLIST = new Set([
  "host",
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "content-type",
  "content-length",
  "referer",
  "origin",
  "connection",
  "upgrade",
  "cookie",
  "authorization",
  "x-requested-with",
  // Client-claimed forwarding headers: kept as evidence only, never trusted for src_ip.
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
  "via"
]);

const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_PAST_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Canonicalize an IP string, or return null if it isn't a literal IP.
 * IPv4-mapped IPv6 (::ffff:1.2.3.4) collapses to IPv4; zone ids are dropped.
 * @param {string} value
 * @returns {string | null}
 */
export function normalizeIp(value) {
  let ip = value.trim();
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  const family = net.isIP(ip);
  if (family === 4) return ip;
  if (family === 6) return ip.toLowerCase();
  return null;
}

const str = z.string().max(HARD_MAX);
const headerValue = z.union([str, z.array(str).max(16)]);

const ipField = z.string().max(64).refine((v) => normalizeIp(v) !== null, "must be an IP literal");

const base = {
  timestamp: z.iso.datetime({ offset: true }).refine((v) => {
    const t = Date.parse(v);
    const now = Date.now();
    return t <= now + MAX_FUTURE_SKEW_MS && t >= now - MAX_PAST_AGE_MS;
  }, "timestamp is outside the accepted window"),
  sensor_id: z.string().regex(/^[a-zA-Z0-9_.-]{1,64}$/).optional(),
  src_ip: ipField,
  src_port: z.number().int().min(0).max(65535).optional(),
  session_id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional(),
  raw: str.optional()
};

const sshEvent = z
  .object({
    ...base,
    protocol: z.literal("ssh"),
    event_type: z.enum(["connect", "auth_attempt", "command", "session_closed"]),
    ssh: z
      .object({
        username: str.optional(),
        password: str.optional(),
        auth_method: str.optional(),
        auth_success: z.boolean().optional(),
        command: str.optional()
      })
      .strict()
      .default({})
  })
  .strict();

const httpEvent = z
  .object({
    ...base,
    protocol: z.literal("http"),
    event_type: z.literal("request"),
    http: z
      .object({
        method: str.optional(),
        path: str.optional(),
        user_agent: str.optional(),
        username: str.optional(),
        password: str.optional(),
        headers: z
          .record(z.string().max(256), headerValue)
          .refine((h) => Object.keys(h).length <= 128, "too many headers")
          .optional()
      })
      .strict()
      .default({})
  })
  .strict();

export const wireEventSchema = z.discriminatedUnion("protocol", [sshEvent, httpEvent]);

/** @typedef {z.infer<typeof wireEventSchema>} WireEvent */

/**
 * Make an attacker string safe to store and display as plain text:
 * - lone UTF-16 surrogates become U+FFFD
 * - NUL and other control chars (except \t \n \r) become visible \xNN escapes
 *   (Postgres rejects NUL; raw ESC sequences are a log/terminal injection risk)
 * - bidirectional override/isolate controls become visible \u{NNNN} escapes
 *   (they let attacker text visually reorder what an analyst sees)
 * - truncated to `max` code units without splitting a surrogate pair
 * @param {string | undefined | null} value
 * @param {number} max
 * @returns {{ value: string | null, truncated: boolean }}
 */
export function sanitizeString(value, max) {
  if (value === undefined || value === null) return { value: null, truncated: false };
  let out = value
    .toWellFormed()
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, (c) =>
      `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`
    )
    .replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (c) =>
      `\\u{${c.charCodeAt(0).toString(16)}}`
    );
  let truncated = false;
  if (out.length > max) {
    let end = max;
    const code = out.charCodeAt(end - 1);
    if (code >= 0xd800 && code <= 0xdbff) end -= 1;
    out = out.slice(0, end);
    truncated = true;
  }
  return { value: out, truncated };
}

/**
 * @typedef {object} NormalizedEvent
 * @property {Date} ts
 * @property {string} sensor_id
 * @property {"ssh" | "http"} protocol
 * @property {string} event_type
 * @property {string} src_ip
 * @property {number | null} src_port
 * @property {string | null} session_id
 * @property {string | null} username
 * @property {string | null} password
 * @property {string | null} auth_method
 * @property {boolean | null} auth_success
 * @property {string | null} command
 * @property {string | null} http_method
 * @property {string | null} http_path
 * @property {string | null} user_agent
 * @property {Record<string, string>} http_headers
 * @property {string | null} raw
 * @property {boolean} truncated
 */

/**
 * Turn a schema-valid wire event into the row we store.
 * `sensorId` comes from the authenticated ingest token, never from the payload.
 * @param {WireEvent} event
 * @param {string} sensorId
 * @returns {NormalizedEvent}
 */
export function normalizeEvent(event, sensorId) {
  let truncated = false;
  /** @param {string | undefined | null} v @param {number} max */
  const clean = (v, max) => {
    const r = sanitizeString(v, max);
    truncated ||= r.truncated;
    return r.value;
  };

  const common = {
    ts: new Date(event.timestamp),
    sensor_id: sensorId,
    protocol: event.protocol,
    event_type: event.event_type,
    src_ip: /** @type {string} */ (normalizeIp(event.src_ip)),
    src_port: event.src_port ?? null,
    session_id: event.session_id ?? null,
    raw: clean(event.raw, FIELD_LIMITS.raw)
  };

  if (event.protocol === "ssh") {
    const ssh = event.ssh;
    return {
      ...common,
      username: clean(ssh.username, FIELD_LIMITS.username),
      password: clean(ssh.password, FIELD_LIMITS.password),
      auth_method: clean(ssh.auth_method, FIELD_LIMITS.auth_method),
      auth_success: ssh.auth_success ?? null,
      command: clean(ssh.command, FIELD_LIMITS.command),
      http_method: null,
      http_path: null,
      user_agent: null,
      http_headers: {},
      truncated
    };
  }

  const http = event.http;
  /** @type {Record<string, string>} */
  const headers = {};
  for (const [rawName, rawValue] of Object.entries(http.headers ?? {})) {
    const name = rawName.toLowerCase();
    if (!HEADER_ALLOWLIST.has(name)) continue;
    if (Object.keys(headers).length >= FIELD_LIMITS.max_headers) {
      truncated = true;
      break;
    }
    const joined = Array.isArray(rawValue) ? rawValue.join(", ") : rawValue;
    headers[name] = /** @type {string} */ (clean(joined, FIELD_LIMITS.header_value));
  }

  return {
    ...common,
    username: clean(http.username, FIELD_LIMITS.username),
    password: clean(http.password, FIELD_LIMITS.password),
    auth_method: null,
    auth_success: null,
    command: null,
    http_method: clean(http.method, FIELD_LIMITS.http_method),
    http_path: clean(http.path, FIELD_LIMITS.http_path),
    user_agent: clean(http.user_agent ?? headers["user-agent"], FIELD_LIMITS.user_agent),
    http_headers: headers,
    truncated
  };
}

/**
 * Validate + normalize one untrusted event.
 * Error messages contain only schema paths, never the attacker's values.
 * @param {unknown} input
 * @param {string} sensorId
 * @returns {{ ok: true, event: NormalizedEvent } | { ok: false, error: string }}
 */
export function parseEvent(input, sensorId) {
  const parsed = wireEventSchema.safeParse(input);
  if (!parsed.success) {
    const error = parsed.error.issues
      .slice(0, 5)
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    return { ok: false, error };
  }
  if (parsed.data.sensor_id && parsed.data.sensor_id !== sensorId) {
    return { ok: false, error: "sensor_id: does not match the ingest token" };
  }
  return { ok: true, event: normalizeEvent(parsed.data, sensorId) };
}
