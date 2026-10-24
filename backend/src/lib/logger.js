import pino from "pino";

/**
 * Structured JSON logs (one object per line). Secrets are redacted by path,
 * and request URLs have secret query params masked, because the EDL accepts
 * ?token= and firewalls poll it every few minutes.
 *
 * Attacker-controlled content (event bodies, usernames, commands) is never
 * logged here; it lives in the database and is rendered as text in the UI.
 */
export const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.headers[\"x-honeypot-token\"]",
  "headers.authorization",
  "*.password",
  "*.token",
  "*.apiKey",
  "*.api_key",
  "*.secret"
];

const SECRET_QUERY_PARAMS = /([?&](?:token|key|api_key|apikey|password|secret)=)[^&#]*/gi;

/** @param {string | undefined} url */
export function redactUrl(url) {
  return (url ?? "").replace(SECRET_QUERY_PARAMS, "$1[REDACTED]");
}

/**
 * @param {string} service
 * @param {pino.DestinationStream} [destination] for tests
 */
export function createLogger(service, destination) {
  return pino(
    {
      level: process.env.LOG_LEVEL ?? (process.env.NODE_ENV === "test" ? "silent" : "info"),
      base: { service },
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: { paths: REDACT_PATHS, censor: "[REDACTED]" },
      formatters: { level: (label) => ({ level: label }) }
    },
    destination
  );
}

export const logger = createLogger(process.env.SERVICE_NAME ?? "honeypot-backend");
