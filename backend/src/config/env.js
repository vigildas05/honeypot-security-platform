import dotenv from "dotenv";

dotenv.config();

const DEV_JWT_SECRET = "dev-only-change-me-dev-only-change-me";
const DEV_SENSOR_TOKEN = "dev-honeypot-token";
const KNOWN_WEAK_SECRETS = new Set([
  "change-this-dev-secret",
  "dev-only-change-me",
  DEV_JWT_SECRET,
  DEV_SENSOR_TOKEN,
  "admin123"
]);

/**
 * Parse "sensor-a:token1,sensor-b:token2" into a Map of token -> sensorId.
 * @param {string | undefined} value
 * @returns {Map<string, string>}
 */
export function parseSensorTokens(value) {
  const tokens = new Map();
  for (const entry of (value ?? "").split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf(":");
    if (idx <= 0 || idx === trimmed.length - 1) {
      throw new Error("SENSOR_TOKENS entries must look like sensor_id:token");
    }
    const sensorId = trimmed.slice(0, idx).trim();
    const token = trimmed.slice(idx + 1).trim();
    if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(sensorId)) {
      throw new Error(`Invalid sensor id in SENSOR_TOKENS: ${sensorId}`);
    }
    tokens.set(token, sensorId);
  }
  return tokens;
}

/**
 * @param {string | undefined} value
 * @param {number} fallback
 */
function int(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`Expected a number, got "${value}"`);
  return parsed;
}

/**
 * @param {string | undefined} value
 * @returns {boolean | number | string}
 */
function parseTrustProxy(value) {
  if (value === undefined || value === "" || value === "false") return false;
  if (value === "true") return true;
  const n = Number(value);
  return Number.isInteger(n) ? n : value;
}

/**
 * Tidy a database URL pasted into a hosting dashboard: trim whitespace and one
 * pair of surrounding quotes. Returns "" for unset/blank values.
 * @param {string | undefined} value
 */
export function cleanDatabaseUrl(value) {
  let v = (value ?? "").trim();
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0]) v = v.slice(1, -1).trim();
  return v;
}

const DB_URL_RE = /^postgres(ql)?:\/\/[^\s]+$/i;

/**
 * Build the runtime config. In production, missing or weak secrets are fatal
 * (fail closed) instead of silently falling back to dev defaults.
 * @param {NodeJS.ProcessEnv} raw
 */
export function loadConfig(raw) {
  const nodeEnv = raw.NODE_ENV ?? "development";
  const isProduction = nodeEnv === "production";
  const problems = [];

  const sensorTokens = parseSensorTokens(raw.SENSOR_TOKENS);
  // Legacy single shared token, kept so existing sensors/compose files still work.
  if (raw.HONEYPOT_API_TOKEN) {
    sensorTokens.set(raw.HONEYPOT_API_TOKEN, raw.LEGACY_SENSOR_ID ?? "legacy-sensor");
  }
  if (sensorTokens.size === 0 && !isProduction) {
    sensorTokens.set(DEV_SENSOR_TOKEN, "dev-sensor");
  }

  const jwtSecret = raw.JWT_SECRET_KEY ?? (isProduction ? "" : DEV_JWT_SECRET);

  const databaseUrl = cleanDatabaseUrl(raw.DATABASE_URL);
  const databaseUrlUnpooled = cleanDatabaseUrl(raw.DATABASE_URL_UNPOOLED);
  // Never echo the value: it contains the database password.
  for (const [name, value] of [["DATABASE_URL", databaseUrl], ["DATABASE_URL_UNPOOLED", databaseUrlUnpooled]]) {
    if (value && !DB_URL_RE.test(value)) {
      problems.push(
        `${name} must be one line starting with postgres:// or postgresql:// (check for a "${name}=" or "psql" prefix, spaces or line breaks)`
      );
    }
  }

  if (isProduction) {
    if (!databaseUrl) problems.push("DATABASE_URL is required");
    if (jwtSecret.length < 32 || KNOWN_WEAK_SECRETS.has(jwtSecret)) {
      problems.push("JWT_SECRET_KEY must be set to a random value of at least 32 characters");
    }
    if (sensorTokens.size === 0) problems.push("SENSOR_TOKENS is required");
    for (const token of sensorTokens.keys()) {
      if (token.length < 24 || KNOWN_WEAK_SECRETS.has(token)) {
        problems.push("Every sensor token must be a random value of at least 24 characters");
        break;
      }
    }
  }

  const edlMode = raw.EDL_AUTH_MODE ?? "token";
  if (!["token", "basic", "both"].includes(edlMode)) {
    problems.push("EDL_AUTH_MODE must be token, basic or both");
  }
  const edlToken = raw.EDL_TOKEN ?? "";
  const edlUser = raw.EDL_BASIC_USER ?? "";
  const edlPassword = raw.EDL_BASIC_PASSWORD ?? "";
  if (isProduction) {
    if (edlMode !== "basic" && edlToken && edlToken.length < 24) {
      problems.push("EDL_TOKEN must be at least 24 characters");
    }
    if (edlMode !== "token" && edlUser && edlPassword.length < 16) {
      problems.push("EDL_BASIC_PASSWORD must be at least 16 characters");
    }
  }

  if (problems.length > 0) {
    throw new Error(`Refusing to start with unsafe configuration:\n - ${problems.join("\n - ")}`);
  }

  return {
    nodeEnv,
    isProduction,
    port: int(raw.BACKEND_PORT ?? raw.PORT, 8000),
    databaseUrl: databaseUrl || "postgresql://honeypot:honeypot_password@localhost:5432/honeypot",
    /**
     * Direct (non-pooled) connection for migrations and the worker, which need
     * session state (pg-boss, session advisory locks). On Neon this is
     * DATABASE_URL_UNPOOLED; elsewhere it falls back to DATABASE_URL.
     */
    databaseUrlDirect:
      databaseUrlUnpooled || databaseUrl || "postgresql://honeypot:honeypot_password@localhost:5432/honeypot",
    corsOrigins: (raw.CORS_ORIGINS ?? "http://localhost:5173")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
    trustProxy: parseTrustProxy(raw.TRUST_PROXY),
    jwtSecret,
    jwtTtl: raw.JWT_TTL ?? "1h",
    /** Seed accounts; only used by the migrate step to create users if absent. */
    seedAdminUser: raw.DASHBOARD_ADMIN_USERNAME ?? "admin",
    seedAdminPassword: raw.DASHBOARD_ADMIN_PASSWORD ?? (isProduction ? "" : "admin123"),
    seedDemoUser: raw.DASHBOARD_DEMO_USERNAME ?? "",
    seedDemoPassword: raw.DASHBOARD_DEMO_PASSWORD ?? "",
    sensorTokens,
    ingestMaxBatch: int(raw.INGEST_MAX_BATCH, 100),
    ingestRateLimitPerMinute: int(raw.INGEST_RATE_LIMIT_PER_MINUTE, 1200),
    apiRateLimitPerMinute: int(raw.API_RATE_LIMIT_PER_MINUTE, 300),
    loginRateLimitPer15Min: int(raw.LOGIN_RATE_LIMIT_PER_15MIN, 10),
    /** Firewall External Dynamic List. Disabled (404) unless credentials are configured. */
    edl: {
      mode: /** @type {"token" | "basic" | "both"} */ (edlMode),
      token: edlToken,
      basicUser: edlUser,
      basicPassword: edlPassword
    }
  };
}

export const env = loadConfig(process.env);
