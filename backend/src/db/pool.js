import pg from "pg";
import { env } from "../config/env.js";

/**
 * Pin full TLS verification. node-postgres currently treats sslmode=require /
 * prefer / verify-ca as verify-full, but pg v9 will switch them to libpq
 * semantics (encrypt without verifying the server certificate). Rewriting to
 * verify-full keeps certificate + hostname checks across that upgrade.
 * Neon (and other managed Postgres with public CAs) works with verify-full.
 * @param {string} url
 */
export function withVerifiedTls(url) {
  try {
    const u = new URL(url);
    const mode = u.searchParams.get("sslmode");
    if (mode && ["require", "prefer", "verify-ca"].includes(mode)) {
      u.searchParams.set("sslmode", "verify-full");
      return u.toString();
    }
  } catch {
    // Not a URL (e.g. a libpq keyword string); leave it to pg.
  }
  return url;
}

const poolOptions = {
  max: Number(process.env.DATABASE_POOL_MAX ?? 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
};

/**
 * Request traffic (API). On Neon this can be the pooled (-pooler, PgBouncer
 * transaction mode) DATABASE_URL: the API only runs plain queries and
 * self-contained transactions.
 */
export const pool = new pg.Pool({ connectionString: withVerifiedTls(env.databaseUrl), ...poolOptions });

/** @type {pg.Pool | null} */
let direct = null;

/**
 * Direct (non-pooled) connection for migrations and the worker. Session-level
 * advisory locks, pg-boss and LISTEN/NOTIFY don't work through a transaction
 * pooler. Created lazily, so an API-only process opens no direct connections.
 * Falls back to the same URL as `pool` when no unpooled URL is configured.
 */
export function getDirectPool() {
  if (env.databaseUrlDirect === env.databaseUrl) return pool;
  direct ??= new pg.Pool({ connectionString: withVerifiedTls(env.databaseUrlDirect), ...poolOptions });
  return direct;
}

export async function closePools() {
  await Promise.all([pool.end().catch(() => {}), direct?.end().catch(() => {})]);
}
