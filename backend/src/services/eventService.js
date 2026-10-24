import { pool } from "../db/pool.js";

const COLUMNS = [
  "ts",
  "sensor_id",
  "protocol",
  "event_type",
  "src_ip",
  "src_port",
  "session_id",
  "username",
  "password",
  "auth_method",
  "auth_success",
  "command",
  "http_method",
  "http_path",
  "user_agent",
  "http_headers",
  "raw",
  "truncated"
];

/**
 * Insert normalized events in one statement.
 * @param {import("../ingest/eventSchema.js").NormalizedEvent[]} events
 * @param {import("pg").Pool | import("pg").PoolClient} [db]
 * @returns {Promise<{ id: string, src_ip: string, ts: Date }[]>}
 */
export async function insertEvents(events, db = pool) {
  if (events.length === 0) return [];
  /** @type {unknown[]} */
  const params = [];
  const rows = events.map((event) => {
    const placeholders = COLUMNS.map((column) => {
      const value = /** @type {Record<string, unknown>} */ (event)[column];
      params.push(column === "http_headers" ? JSON.stringify(value ?? {}) : value);
      return `$${params.length}`;
    });
    return `(${placeholders.join(", ")})`;
  });

  const result = await db.query(
    `INSERT INTO events (${COLUMNS.join(", ")}) VALUES ${rows.join(", ")}
     RETURNING id, host(src_ip) AS src_ip, ts`,
    params
  );
  return result.rows;
}
