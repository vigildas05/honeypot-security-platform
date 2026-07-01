import { pool } from "../db/pool.js";
import { guessCountry } from "../utils/geoip.js";

export async function createAttack(payload) {
  const country = payload.country ?? guessCountry(payload.ip);

  const result = await pool.query(
    `INSERT INTO attacks (
      ip, country, protocol, service, username, password, user_agent,
      method, path, headers, metadata, status, connection_duration_ms
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    RETURNING *`,
    [
      payload.ip,
      country,
      payload.protocol,
      payload.service,
      payload.username ?? null,
      payload.password ?? null,
      payload.userAgent ?? null,
      payload.method ?? null,
      payload.path ?? null,
      payload.headers ?? {},
      payload.metadata ?? {},
      payload.status ?? "captured",
      payload.connectionDurationMs ?? null
    ]
  );

  return result.rows[0];
}

export async function listAttacks(limit = 100) {
  const result = await pool.query(
    "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT $1",
    [limit]
  );
  return result.rows;
}

export async function getStats() {
  const [total, today, services, timeline, countries, passwords, ips] =
    await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM attacks"),
      pool.query(
        "SELECT COUNT(*)::int AS count FROM attacks WHERE timestamp >= date_trunc('day', NOW())"
      ),
      pool.query(
        "SELECT service, COUNT(*)::int AS count FROM attacks GROUP BY service ORDER BY count DESC"
      ),
      pool.query(
        `SELECT date_trunc('hour', timestamp) AS bucket, COUNT(*)::int AS count
         FROM attacks
         WHERE timestamp >= NOW() - INTERVAL '24 hours'
         GROUP BY bucket
         ORDER BY bucket`
      ),
      pool.query(
        `SELECT COALESCE(country, 'Unknown') AS country, COUNT(*)::int AS count
         FROM attacks
         GROUP BY country
         ORDER BY count DESC
         LIMIT 10`
      ),
      pool.query(
        `SELECT password, COUNT(*)::int AS count
         FROM attacks
         WHERE password IS NOT NULL AND password <> ''
         GROUP BY password
         ORDER BY count DESC
         LIMIT 10`
      ),
      pool.query(
        `SELECT ip, COUNT(*)::int AS count
         FROM attacks
         GROUP BY ip
         ORDER BY count DESC
         LIMIT 10`
      )
    ]);

  return {
    totalAttacks: total.rows[0].count,
    attacksToday: today.rows[0].count,
    activeHoneypots: services.rows.length,
    services: services.rows,
    timeline: timeline.rows,
    countries: countries.rows,
    topPasswords: passwords.rows,
    topIps: ips.rows
  };
}
