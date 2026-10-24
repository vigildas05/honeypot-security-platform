import { pool } from "../db/pool.js";

// Legacy read API backed by the normalized `events` table. Response shapes are
// unchanged so the original dashboard keeps working.

const LEGACY_SELECT = `
  SELECT
    id,
    ts AS timestamp,
    host(src_ip) AS ip,
    country,
    upper(protocol) AS protocol,
    protocol || '-honeypot' AS service,
    event_type,
    username,
    password,
    command,
    user_agent,
    http_method AS method,
    http_path AS path,
    CASE
      WHEN auth_success IS TRUE THEN 'accepted'
      WHEN auth_success IS FALSE THEN 'rejected'
      ELSE 'captured'
    END AS status
  FROM events`;

export async function listAttacks(limit = 100) {
  const result = await pool.query(`${LEGACY_SELECT} ORDER BY ts DESC LIMIT $1`, [limit]);
  return result.rows;
}

export async function getStats() {
  const [total, today, services, timeline, countries, passwords, ips] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM events"),
    pool.query(
      "SELECT COUNT(*)::int AS count FROM events WHERE ts >= date_trunc('day', NOW())"
    ),
    pool.query(
      `SELECT protocol || '-honeypot' AS service, COUNT(*)::int AS count
       FROM events GROUP BY protocol ORDER BY count DESC`
    ),
    pool.query(
      `SELECT date_trunc('hour', ts) AS bucket, COUNT(*)::int AS count
       FROM events
       WHERE ts >= NOW() - INTERVAL '24 hours'
       GROUP BY bucket
       ORDER BY bucket`
    ),
    pool.query(
      `SELECT COALESCE(country, 'Unknown') AS country, COUNT(*)::int AS count
       FROM events
       GROUP BY 1
       ORDER BY count DESC
       LIMIT 10`
    ),
    pool.query(
      `SELECT password, COUNT(*)::int AS count
       FROM events
       WHERE password IS NOT NULL AND password <> ''
       GROUP BY password
       ORDER BY count DESC
       LIMIT 10`
    ),
    pool.query(
      `SELECT host(src_ip) AS ip, COUNT(*)::int AS count
       FROM events
       GROUP BY src_ip
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
