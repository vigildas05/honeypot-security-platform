import { summarize } from "../enrichment/service.js";
import { computeFeatures, persistableFeatures } from "./features.js";
import { RULES, evaluateIncident } from "./rules.js";

const RULE_TAGS = new Set(RULES.map((r) => r.tag));
/** Cap on events loaded to rescore one incident (a long brute force can be huge). */
const MAX_EVENTS_FOR_SCORING = 20_000;

/**
 * @typedef {{ id: string, src_ip: string, created: boolean, event_count: number, analyzed_event_count: number, severity: string }} TouchedIncident
 */

/**
 * Attach every not-yet-correlated event to an incident. Events from the same
 * src_ip belong to the same incident while the gap between consecutive events
 * stays within the inactivity window; a longer gap starts a new incident.
 *
 * Idempotent and safe to run concurrently (per-IP advisory locks, and
 * incident_events.event_id is UNIQUE).
 *
 * @param {import("pg").Pool} db
 * @param {{ windowMinutes: number, batchSize?: number, thresholds?: object }} options
 * @returns {Promise<TouchedIncident[]>}
 */
export async function correlateNewEvents(db, { windowMinutes, batchSize = 2000, thresholds }) {
  const pending = await db.query(
    `SELECT e.id, host(e.src_ip) AS src_ip, e.ts
     FROM events e
     LEFT JOIN incident_events ie ON ie.event_id = e.id
     WHERE ie.event_id IS NULL
     ORDER BY e.ts, e.id
     LIMIT $1`,
    [batchSize]
  );
  if (pending.rowCount === 0) return [];

  /** @type {Map<string, { id: string, ts: Date }[]>} */
  const byIp = new Map();
  for (const row of pending.rows) {
    const list = byIp.get(row.src_ip) ?? [];
    list.push({ id: row.id, ts: row.ts });
    byIp.set(row.src_ip, list);
  }

  const windowMs = windowMinutes * 60_000;
  /** @type {Map<string, boolean>} incident id -> created in this run */
  const touched = new Map();

  for (const [ip, events] of byIp) {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`incident:${ip}`]);

      const latest = await client.query(
        `SELECT id, first_seen, last_seen FROM incidents
         WHERE src_ip = $1 ORDER BY last_seen DESC LIMIT 1`,
        [ip]
      );
      /** @type {{ id: string, first: number, last: number } | null} */
      let current = latest.rows[0]
        ? { id: latest.rows[0].id, first: latest.rows[0].first_seen.getTime(), last: latest.rows[0].last_seen.getTime() }
        : null;

      for (const event of events) {
        const t = new Date(event.ts).getTime();
        const fits = current && t <= current.last + windowMs && t >= current.first - windowMs;
        if (!fits || !current) {
          const created = await client.query(
            `INSERT INTO incidents (src_ip, first_seen, last_seen) VALUES ($1, $2, $2) RETURNING id`,
            [ip, event.ts]
          );
          current = { id: created.rows[0].id, first: t, last: t };
          touched.set(current.id, true);
        } else {
          current.first = Math.min(current.first, t);
          current.last = Math.max(current.last, t);
          if (!touched.has(current.id)) touched.set(current.id, false);
        }
        await client.query(
          `INSERT INTO incident_events (incident_id, event_id) VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING`,
          [current.id, event.id]
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  /** @type {TouchedIncident[]} */
  const results = [];
  for (const [id, created] of touched) {
    const scored = await rescoreIncident(db, id, { windowMinutes, thresholds });
    if (scored) results.push({ ...scored, created });
  }
  return results;
}

/**
 * Build an enrichment summary from cached provider rows (no network calls).
 * @param {import("pg").Pool | import("pg").PoolClient} db
 * @param {string} ip
 */
export async function loadCachedIntel(db, ip) {
  const rows = await db.query(
    "SELECT provider, data FROM ip_enrichment_cache WHERE ip = $1 AND data IS NOT NULL",
    [ip]
  );
  /** @type {Record<string, import("../enrichment/service.js").ProviderOutcome>} */
  const outcomes = {};
  for (const row of rows.rows) outcomes[row.provider] = { status: "cached", data: row.data };
  return { providers: outcomes, summary: summarize(outcomes) };
}

/**
 * Recompute counters, techniques, tags and severity for one incident.
 * Preserves non-rule tags (e.g. prompt-injection-attempt).
 * @param {import("pg").Pool} db
 * @param {string} incidentId
 * @param {{ windowMinutes: number, thresholds?: object }} options
 */
export async function rescoreIncident(db, incidentId, { windowMinutes, thresholds }) {
  const incident = await db.query("SELECT id, host(src_ip) AS src_ip, tags FROM incidents WHERE id = $1", [incidentId]);
  if (!incident.rowCount) return null;
  const { src_ip: ip, tags: existingTags } = incident.rows[0];

  const [events, counts, intel] = await Promise.all([
    db.query(
      `SELECT e.protocol, e.event_type, e.ts, e.username, e.password, e.auth_success, e.auth_method,
              e.command, e.http_method, e.http_path, e.user_agent, e.http_headers, e.session_id
       FROM incident_events ie JOIN events e ON e.id = ie.event_id
       WHERE ie.incident_id = $1
       ORDER BY e.ts DESC
       LIMIT $2`,
      [incidentId, MAX_EVENTS_FOR_SCORING]
    ),
    db.query(
      `SELECT COUNT(*)::int AS n, MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
       FROM incident_events ie JOIN events e ON e.id = ie.event_id WHERE ie.incident_id = $1`,
      [incidentId]
    ),
    loadCachedIntel(db, ip)
  ]);

  const features = computeFeatures(events.rows.reverse());
  const result = evaluateIncident(features, intel.summary, thresholds);
  const preserved = (existingTags ?? []).filter((/** @type {string} */ t) => !RULE_TAGS.has(t));
  const tags = [...new Set([...result.tags, ...preserved])].sort();
  const { n, first_seen, last_seen } = counts.rows[0];

  const updated = await db.query(
    `UPDATE incidents SET
       event_count = $2,
       first_seen = $3,
       last_seen = $4,
       techniques = $5,
       tags = $6,
       severity = $7,
       severity_score = $8,
       stats = $9,
       status = CASE WHEN $4 > NOW() - ($10 || ' minutes')::interval THEN 'open' ELSE status END,
       updated_at = NOW()
     WHERE id = $1
     RETURNING id, host(src_ip) AS src_ip, event_count, analyzed_event_count, severity`,
    [
      incidentId,
      n,
      first_seen,
      last_seen,
      JSON.stringify(result.techniques),
      tags,
      result.severity,
      result.score,
      JSON.stringify({
        features: persistableFeatures(features),
        severity_reasons: result.reasons,
        intel: intel.summary,
        scored_events: events.rowCount,
        scoring_truncated: n > MAX_EVENTS_FOR_SCORING
      }),
      String(windowMinutes)
    ]
  );
  return updated.rows[0];
}

/**
 * Close incidents with no activity inside the window.
 * @param {import("pg").Pool} db
 * @param {number} windowMinutes
 */
export async function closeIdleIncidents(db, windowMinutes) {
  const r = await db.query(
    `UPDATE incidents SET status = 'closed', updated_at = NOW()
     WHERE status = 'open' AND last_seen < NOW() - ($1 || ' minutes')::interval`,
    [String(windowMinutes)]
  );
  return r.rowCount ?? 0;
}
