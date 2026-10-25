import { attackUrl } from "../attack/catalog.js";
import { pool } from "../db/pool.js";

export const SEVERITIES = ["low", "medium", "high", "critical"];

/**
 * @typedef {{ severity?: string[], technique?: string, tag?: string, status?: string, from?: Date, to?: Date, limit?: number, offset?: number }} IncidentFilter
 */

/** @param {IncidentFilter} f */
export async function listIncidents(f) {
  const where = [];
  /** @type {unknown[]} */
  const params = [];
  const add = (/** @type {unknown} */ v) => {
    params.push(v);
    return `$${params.length}`;
  };
  if (f.severity?.length) where.push(`i.severity = ANY(${add(f.severity)}::text[])`);
  if (f.technique) where.push(`i.techniques @> ${add(JSON.stringify([{ id: f.technique }]))}::jsonb`);
  if (f.tag) where.push(`i.tags @> ARRAY[${add(f.tag)}]::text[]`);
  if (f.status) where.push(`i.status = ${add(f.status)}`);
  if (f.from) where.push(`i.last_seen >= ${add(f.from)}`);
  if (f.to) where.push(`i.first_seen <= ${add(f.to)}`);
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = await pool.query(`SELECT COUNT(*)::int AS n FROM incidents i ${clause}`, params);
  const limit = Math.min(f.limit ?? 50, 200);
  const offset = Math.max(f.offset ?? 0, 0);
  const rows = await pool.query(
    `SELECT i.id, host(i.src_ip) AS src_ip, i.status, i.first_seen, i.last_seen, i.event_count,
            i.severity, i.severity_score, i.tags,
            (SELECT COALESCE(jsonb_agg(t->>'id'), '[]'::jsonb) FROM jsonb_array_elements(i.techniques) t) AS technique_ids,
            i.stats->'intel'->>'country' AS country,
            (SELECT COUNT(*)::int FROM proposed_actions a WHERE a.incident_id = i.id AND a.status = 'pending') AS pending_actions,
            (SELECT r.ai_generated FROM agent_reports r WHERE r.incident_id = i.id ORDER BY r.id DESC LIMIT 1) AS latest_report_ai
     FROM incidents i ${clause}
     ORDER BY i.last_seen DESC
     LIMIT ${add(limit)} OFFSET ${add(offset)}`,
    params
  );
  return { total: total.rows[0].n, limit, offset, items: rows.rows };
}

/** @param {string} id */
export async function getIncidentDetail(id) {
  const inc = await pool.query(
    `SELECT id, host(src_ip) AS src_ip, status, first_seen, last_seen, event_count, severity, severity_score,
            techniques, tags, stats, last_analyzed_at, created_at, updated_at
     FROM incidents WHERE id = $1`,
    [id]
  );
  if (!inc.rowCount) return null;
  const incident = inc.rows[0];

  const [events, reports, actions, intel] = await Promise.all([
    pool.query(
      `SELECT e.id, e.ts, e.sensor_id, e.protocol, e.event_type, host(e.src_ip) AS src_ip, e.src_port, e.session_id,
              e.username, e.password, e.auth_method, e.auth_success, e.command,
              e.http_method, e.http_path, e.user_agent, e.http_headers, e.truncated
       FROM incident_events ie JOIN events e ON e.id = ie.event_id
       WHERE ie.incident_id = $1 ORDER BY e.ts, e.id LIMIT 1000`,
      [id]
    ),
    pool.query(
      `SELECT id, source, ai_generated, model, prompt_version, report, validation_status, fallback_reason,
              tokens_in, tokens_out, latency_ms, created_at
       FROM agent_reports WHERE incident_id = $1 ORDER BY id DESC LIMIT 20`,
      [id]
    ),
    pool.query(
      `SELECT id, action_type, host(target) AS target, reason, ttl_hours, status, proposed_by, decided_by,
              decided_at, decision_reason, activated_at, expires_at, created_at
       FROM proposed_actions WHERE incident_id = $1 ORDER BY id DESC`,
      [id]
    ),
    pool.query(
      `SELECT provider, data, error, fetched_at, expires_at FROM ip_enrichment_cache WHERE ip = $1 ORDER BY provider`,
      [incident.src_ip]
    )
  ]);

  return {
    ...incident,
    techniques: (incident.techniques ?? []).map((/** @type {any} */ t) => ({ ...t, url: attackUrl(t.id) })),
    reports: reports.rows.map((r) => ({
      ...r,
      report: {
        ...r.report,
        techniques: (r.report?.techniques ?? []).map((/** @type {any} */ t) => ({ ...t, url: attackUrl(t.id) }))
      }
    })),
    actions: actions.rows,
    intel: { summary: incident.stats?.intel ?? {}, providers: intel.rows },
    events: events.rows,
    events_shown: events.rowCount,
    events_capped: (events.rowCount ?? 0) >= 1000
  };
}
