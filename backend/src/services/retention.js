// Data retention. Keeps the database inside free-tier limits (Neon: 0.5 GB)
// without touching anything still in use:
//   - closed incidents older than incidentDays are deleted, unless they have a
//     pending/approved/active action (cascades to their reports and actions)
//   - raw events older than eventDays are deleted unless they belong to an
//     open incident (closed incidents keep their counters, techniques, stats
//     and reports; only the old raw timeline goes)
//   - LLM call ledger, expired enrichment cache and old counters are trimmed
// The audit log is append-only (DB trigger) and is never deleted here.

const BATCH = 5000;

/** @param {NodeJS.ProcessEnv} raw */
export function loadRetentionConfig(raw) {
  const days = (/** @type {string | undefined} */ v, /** @type {number} */ d) => {
    const n = Number(v ?? d);
    if (!Number.isInteger(n) || n < 1) throw new Error(`Invalid retention days: ${v}`);
    return n;
  };
  return {
    eventDays: days(raw.EVENT_RETENTION_DAYS, 30),
    incidentDays: days(raw.INCIDENT_RETENTION_DAYS, 90),
    llmCallDays: days(raw.LLM_CALL_RETENTION_DAYS, 90)
  };
}

/**
 * @param {import("pg").Pool} db
 * @param {ReturnType<typeof loadRetentionConfig>} cfg
 */
export async function applyRetention(db, cfg) {
  const result = { incidents: 0, events: 0, llm_calls: 0, enrichment: 0, counters: 0 };

  const inc = await db.query(
    `DELETE FROM incidents i
     WHERE i.status = 'closed'
       AND i.last_seen < NOW() - ($1 || ' days')::interval
       AND NOT EXISTS (SELECT 1 FROM proposed_actions a
                       WHERE a.incident_id = i.id AND a.status IN ('pending', 'approved', 'active'))`,
    [String(cfg.incidentDays)]
  );
  result.incidents = inc.rowCount ?? 0;

  // Batched so a large backlog never holds long locks.
  for (;;) {
    const r = await db.query(
      `DELETE FROM events WHERE id IN (
         SELECT e.id FROM events e
         WHERE e.ts < NOW() - ($1 || ' days')::interval
           AND NOT EXISTS (SELECT 1 FROM incident_events ie JOIN incidents i ON i.id = ie.incident_id
                           WHERE ie.event_id = e.id AND i.status = 'open')
         LIMIT $2)`,
      [String(cfg.eventDays), BATCH]
    );
    result.events += r.rowCount ?? 0;
    if ((r.rowCount ?? 0) < BATCH) break;
  }

  result.llm_calls = (await db.query(
    "DELETE FROM llm_calls WHERE ts < NOW() - ($1 || ' days')::interval", [String(cfg.llmCallDays)]
  )).rowCount ?? 0;
  result.enrichment = (await db.query(
    "DELETE FROM ip_enrichment_cache WHERE expires_at < NOW() - interval '7 days'"
  )).rowCount ?? 0;
  result.counters = (await db.query(
    "DELETE FROM metric_counters WHERE day < (NOW() AT TIME ZONE 'UTC')::date - 400"
  )).rowCount ?? 0;
  await db.query("DELETE FROM provider_usage WHERE day < (NOW() AT TIME ZONE 'UTC')::date - 90");
  return result;
}
