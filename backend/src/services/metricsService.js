import { pool } from "../db/pool.js";

/**
 * Dashboard metrics over a trailing window. Counts only what is in the
 * database; nothing is estimated or extrapolated.
 * @param {{ days: number }} opts
 */
export async function getDashboardMetrics({ days }) {
  const since = `NOW() - ($1 || ' days')::interval`;
  const p = [String(days)];
  const q = (/** @type {string} */ sql, /** @type {unknown[]} */ params = p) => pool.query(sql, params).then((r) => r.rows);

  const [
    eventsPerHour, topIps, topCountries, topUsernames, topPasswords, topTechniques,
    severities, injectionIncidents, injectionRecent, counters, llmToday, llmCalls, queue, worker
  ] = await Promise.all([
    q(`SELECT h AS bucket, COALESCE(c.n, 0)::int AS count
       FROM generate_series(date_trunc('hour', NOW()) - interval '47 hours', date_trunc('hour', NOW()), interval '1 hour') h
       LEFT JOIN (SELECT date_trunc('hour', ts) AS b, COUNT(*) AS n FROM events
                  WHERE ts >= date_trunc('hour', NOW()) - interval '47 hours' GROUP BY 1) c ON c.b = h
       ORDER BY h`, []),
    q(`SELECT host(src_ip) AS ip, COUNT(*)::int AS count FROM events WHERE ts >= ${since}
       GROUP BY src_ip ORDER BY count DESC LIMIT 10`),
    q(`SELECT COALESCE(country, 'Unknown') AS country, COUNT(*)::int AS count FROM events WHERE ts >= ${since}
       GROUP BY 1 ORDER BY count DESC LIMIT 10`),
    q(`SELECT username AS value, COUNT(*)::int AS count FROM events
       WHERE ts >= ${since} AND event_type = 'auth_attempt' AND username IS NOT NULL
       GROUP BY username ORDER BY count DESC LIMIT 10`),
    q(`SELECT password AS value, COUNT(*)::int AS count FROM events
       WHERE ts >= ${since} AND password IS NOT NULL AND password <> ''
       GROUP BY password ORDER BY count DESC LIMIT 10`),
    q(`SELECT t->>'id' AS id, MAX(t->>'name') AS name, COUNT(*)::int AS incidents
       FROM incidents i, jsonb_array_elements(i.techniques) t WHERE i.last_seen >= ${since}
       GROUP BY 1 ORDER BY incidents DESC LIMIT 15`),
    q(`SELECT severity, COUNT(*)::int AS count FROM incidents WHERE last_seen >= ${since} GROUP BY severity`),
    q(`SELECT COUNT(*)::int AS count FROM incidents
       WHERE last_seen >= ${since} AND tags @> ARRAY['prompt-injection-attempt']::text[]`),
    q(`SELECT id, host(src_ip) AS src_ip, last_seen, severity FROM incidents
       WHERE tags @> ARRAY['prompt-injection-attempt']::text[] ORDER BY last_seen DESC LIMIT 10`, []),
    q(`SELECT name, SUM(value)::bigint AS value FROM metric_counters
       WHERE day >= (NOW() AT TIME ZONE 'UTC')::date - ($1::int - 1) GROUP BY name`),
    q(`SELECT calls, tokens FROM provider_usage WHERE provider = 'llm' AND day = (NOW() AT TIME ZONE 'UTC')::date`, []),
    q(`SELECT outcome, COUNT(*)::int AS count, ROUND(AVG(latency_ms))::int AS avg_latency_ms,
              COALESCE(SUM(tokens_in + tokens_out), 0)::bigint AS tokens
       FROM llm_calls WHERE ts >= ${since} GROUP BY outcome`),
    q(`SELECT
         (SELECT COUNT(*)::int FROM proposed_actions WHERE status = 'pending') AS pending_actions,
         (SELECT COUNT(*)::int FROM proposed_actions WHERE status = 'active' AND action_type = 'block_ip'
            AND (expires_at IS NULL OR expires_at > NOW())) AS active_blocks,
         (SELECT COUNT(*)::int FROM events WHERE ts >= ${since}) AS events,
         (SELECT COUNT(*)::int FROM incidents WHERE last_seen >= ${since}) AS incidents`),
    q(`SELECT data, started_at, updated_at, updated_at > NOW() - interval '3 minutes' AS alive
       FROM runtime_status WHERE component = 'worker'`, [])
  ]);
  const w = worker[0];

  const counterMap = Object.fromEntries(counters.map((c) => [c.name, Number(c.value)]));
  return {
    window_days: days,
    totals: queue[0],
    events_per_hour: eventsPerHour,
    top_source_ips: topIps,
    top_countries: topCountries,
    top_usernames: topUsernames,
    top_passwords: topPasswords,
    top_techniques: topTechniques,
    incidents_by_severity: Object.fromEntries(severities.map((s) => [s.severity, s.count])),
    injection: { incidents: injectionIncidents[0].count, recent: injectionRecent },
    agent: {
      reports_llm: counterMap["agent.reports.llm"] ?? 0,
      reports_rules: counterMap["agent.reports.rules"] ?? 0,
      llm_calls: counterMap["llm.calls"] ?? 0,
      llm_validation_failures: counterMap["llm.validation_failures"] ?? 0,
      llm_errors: counterMap["llm.calls.error"] ?? 0,
      canary_leaks: counterMap["agent.canary_leaks"] ?? 0,
      policy_violations_blocked: counterMap["policy.violations_blocked"] ?? 0,
      actions_proposed: counterMap["actions.proposed"] ?? 0,
      edl_fetches: counterMap["edl.fetches"] ?? 0,
      calls_by_outcome: llmCalls
    },
    // Published by the worker (it holds the LLM config); null if it never ran.
    worker: w ? { alive: w.alive, started_at: w.started_at, last_heartbeat: w.updated_at, ...w.data } : null,
    llm_budget_today: {
      configured: Boolean(w?.data?.llm_model),
      calls: Number(llmToday[0]?.calls ?? 0),
      call_budget: w?.data?.llm_daily_call_budget ?? null,
      tokens: Number(llmToday[0]?.tokens ?? 0),
      token_budget: w?.data?.llm_daily_token_budget ?? null
    }
  };
}
