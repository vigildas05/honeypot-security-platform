import { pool } from "../db/pool.js";

/**
 * Pipeline + agent health metrics. Everything is read from Postgres (shared
 * by the API and worker processes); nothing is estimated.
 */
export async function getObservabilityMetrics() {
  const q = (/** @type {string} */ sql, /** @type {unknown[]} */ params = []) => pool.query(sql, params).then((r) => r.rows);

  const [today, week, latency, outcomes, budgetUsage, worker, pipeline] = await Promise.all([
    q(`SELECT name, value::bigint AS value FROM metric_counters WHERE day = (NOW() AT TIME ZONE 'UTC')::date`),
    q(`SELECT name, SUM(value)::bigint AS value FROM metric_counters
       WHERE day > (NOW() AT TIME ZONE 'UTC')::date - 7 GROUP BY name`),
    q(`SELECT COUNT(*)::int AS calls,
              percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
              MAX(latency_ms) AS max,
              COALESCE(SUM(tokens_in), 0)::bigint AS tokens_in,
              COALESCE(SUM(tokens_out), 0)::bigint AS tokens_out
       FROM llm_calls WHERE ts > NOW() - interval '24 hours' AND latency_ms IS NOT NULL`),
    q(`SELECT outcome, COUNT(*)::int AS count FROM llm_calls WHERE ts > NOW() - interval '24 hours' GROUP BY outcome`),
    q(`SELECT calls, tokens FROM provider_usage WHERE provider = 'llm' AND day = (NOW() AT TIME ZONE 'UTC')::date`),
    q(`SELECT data, EXTRACT(EPOCH FROM NOW() - updated_at)::int AS heartbeat_age_seconds FROM runtime_status WHERE component = 'worker'`),
    q(`SELECT
         (SELECT COUNT(*)::int FROM events WHERE received_at > NOW() - interval '1 hour') AS events_last_hour,
         (SELECT COUNT(*)::int FROM incidents WHERE status = 'open') AS open_incidents,
         (SELECT COUNT(*)::int FROM events e WHERE NOT EXISTS (SELECT 1 FROM incident_events ie WHERE ie.event_id = e.id)) AS uncorrelated_events,
         (SELECT COUNT(*)::int FROM proposed_actions WHERE status = 'pending') AS pending_actions`)
  ]);

  /** @type {{ name: string, state: string, count: number }[]} */
  let queues = [];
  try {
    queues = await q(`SELECT name, state::text AS state, COUNT(*)::int AS count FROM pgboss.job
                      WHERE state IN ('created', 'retry', 'active', 'failed') AND name NOT LIKE '\\_\\_pgboss%'
                      GROUP BY 1, 2 ORDER BY 1, 2`);
  } catch {
    // pg-boss schema not created yet (worker never started).
  }

  const toMap = (/** @type {{ name: string, value: string | number }[]} */ rows) =>
    Object.fromEntries(rows.map((r) => [r.name, Number(r.value)]));
  const t = toMap(today);
  const w = toMap(week);
  const pick = (/** @type {Record<string, number>} */ m) => ({
    events_ingested: m["ingest.accepted"] ?? 0,
    events_rejected: m["ingest.rejected"] ?? 0,
    incidents_touched: m["correlation.incidents_touched"] ?? 0,
    reports_llm: m["agent.reports.llm"] ?? 0,
    reports_rules: m["agent.reports.rules"] ?? 0,
    llm_calls: m["llm.calls"] ?? 0,
    llm_errors: m["llm.calls.error"] ?? 0,
    llm_validation_failures: m["llm.validation_failures"] ?? 0,
    llm_tokens: m["llm.tokens"] ?? 0,
    canary_leaks: m["agent.canary_leaks"] ?? 0,
    policy_violations_blocked: m["policy.violations_blocked"] ?? 0,
    injection_incidents: m["agent.injection_incidents"] ?? 0,
    actions_proposed: m["actions.proposed"] ?? 0,
    edl_fetches: m["edl.fetches"] ?? 0
  });
  const l = latency[0] ?? {};
  const wk = worker[0];

  return {
    generated_at: new Date().toISOString(),
    today: pick(t),
    last_7_days: pick(w),
    llm_24h: {
      calls_with_latency: l.calls ?? 0,
      latency_ms: {
        p50: l.p50 === null || l.p50 === undefined ? null : Math.round(Number(l.p50)),
        p95: l.p95 === null || l.p95 === undefined ? null : Math.round(Number(l.p95)),
        max: l.max ?? null
      },
      tokens_in: Number(l.tokens_in ?? 0),
      tokens_out: Number(l.tokens_out ?? 0),
      by_outcome: Object.fromEntries(outcomes.map((o) => [o.outcome, o.count]))
    },
    llm_budget_today: {
      calls: Number(budgetUsage[0]?.calls ?? 0),
      call_budget: wk?.data?.llm_daily_call_budget ?? null,
      tokens: Number(budgetUsage[0]?.tokens ?? 0),
      token_budget: wk?.data?.llm_daily_token_budget ?? null
    },
    worker: wk
      ? { alive: wk.heartbeat_age_seconds < 180, heartbeat_age_seconds: wk.heartbeat_age_seconds, llm_model: wk.data?.llm_model ?? null, intel_providers: wk.data?.intel_providers ?? [] }
      : null,
    pipeline: pipeline[0],
    queues
  };
}

/**
 * Prometheus text exposition (all gauges: the daily counters reset at UTC midnight).
 * @param {Awaited<ReturnType<typeof getObservabilityMetrics>>} m
 */
export function toPrometheus(m) {
  /** @type {string[]} */
  const lines = [];
  /** @param {string} name @param {string} help @param {[Record<string, string>, number | null | undefined][]} samples */
  const gauge = (name, help, samples) => {
    lines.push(`# HELP honeypot_${name} ${help}`, `# TYPE honeypot_${name} gauge`);
    for (const [labels, value] of samples) {
      if (value === null || value === undefined || Number.isNaN(value)) continue;
      const l = Object.entries(labels).map(([k, v]) => `${k}="${String(v).replace(/["\\\n]/g, "_")}"`).join(",");
      lines.push(`honeypot_${name}${l ? `{${l}}` : ""} ${value}`);
    }
  };
  for (const [key, help] of /** @type {[keyof ReturnType<typeof Object>, string][]} */ ([
    ["events_ingested", "Events accepted at ingest"],
    ["events_rejected", "Events rejected by validation at ingest"],
    ["llm_calls", "LLM calls (including retries and failures)"],
    ["llm_errors", "LLM calls that errored"],
    ["llm_validation_failures", "LLM replies rejected by schema/ATT&CK validation"],
    ["llm_tokens", "LLM tokens used"],
    ["canary_leaks", "LLM replies rejected for leaking the prompt canary"],
    ["policy_violations_blocked", "Proposed actions rejected by the policy engine"],
    ["injection_incidents", "Incidents newly tagged prompt-injection-attempt"],
    ["actions_proposed", "Response actions proposed for human approval"],
    ["reports_llm", "AI-generated reports stored"],
    ["reports_rules", "Rule-based reports stored"]
  ])) {
    gauge(String(key), help, [
      [{ window: "today" }, /** @type {any} */ (m.today)[key]],
      [{ window: "7d" }, /** @type {any} */ (m.last_7_days)[key]]
    ]);
  }
  gauge("llm_latency_ms", "LLM call latency over the last 24h", [
    [{ quantile: "0.5" }, m.llm_24h.latency_ms.p50],
    [{ quantile: "0.95" }, m.llm_24h.latency_ms.p95],
    [{ quantile: "1" }, m.llm_24h.latency_ms.max]
  ]);
  gauge("llm_budget_used_ratio", "Share of today's LLM budget used", [
    [{ kind: "calls" }, m.llm_budget_today.call_budget ? m.llm_budget_today.calls / m.llm_budget_today.call_budget : null],
    [{ kind: "tokens" }, m.llm_budget_today.token_budget ? m.llm_budget_today.tokens / m.llm_budget_today.token_budget : null]
  ]);
  gauge("worker_heartbeat_age_seconds", "Seconds since the worker's last heartbeat", [[{}, m.worker?.heartbeat_age_seconds]]);
  gauge("events_last_hour", "Events received in the last hour", [[{}, m.pipeline.events_last_hour]]);
  gauge("uncorrelated_events", "Events not yet attached to an incident", [[{}, m.pipeline.uncorrelated_events]]);
  gauge("open_incidents", "Open incidents", [[{}, m.pipeline.open_incidents]]);
  gauge("pending_actions", "Proposed actions awaiting approval", [[{}, m.pipeline.pending_actions]]);
  gauge("queue_jobs", "pg-boss jobs by queue and state", m.queues.map((x) => [{ queue: x.name, state: x.state }, x.count]));
  return `${lines.join("\n")}\n`;
}
