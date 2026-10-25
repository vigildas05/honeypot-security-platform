import { getDailyUsage, reserveDailyCall } from "../lib/quota.js";
import { incrementCounters } from "../lib/metrics.js";
import { incidentSignature, runAgent } from "./core.js";
import { INJECTION_TAG } from "./injection.js";
import { PROMPT_VERSION } from "./prompt.js";

const LLM_PROVIDER_KEY = "llm";
const MAX_EVENTS_FOR_AGENT = 5000;

/**
 * Daily LLM budget backed by provider_usage (shared across processes).
 * @param {import("pg").Pool} db
 * @param {{ dailyCallBudget: number, dailyTokenBudget: number }} llm
 * @returns {import("./core.js").Budget}
 */
export function createDbBudget(db, llm) {
  return {
    async tryReserveCall() {
      const { tokens } = await getDailyUsage(db, LLM_PROVIDER_KEY);
      if (tokens >= llm.dailyTokenBudget) return false;
      return reserveDailyCall(db, LLM_PROVIDER_KEY, llm.dailyCallBudget);
    },
    async recordTokens(n) {
      if (!n) return;
      await db.query(
        `UPDATE provider_usage SET tokens = tokens + $2
         WHERE provider = $1 AND day = (NOW() AT TIME ZONE 'UTC')::date`,
        [LLM_PROVIDER_KEY, n]
      );
    }
  };
}

/**
 * Run the agent for one incident and persist everything it produced.
 * @param {import("pg").Pool} db
 * @param {string} incidentId
 * @param {{
 *   llm: import("./llmClient.js").LlmClient | null,
 *   budget: import("./core.js").Budget,
 *   policy: ReturnType<typeof import("./policy.js").createPolicyEngine>,
 *   log?: (msg: string, fields?: Record<string, unknown>) => void
 * }} deps
 */
export async function analyzeIncident(db, incidentId, { llm, budget, policy, log = () => {} }) {
  const inc = await db.query(
    `SELECT id, host(src_ip) AS src_ip, first_seen, last_seen, event_count, severity, severity_score,
            techniques, tags, stats
     FROM incidents WHERE id = $1`,
    [incidentId]
  );
  if (!inc.rowCount) return null;
  const incident = inc.rows[0];

  const events = await db.query(
    `SELECT e.protocol, e.event_type, e.ts, e.username, e.password, e.auth_success, e.auth_method,
            e.command, e.http_method, e.http_path, e.user_agent, e.http_headers, e.session_id
     FROM incident_events ie JOIN events e ON e.id = ie.event_id
     WHERE ie.incident_id = $1 ORDER BY e.ts DESC LIMIT $2`,
    [incidentId, MAX_EVENTS_FOR_AGENT]
  );

  const result = await runAgent({ incident, events: events.rows, llm, budget, policy });
  const newlyTaggedInjection = !incident.tags.includes(INJECTION_TAG) && result.tags.includes(INJECTION_TAG);
  const actor = "system:agent";

  const tokensIn = result.calls.reduce((s, c) => s + c.tokensIn, 0);
  const tokensOut = result.calls.reduce((s, c) => s + c.tokensOut, 0);
  const latency = result.calls.reduce((s, c) => s + (c.latencyMs ?? 0), 0);

  const client = await db.connect();
  let reportId;
  const created = [];
  try {
    await client.query("BEGIN");

    for (const call of result.calls) {
      await client.query(
        `INSERT INTO llm_calls (incident_id, model, attempt, outcome, detail, latency_ms, tokens_in, tokens_out)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [incidentId, call.model, call.attempt, call.outcome, call.detail, call.latencyMs, call.tokensIn, call.tokensOut]
      );
    }

    const inserted = await client.query(
      `INSERT INTO agent_reports (incident_id, source, ai_generated, model, prompt_version, report,
                                  validation_status, fallback_reason, tokens_in, tokens_out, latency_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
      [
        incidentId,
        result.source,
        result.aiGenerated,
        result.source === "llm" ? (result.calls.at(-1)?.model ?? llm?.model ?? null) : null,
        PROMPT_VERSION,
        JSON.stringify({ ...result.report, injection_signals: result.injectionFindings.map(({ field, pattern }) => ({ field, pattern })) }),
        result.validationStatus,
        result.fallbackReason,
        tokensIn || null,
        tokensOut || null,
        latency || null
      ]
    );
    reportId = inserted.rows[0].id;

    for (const action of result.actions) {
      if (action.type === "no_action") continue;
      // Don't stack duplicate proposals for something already pending or in force.
      const dup = await client.query(
        `SELECT 1 FROM proposed_actions
         WHERE action_type = $1 AND target = $2 AND status IN ('pending', 'approved', 'active') LIMIT 1`,
        [action.type, action.target]
      );
      if (dup.rowCount) continue;
      const row = await client.query(
        `INSERT INTO proposed_actions (incident_id, report_id, action_type, target, reason, ttl_hours, proposed_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [incidentId, reportId, action.type, action.target, action.reason, action.ttl_hours, result.source]
      );
      created.push(row.rows[0].id);
      await audit(client, actor, "action.proposed", "proposed_action", row.rows[0].id, {
        incident_id: incidentId, type: action.type, target: action.target, ttl_hours: action.ttl_hours, notes: action.notes, source: result.source
      });
    }

    for (const v of result.violations) {
      await audit(client, actor, "policy.violation", "incident", incidentId, { code: v.code, message: v.message, action: v.action, source: result.source });
    }
    if (result.canaryLeak) {
      await audit(client, actor, "agent.canary_leak", "incident", incidentId, { report_id: reportId });
    }
    if (newlyTaggedInjection) {
      await audit(client, actor, "agent.injection_detected", "incident", incidentId, {
        findings: result.injectionFindings.slice(0, 10).map(({ field, pattern }) => ({ field, pattern }))
      });
    }
    await audit(client, actor, "agent.report_created", "agent_report", reportId, {
      incident_id: incidentId, source: result.source, validation_status: result.validationStatus, fallback_reason: result.fallbackReason
    });

    const tags = result.tags;
    await client.query(
      `UPDATE incidents SET tags = $2, analyzed_event_count = $3, analyzed_signature = $4,
              last_analyzed_at = NOW(), updated_at = NOW()
       WHERE id = $1`,
      [incidentId, tags, incident.event_count, incidentSignature({ ...incident, tags })]
    );

    await incrementCounters(client, {
      "agent.reports": 1,
      [`agent.reports.${result.source}`]: 1,
      "llm.calls": result.calls.length,
      "llm.calls.error": result.calls.filter((c) => c.outcome === "error").length,
      "llm.validation_failures": result.calls.filter((c) => c.outcome === "invalid").length,
      "llm.tokens": tokensIn + tokensOut,
      "llm.latency_ms_total": latency,
      "agent.canary_leaks": result.canaryLeak ? 1 : 0,
      "policy.violations_blocked": result.violations.length,
      "agent.injection_incidents": newlyTaggedInjection ? 1 : 0,
      "actions.proposed": created.length
    });

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }

  log("agent report stored", {
    incidentId,
    source: result.source,
    validationStatus: result.validationStatus,
    fallbackReason: result.fallbackReason,
    proposals: created.length,
    policyViolations: result.violations.length,
    injectionFindings: result.injectionFindings.length,
    canaryLeak: result.canaryLeak,
    llmCalls: result.calls.length,
    tokens: tokensIn + tokensOut,
    latencyMs: latency
  });
  return { reportId, proposedActionIds: created, ...result };
}

/**
 * @param {import("pg").PoolClient | import("pg").Pool} db
 * @param {string} actor
 * @param {string} action
 * @param {string} targetType
 * @param {string} targetId
 * @param {Record<string, unknown>} details
 * @param {{ role?: string | null, requestId?: string | null }} [meta]
 */
export async function audit(db, actor, action, targetType, targetId, details, { role = null, requestId = null } = {}) {
  await db.query(
    `INSERT INTO audit_log (actor, actor_role, action, target_type, target_id, details, request_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [actor, role, action, targetType, String(targetId), JSON.stringify(details), requestId]
  );
}
