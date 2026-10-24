// Background worker: correlation loop + pg-boss queues for enrichment and the
// SOC agent. Holds DB credentials and (optional) LLM / threat-intel keys; the
// sensors never see any of these.
import http from "node:http";
import { PgBoss } from "pg-boss";
import { analyzeIncident, createDbBudget } from "./agent/analyze.js";
import { incidentSignature, isSignificantUpdate } from "./agent/core.js";
import { createOpenAICompatibleClient } from "./agent/llmClient.js";
import { createPolicyEngine } from "./agent/policy.js";
import { llmConfigured, loadAgentConfig } from "./config/agent.js";
import { loadEnrichmentConfig } from "./config/enrichment.js";
import { env } from "./config/env.js";
import { closeIdleIncidents, correlateNewEvents, rescoreIncident } from "./correlation/correlator.js";
import { pool } from "./db/pool.js";
import { createEnrichmentService } from "./enrichment/service.js";
import { incrementCounters } from "./lib/metrics.js";

const Q_ENRICH = "enrich-ip";
const Q_ANALYZE = "analyze-incident";
const Q_EXPIRE = "expire-actions";
const CORRELATOR_LOCK = 727275;

const agentConfig = loadAgentConfig(process.env);
const policy = createPolicyEngine(agentConfig.policy); // throws on a bad NEVER_BLOCK_IPS entry
const llm = llmConfigured(agentConfig) ? createOpenAICompatibleClient(agentConfig.llm) : null;
const budget = createDbBudget(pool, agentConfig.llm);
const enrichment = await createEnrichmentService({ db: pool, config: loadEnrichmentConfig(process.env) });

const boss = new PgBoss({ connectionString: env.databaseUrl, schema: "pgboss", application_name: "honeypot-worker" });
boss.on("error", (error) => console.error("pg-boss error:", error.message));

/**
 * Queue analysis if the incident changed significantly since the last report.
 * stately + singletonKey => at most one queued job per incident; later updates
 * inside the debounce window fold into it.
 * @param {string} incidentId
 */
async function maybeScheduleAnalysis(incidentId) {
  const r = await pool.query(
    `SELECT id, event_count, analyzed_event_count, analyzed_signature, last_analyzed_at, severity, techniques, tags
     FROM incidents WHERE id = $1`,
    [incidentId]
  );
  const inc = r.rows[0];
  if (!inc || !isSignificantUpdate(inc, incidentSignature(inc), agentConfig.reanalyzeGrowthFactor)) return;
  await boss.send(Q_ANALYZE, { incidentId: String(incidentId) }, {
    singletonKey: `incident:${incidentId}`,
    startAfter: agentConfig.debounceSeconds
  });
}

let correlating = false;
/** @type {import("pg").PoolClient | null} */
let lockClient = null;

async function correlateTick() {
  if (correlating) return;
  correlating = true;
  try {
    // Only one worker instance correlates at a time (session-level lock).
    if (!lockClient) {
      const client = await pool.connect();
      const got = await client.query("SELECT pg_try_advisory_lock($1) AS ok", [CORRELATOR_LOCK]);
      if (got.rows[0].ok) lockClient = client;
      else {
        client.release();
        return;
      }
    }
    let touched;
    do {
      touched = await correlateNewEvents(pool, { windowMinutes: agentConfig.incidentWindowMinutes });
      for (const t of touched) {
        if (t.created) await boss.send(Q_ENRICH, { ip: t.src_ip }, { singletonKey: `ip:${t.src_ip}` });
        await maybeScheduleAnalysis(t.id);
      }
      if (touched.length) await incrementCounters(pool, { "correlation.incidents_touched": touched.length });
    } while (touched.length > 0 && touched.length >= 50);
    await closeIdleIncidents(pool, agentConfig.incidentWindowMinutes);
  } catch (error) {
    console.error("correlation tick failed:", /** @type {Error} */ (error).message);
    if (lockClient) {
      lockClient.release(true);
      lockClient = null;
    }
  } finally {
    correlating = false;
  }
}

await boss.start();
await boss.createQueue(Q_ENRICH, { policy: "stately", retryLimit: 2, retryDelay: 60 });
await boss.createQueue(Q_ANALYZE, { policy: "stately", retryLimit: 2, retryDelay: 120 });
await boss.createQueue(Q_EXPIRE, { policy: "singleton" });

await boss.work(Q_ENRICH, async (/** @type {any[]} */ [job]) => {
  const ip = String(job.data.ip);
  const result = await enrichment.enrich(ip);
  if (result.summary.country) {
    await pool.query("UPDATE events SET country = $1 WHERE src_ip = $2 AND country IS NULL", [result.summary.country, ip]);
  }
  // New intel can change severity, so rescore this IP's open incidents.
  const open = await pool.query("SELECT id FROM incidents WHERE src_ip = $1 AND status = 'open'", [ip]);
  for (const row of open.rows) {
    await rescoreIncident(pool, row.id, { windowMinutes: agentConfig.incidentWindowMinutes });
    await maybeScheduleAnalysis(row.id);
  }
});

await boss.work(Q_ANALYZE, async (/** @type {any[]} */ [job]) => {
  await analyzeIncident(pool, String(job.data.incidentId), { llm, budget, policy });
});

await boss.work(Q_EXPIRE, async () => {
  const r = await pool.query(
    `UPDATE proposed_actions SET status = 'expired'
     WHERE status = 'active' AND expires_at <= NOW() RETURNING id`
  );
  if (r.rowCount) console.log(`expired ${r.rowCount} block(s)`);
});
await boss.schedule(Q_EXPIRE, "*/5 * * * *");

const interval = setInterval(correlateTick, agentConfig.correlateIntervalSeconds * 1000);
void correlateTick();

console.log(
  `worker started: llm=${llm ? `${llm.model} (${agentConfig.llm.baseUrl})` : "disabled (rule-only reports)"}` +
    ` intel=[${enrichment.enabledProviders.join(", ") || "none"}] window=${agentConfig.incidentWindowMinutes}m` +
    ` debounce=${agentConfig.debounceSeconds}s`
);

// Optional liveness endpoint for platforms that want one (bind to localhost by default).
const healthPort = Number(process.env.WORKER_HEALTH_PORT ?? 0);
const healthServer = healthPort
  ? http
      .createServer((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end('{"status":"ok","service":"honeypot-worker"}');
      })
      .listen(healthPort, process.env.WORKER_HEALTH_HOST ?? "127.0.0.1")
  : null;

async function shutdown() {
  clearInterval(interval);
  healthServer?.close();
  await boss.stop({ graceful: true, timeout: 20_000 }).catch(() => {});
  lockClient?.release();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
