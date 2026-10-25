import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createLogger, redactUrl } from "../../src/lib/logger.js";
import { toPrometheus } from "../../src/services/observabilityService.js";

describe("redactUrl", () => {
  it.each([
    ["/edl/blocklist.txt?token=s3cr3t", "/edl/blocklist.txt?token=[REDACTED]"],
    ["/x?a=1&token=abc&b=2", "/x?a=1&token=[REDACTED]&b=2"],
    ["/x?API_KEY=zzz", "/x?API_KEY=[REDACTED]"],
    ["/incidents?severity=high", "/incidents?severity=high"]
  ])("%s", (input, expected) => {
    expect(redactUrl(input)).toBe(expected);
  });
});

describe("logger", () => {
  it("writes JSON with service + level and redacts secret fields", () => {
    /** @type {string[]} */
    const lines = [];
    const sink = new Writable({ write(chunk, _enc, cb) { lines.push(String(chunk)); cb(); } });
    const prev = process.env.LOG_LEVEL;
    process.env.LOG_LEVEL = "info";
    const log = createLogger("test-svc", sink);
    process.env.LOG_LEVEL = prev;
    log.info({ req: { headers: { authorization: "Bearer abc", cookie: "s=1" } }, cfg: { password: "p", token: "t" } }, "hello");
    const entry = JSON.parse(lines[0]);
    expect(entry).toMatchObject({ level: "info", service: "test-svc", msg: "hello" });
    expect(entry.req.headers.authorization).toBe("[REDACTED]");
    expect(entry.cfg).toEqual({ password: "[REDACTED]", token: "[REDACTED]" });
  });
});

describe("toPrometheus", () => {
  const sample = {
    generated_at: "x",
    today: { events_ingested: 5, events_rejected: 1, llm_calls: 2, llm_errors: 0, llm_validation_failures: 1, llm_tokens: 420, canary_leaks: 0, policy_violations_blocked: 3, injection_incidents: 1, actions_proposed: 1, reports_llm: 1, reports_rules: 2, incidents_touched: 4, edl_fetches: 0 },
    last_7_days: { events_ingested: 50, events_rejected: 2, llm_calls: 9, llm_errors: 1, llm_validation_failures: 2, llm_tokens: 4000, canary_leaks: 1, policy_violations_blocked: 7, injection_incidents: 2, actions_proposed: 3, reports_llm: 4, reports_rules: 5, incidents_touched: 9, edl_fetches: 3 },
    llm_24h: { calls_with_latency: 2, latency_ms: { p50: 800, p95: 1500, max: 1600 }, tokens_in: 300, tokens_out: 120, by_outcome: { valid: 2 } },
    llm_budget_today: { calls: 2, call_budget: 200, tokens: 420, token_budget: 300000 },
    worker: { alive: true, heartbeat_age_seconds: 12, llm_model: null, intel_providers: [] },
    pipeline: { events_last_hour: 7, open_incidents: 2, uncorrelated_events: 0, pending_actions: 1 },
    queues: [{ name: "analyze-incident", state: "created", count: 1 }]
  };

  it("emits well-formed gauges with labels", () => {
    const text = toPrometheus(/** @type {any} */ (sample));
    expect(text).toContain('# TYPE honeypot_policy_violations_blocked gauge');
    expect(text).toContain('honeypot_policy_violations_blocked{window="today"} 3');
    expect(text).toContain('honeypot_llm_latency_ms{quantile="0.95"} 1500');
    expect(text).toContain('honeypot_llm_budget_used_ratio{kind="calls"} 0.01');
    expect(text).toContain('honeypot_queue_jobs{queue="analyze-incident",state="created"} 1');
    for (const line of text.trim().split("\n")) {
      expect(line).toMatch(/^(# (HELP|TYPE) honeypot_\w+ .+|honeypot_\w+(\{[^}]*\})? -?[\d.e+-]+)$/);
    }
  });

  it("skips null samples instead of emitting NaN", () => {
    const text = toPrometheus(/** @type {any} */ ({ ...sample, llm_24h: { ...sample.llm_24h, latency_ms: { p50: null, p95: null, max: null } } }));
    expect(text).not.toMatch(/NaN|null/);
    expect(text).not.toContain("honeypot_llm_latency_ms{");
  });
});
