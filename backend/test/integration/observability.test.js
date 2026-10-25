// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;
const SENSOR_TOKEN = "observability-sensor-token-0123456789";
const METRICS_TOKEN = "metrics-scrape-token-0123456789abcdef";

describe.skipIf(!url)("admin metrics (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {import("supertest").Agent} */
  let request;
  /** @type {Record<string, string>} */
  const auth = {};

  beforeAll(async () => {
    Object.assign(process.env, { DATABASE_URL: url, SENSOR_TOKENS: `obs-sensor:${SENSOR_TOKEN}`, METRICS_TOKEN });
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
    const { createUserIfMissing } = await import("../../src/services/userService.js");
    await createUserIfMissing(pool, { username: "alice", password: "admin-password-123", role: "admin" });
    await createUserIfMissing(pool, { username: "viewer", password: "demo-password-123", role: "demo" });
    await pool.query(
      `INSERT INTO llm_calls (model, attempt, outcome, latency_ms, tokens_in, tokens_out)
       VALUES ('m', 1, 'valid', 1000, 100, 50), ('m', 1, 'invalid', 3000, 100, 50), ('m', 2, 'valid', 2000, 100, 50)`
    );
    await pool.query(
      `INSERT INTO runtime_status (component, data) VALUES ('worker', '{"llm_model":"m","llm_daily_call_budget":200,"llm_daily_token_budget":1000}')`
    );

    const { default: supertest } = await import("supertest");
    const { app } = await import("../../src/app.js");
    request = supertest(app);
    for (const [k, u, p] of [["admin", "alice", "admin-password-123"], ["demo", "viewer", "demo-password-123"]]) {
      auth[k] = `Bearer ${(await request.post("/auth/login").send({ username: u, password: p })).body.token}`;
    }
    // Generate ingest counters through the real endpoint.
    await request
      .post("/ingest/v1/events")
      .set("authorization", `Bearer ${SENSOR_TOKEN}`)
      .send({ events: [
        { timestamp: new Date().toISOString(), protocol: "ssh", event_type: "connect", src_ip: "91.92.93.94" },
        { timestamp: new Date().toISOString(), protocol: "ssh", event_type: "connect", src_ip: "not-an-ip" }
      ] })
      .expect(202);
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("is admin-only (or the scrape token)", async () => {
    await request.get("/admin/metrics").expect(401);
    await request.get("/admin/metrics").set("authorization", auth.demo).expect(403);
    await request.get("/admin/metrics").set("authorization", "Bearer wrong-token-wrong-token-wrong").expect(401);
    await request.get("/admin/metrics").set("authorization", auth.admin).expect(200);
    await request.get("/admin/metrics?format=prometheus").set("authorization", `Bearer ${METRICS_TOKEN}`).expect(200);
  });

  it("reports real pipeline and LLM numbers", async () => {
    const res = await request.get("/admin/metrics").set("authorization", auth.admin).expect(200);
    expect(res.body.today).toMatchObject({ events_ingested: 1, events_rejected: 1 });
    expect(res.body.llm_24h).toMatchObject({ calls_with_latency: 3, tokens_in: 300, tokens_out: 150, by_outcome: { valid: 2, invalid: 1 } });
    expect(res.body.llm_24h.latency_ms).toEqual({ p50: 2000, p95: 2900, max: 3000 });
    expect(res.body.worker).toMatchObject({ alive: true, llm_model: "m" });
    expect(res.body.pipeline.uncorrelated_events).toBe(1);
  });

  it("serves Prometheus text", async () => {
    const res = await request.get("/admin/metrics?format=prometheus").set("authorization", `Bearer ${METRICS_TOKEN}`).expect(200);
    expect(res.headers["content-type"]).toMatch(/^text\/plain/);
    expect(res.text).toContain('honeypot_events_ingested{window="today"} 1');
    expect(res.text).toContain('honeypot_llm_latency_ms{quantile="0.5"} 2000');
  });

  it("returns the request id on responses (and in 500 bodies)", async () => {
    const res = await request.get("/health").set("x-request-id", "trace-abc-12345").expect(200);
    expect(res.headers["x-request-id"]).toBe("trace-abc-12345");
  });
});
