// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;
const A = "91.92.93.94";
const B = "91.92.93.95";

describe.skipIf(!url)("correlator (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {typeof import("../../src/correlation/correlator.js")} */
  let correlator;
  /** @type {typeof import("../../src/services/eventService.js").insertEvents} */
  let insertEvents;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
    correlator = await import("../../src/correlation/correlator.js");
    ({ insertEvents } = await import("../../src/services/eventService.js"));
  });

  beforeEach(async () => {
    await pool.query("TRUNCATE events, incidents, incident_events, ip_enrichment_cache RESTART IDENTITY CASCADE");
  });

  afterAll(async () => {
    await pool?.end();
  });

  const minutesAgo = (/** @type {number} */ m) => new Date(Date.now() - m * 60_000);

  /** @param {string} ip @param {Date} ts @param {Partial<Record<string, any>>} [extra] @returns {any} */
  const ev = (ip, ts, extra = {}) => ({
    ts,
    sensor_id: "t",
    protocol: "ssh",
    event_type: "auth_attempt",
    src_ip: ip,
    src_port: null,
    session_id: null,
    username: "root",
    password: "x",
    auth_method: "password",
    auth_success: false,
    command: null,
    http_method: null,
    http_path: null,
    user_agent: null,
    http_headers: {},
    raw: null,
    truncated: false,
    ...extra
  });

  const run = () => correlator.correlateNewEvents(pool, { windowMinutes: 30 });

  it("groups by src_ip and splits on inactivity gaps", async () => {
    await insertEvents([
      ev(A, minutesAgo(120)),
      ev(A, minutesAgo(110)), // 10 min gap: same incident
      ev(A, minutesAgo(50)), // 60 min gap: new incident
      ev(B, minutesAgo(49))
    ]);
    const touched = await run();
    expect(touched).toHaveLength(3);
    expect(touched.every((t) => t.created)).toBe(true);

    const r = await pool.query(
      "SELECT host(src_ip) ip, event_count FROM incidents ORDER BY first_seen"
    );
    expect(r.rows).toEqual([
      { ip: A, event_count: 2 },
      { ip: A, event_count: 1 },
      { ip: B, event_count: 1 }
    ]);
  });

  it("is idempotent and extends open incidents with new events", async () => {
    await insertEvents([ev(A, minutesAgo(5))]);
    await run();
    expect(await run()).toEqual([]); // nothing new

    await insertEvents(Array.from({ length: 6 }, (_, i) => ev(A, minutesAgo(4), { password: `p${i}` })));
    const touched = await run();
    expect(touched).toHaveLength(1);
    expect(touched[0]).toMatchObject({ created: false, event_count: 7 });

    const inc = await pool.query("SELECT techniques, tags, severity, stats FROM incidents");
    expect(inc.rowCount).toBe(1);
    expect(inc.rows[0].techniques.map((/** @type {any} */ t) => t.id)).toContain("T1110");
    expect(inc.rows[0].tags).toContain("brute-force");
    expect(inc.rows[0].stats.features.failed_logins).toBe(7);
  });

  it("uses cached threat intel when scoring", async () => {
    await pool.query(
      `INSERT INTO ip_enrichment_cache (ip, provider, data, expires_at)
       VALUES ($1, 'abuseipdb', '{"found":true,"abuse_confidence":100}', NOW() + interval '1 day')`,
      [A]
    );
    await insertEvents([ev(A, minutesAgo(1))]);
    await run();
    const inc = await pool.query("SELECT severity_score, stats FROM incidents");
    expect(inc.rows[0].severity_score).toBe(10);
    expect(inc.rows[0].stats.intel.abuse_confidence).toBe(100);
  });

  it("preserves non-rule tags across rescoring", async () => {
    await insertEvents([ev(A, minutesAgo(2))]);
    const [t] = await run();
    await pool.query("UPDATE incidents SET tags = array_append(tags, 'prompt-injection-attempt') WHERE id = $1", [t.id]);
    await insertEvents([ev(A, minutesAgo(1))]);
    await run();
    const inc = await pool.query("SELECT tags FROM incidents WHERE id = $1", [t.id]);
    expect(inc.rows[0].tags).toContain("prompt-injection-attempt");
  });

  it("closes idle incidents", async () => {
    await insertEvents([ev(A, minutesAgo(90)), ev(B, minutesAgo(1))]);
    await run();
    expect(await correlator.closeIdleIncidents(pool, 30)).toBe(1);
    const r = await pool.query("SELECT host(src_ip) ip, status FROM incidents ORDER BY ip");
    expect(r.rows).toEqual([{ ip: A, status: "closed" }, { ip: B, status: "open" }]);
  });
});
