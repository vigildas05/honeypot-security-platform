// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;
const SENSOR_TOKEN = "integration-sensor-token-0123456789";

describe.skipIf(!url)("ingest pipeline (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {import("supertest").Agent} */
  let request;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.SENSOR_TOKENS = `itest-sensor:${SENSOR_TOKEN}`;
    process.env.HONEYPOT_API_TOKEN = "";
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations, MIGRATIONS_DIR } = await import("../../src/db/migrations.js");
    const { createUserIfMissing } = await import("../../src/services/userService.js");

    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");

    // Apply only 001, insert legacy rows, then apply the rest to exercise the backfill.
    const only001 = await fs.mkdtemp(path.join(os.tmpdir(), "mig-"));
    await fs.copyFile(
      path.join(MIGRATIONS_DIR, "001_initial_attacks.sql"),
      path.join(only001, "001_initial_attacks.sql")
    );
    await runMigrations(pool, { dir: only001, log: () => {} });
    await pool.query(`
      INSERT INTO attacks (ip, protocol, service, username, password, metadata) VALUES
        ('::ffff:203.0.113.50', 'SSH', 'ssh-honeypot', 'root', 'toor', '{"authMethod":"password"}'),
        ('198.51.100.9', 'HTTP', 'http-honeypot', NULL, NULL, '{}'),
        ('unknown', 'SSH', 'ssh-honeypot', 'x', 'y', '{}')`);
    await runMigrations(pool, { log: () => {} });
    // Second run must be a no-op.
    expect(await runMigrations(pool, { log: () => {} })).toEqual([]);

    await createUserIfMissing(pool, { username: "itadmin", password: "correct horse battery", role: "admin" });

    const { default: supertest } = await import("supertest");
    const { app } = await import("../../src/app.js");
    request = supertest(app);
  });

  afterAll(async () => {
    await pool?.end();
  });

  const event = (overrides = {}) => ({
    timestamp: new Date().toISOString(),
    protocol: "ssh",
    event_type: "auth_attempt",
    src_ip: "203.0.113.77",
    ssh: { username: "admin", password: "admin", auth_success: false },
    ...overrides
  });

  it("backfilled valid legacy rows and skipped invalid IPs", async () => {
    const r = await pool.query(
      "SELECT host(src_ip) AS ip, protocol, sensor_id FROM events WHERE legacy_attack_id IS NOT NULL ORDER BY id"
    );
    expect(r.rows).toEqual([
      { ip: "203.0.113.50", protocol: "ssh", sensor_id: "legacy-ssh-honeypot" },
      { ip: "198.51.100.9", protocol: "http", sensor_id: "legacy-http-honeypot" }
    ]);
  });

  it("rejects ingest without a valid token", async () => {
    await request.post("/ingest/v1/events").send(event()).expect(401);
    await request
      .post("/ingest/v1/events")
      .set("authorization", "Bearer wrong")
      .send(event())
      .expect(401);
  });

  it("accepts a batch, rejecting only the malformed entries", async () => {
    const res = await request
      .post("/ingest/v1/events")
      .set("authorization", `Bearer ${SENSOR_TOKEN}`)
      .send({ events: [event(), event({ src_ip: "not-an-ip" }), event({ ssh: { password: "a\u0000b" } })] })
      .expect(202);
    expect(res.body.accepted).toBe(2);
    expect(res.body.rejected).toEqual([{ index: 1, error: expect.stringContaining("src_ip") }]);

    const stored = await pool.query(
      "SELECT sensor_id, password FROM events WHERE src_ip = '203.0.113.77' ORDER BY id"
    );
    expect(stored.rows.map((r) => r.sensor_id)).toEqual(["itest-sensor", "itest-sensor"]);
    expect(stored.rows[1].password).toBe("a\\x00b");
  });

  it("rejects oversized batches and malformed JSON", async () => {
    await request
      .post("/ingest/v1/events")
      .set("authorization", `Bearer ${SENSOR_TOKEN}`)
      .send({ events: Array.from({ length: 101 }, () => event()) })
      .expect(413);
    await request
      .post("/ingest/v1/events")
      .set("authorization", `Bearer ${SENSOR_TOKEN}`)
      .set("content-type", "application/json")
      .send("{not json")
      .expect(400);
  });

  it("keeps the legacy POST /attack endpoint working", async () => {
    await request
      .post("/attack")
      .set("x-honeypot-token", SENSOR_TOKEN)
      .send({ ip: "198.51.100.33", protocol: "HTTP", service: "http-honeypot", method: "GET", path: "/" })
      .expect(201);
  });

  it("logs in a seeded user and serves stats", async () => {
    await request.post("/auth/login").send({ username: "itadmin", password: "nope" }).expect(401);
    await request.post("/auth/login").send({ username: "ghost", password: "nope" }).expect(401);
    const login = await request
      .post("/auth/login")
      .send({ username: "itadmin", password: "correct horse battery" })
      .expect(200);
    expect(login.body.role).toBe("admin");

    const stats = await request
      .get("/stats")
      .set("authorization", `Bearer ${login.body.token}`)
      .expect(200);
    expect(stats.body.totalAttacks).toBeGreaterThanOrEqual(5);

    const attacks = await request
      .get("/attacks?limit=2")
      .set("authorization", `Bearer ${login.body.token}`)
      .expect(200);
    expect(attacks.body).toHaveLength(2);
  });

  it("refuses JWTs signed with alg=none", async () => {
    const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
    const payload = Buffer.from('{"sub":"1","username":"x","role":"admin"}').toString("base64url");
    await request.get("/stats").set("authorization", `Bearer ${header}.${payload}.`).expect(401);
  });

  it("makes audit_log append-only", async () => {
    await pool.query("INSERT INTO audit_log (actor, action) VALUES ('test', 'test.write')");
    await expect(pool.query("DELETE FROM audit_log")).rejects.toThrow(/append-only/);
    await expect(pool.query("UPDATE audit_log SET actor = 'x'")).rejects.toThrow(/append-only/);
  });
});
