// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;
const ATTACKER = "91.92.93.94";
const LATER_PROTECTED = "91.92.93.250"; // proposed before it was added to NEVER_BLOCK_IPS
const EDL_TOKEN = "edl-token-0123456789abcdef0123";
const basic = (/** @type {string} */ u, /** @type {string} */ p) => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

describe.skipIf(!url)("approvals, roles and EDL (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {import("supertest").Agent} */
  let request;
  /** @type {string} */
  let adminToken;
  /** @type {string} */
  let demoToken;
  /** @type {typeof import("../../src/services/actionService.js")} */
  let actions;

  beforeAll(async () => {
    Object.assign(process.env, {
      DATABASE_URL: url,
      NEVER_BLOCK_IPS: LATER_PROTECTED,
      EDL_AUTH_MODE: "both",
      EDL_TOKEN,
      EDL_BASIC_USER: "firewall",
      EDL_BASIC_PASSWORD: "edl-basic-password-123"
    });
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
    const { createUserIfMissing } = await import("../../src/services/userService.js");
    await createUserIfMissing(pool, { username: "alice", password: "admin-password-123", role: "admin" });
    await createUserIfMissing(pool, { username: "viewer", password: "demo-password-123", role: "demo" });
    actions = await import("../../src/services/actionService.js");

    const { default: supertest } = await import("supertest");
    const { app } = await import("../../src/app.js");
    request = supertest(app);
    adminToken = (await request.post("/auth/login").send({ username: "alice", password: "admin-password-123" })).body.token;
    demoToken = (await request.post("/auth/login").send({ username: "viewer", password: "demo-password-123" })).body.token;
  });

  /** @type {Record<string, string>} */
  let ids = {};
  beforeEach(async () => {
    await pool.query("TRUNCATE incidents, proposed_actions RESTART IDENTITY CASCADE");
    const inc = await pool.query(
      `INSERT INTO incidents (src_ip, first_seen, last_seen, severity) VALUES ($1, NOW(), NOW(), 'critical') RETURNING id`,
      [ATTACKER]
    );
    const add = async (/** @type {string} */ target, /** @type {number} */ ttl) =>
      (await pool.query(
        `INSERT INTO proposed_actions (incident_id, action_type, target, reason, ttl_hours, proposed_by)
         VALUES ($1, 'block_ip', $2, 'test', $3, 'rules') RETURNING id`,
        [inc.rows[0].id, target, ttl]
      )).rows[0].id;
    ids = { attacker: await add(ATTACKER, 24), stale: await add(LATER_PROTECTED, 24) };
  });

  afterAll(async () => {
    await pool?.end();
  });

  const as = (/** @type {string} */ token) => ({ authorization: `Bearer ${token}` });
  const approve = (/** @type {string} */ id, token = adminToken, reason = "confirmed brute force") =>
    request.post(`/actions/${id}/approve`).set(as(token)).send({ reason });

  describe("roles", () => {
    it("demo users cannot approve, reject or revoke", async () => {
      await approve(ids.attacker, demoToken).expect(403);
      await request.post(`/actions/${ids.attacker}/reject`).set(as(demoToken)).send({ reason: "nope" }).expect(403);
      await request.post(`/actions/${ids.attacker}/revoke`).set(as(demoToken)).send({ reason: "nope" }).expect(403);
      expect((await actions.getAction(ids.attacker)).status).toBe("pending");
    });

    it("demo users are refused on ANY mutating method, even unknown routes", async () => {
      await request.post("/anything").set(as(demoToken)).send({}).expect(403);
      await request.delete(`/actions/${ids.attacker}`).set(as(demoToken)).expect(403);
    });

    it("demo users see masked IPs, admins see full IPs", async () => {
      const demo = await request.get("/actions").set(as(demoToken)).expect(200);
      expect(demo.body.map((/** @type {any} */ a) => a.target)).toEqual(["91.92.93.x", "91.92.93.x"]);
      expect(JSON.stringify(demo.body)).not.toContain(ATTACKER);
      const admin = await request.get("/actions").set(as(adminToken)).expect(200);
      expect(admin.body.map((/** @type {any} */ a) => a.target)).toContain(ATTACKER);
    });

    it("the audit log is admin-only", async () => {
      await request.get("/audit").set(as(demoToken)).expect(403);
      await request.get("/audit").set(as(adminToken)).expect(200);
    });

    it("unauthenticated requests are refused", async () => {
      await request.post(`/actions/${ids.attacker}/approve`).send({ reason: "x x x" }).expect(401);
    });
  });

  describe("lifecycle", () => {
    it("requires a reason", async () => {
      await approve(ids.attacker, adminToken, "").expect(400);
      await request.post(`/actions/${ids.attacker}/approve`).set(as(adminToken)).send({}).expect(400);
    });

    it("approve activates with an expiry, and audits who/when/what/why", async () => {
      const res = await approve(ids.attacker).set("x-request-id", "req-approve-0001").expect(200);
      expect(res.body).toMatchObject({ status: "active", decided_by: "alice", decision_reason: "confirmed brute force" });
      const hours = (Date.parse(res.body.expires_at) - Date.parse(res.body.activated_at)) / 3600_000;
      expect(Math.round(hours)).toBe(24);

      const audit = await pool.query(
        "SELECT actor, actor_role, action, details, request_id FROM audit_log WHERE target_id = $1 ORDER BY id",
        [ids.attacker]
      );
      expect(audit.rows.map((r) => r.action)).toEqual(["action.approved", "action.activated"]);
      expect(audit.rows[0]).toMatchObject({ actor: "alice", actor_role: "admin", request_id: "req-approve-0001" });
      expect(audit.rows[0].details).toMatchObject({ target: ATTACKER, reason: "confirmed brute force" });
    });

    it("cannot approve twice, or approve after rejecting", async () => {
      await approve(ids.attacker).expect(200);
      await approve(ids.attacker).expect(409);
      await request.post(`/actions/${ids.stale}/reject`).set(as(adminToken)).send({ reason: "false positive" }).expect(200);
      await approve(ids.stale).expect(409);
    });

    it("re-checks policy at approval time", async () => {
      const res = await approve(ids.stale).expect(409);
      expect(res.body.error).toMatch(/target_never_block/);
      expect((await actions.getAction(ids.stale)).status).toBe("pending");
      const v = await pool.query("SELECT details FROM audit_log WHERE action = 'policy.violation' AND target_id = $1", [ids.stale]);
      expect(v.rows[0].details).toMatchObject({ stage: "approval", code: "target_never_block" });
    });

    it("concurrent approvals: exactly one wins", async () => {
      const results = await Promise.all([approve(ids.attacker), approve(ids.attacker), approve(ids.attacker)]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 409, 409]);
    });

    it("unknown ids are 404, malformed ids are 400", async () => {
      await approve("999999").expect(404);
      await approve("1;DROP TABLE users").expect(400);
    });
  });

  describe("EDL /edl/blocklist.txt", () => {
    const edl = () => request.get("/edl/blocklist.txt");

    it("requires credentials", async () => {
      await edl().expect(401);
      await request.get("/edl/blocklist.txt?token=wrong").expect(401);
      await edl().set("authorization", basic("firewall", "wrong")).expect(401);
      await edl().set("authorization", `Bearer ${adminToken}`).expect(401); // dashboard JWTs don't work here
    });

    it("lists only approved + active blocks, one IP per line", async () => {
      const empty = await request.get(`/edl/blocklist.txt?token=${EDL_TOKEN}`).expect(200);
      expect(empty.text).toBe("");
      await approve(ids.attacker).expect(200);

      const byToken = await request.get(`/edl/blocklist.txt?token=${EDL_TOKEN}`).expect(200);
      expect(byToken.headers["content-type"]).toMatch(/^text\/plain/);
      expect(byToken.headers["cache-control"]).toBe("no-store");
      expect(byToken.text).toBe(`${ATTACKER}\n`);

      const byBasic = await edl().set("authorization", basic("firewall", "edl-basic-password-123")).expect(200);
      expect(byBasic.text).toBe(`${ATTACKER}\n`);
    });

    it("drops expired and revoked blocks", async () => {
      await approve(ids.attacker).expect(200);
      await pool.query("UPDATE proposed_actions SET expires_at = NOW() - interval '1 minute' WHERE id = $1", [ids.attacker]);
      expect((await request.get(`/edl/blocklist.txt?token=${EDL_TOKEN}`)).text).toBe("");
      expect(await actions.expireActions(pool)).toBe(1);
      expect((await actions.getAction(ids.attacker)).status).toBe("expired");

      await pool.query("UPDATE proposed_actions SET status = 'pending', expires_at = NULL WHERE id = $1", [ids.attacker]);
      await approve(ids.attacker).expect(200);
      await request.post(`/actions/${ids.attacker}/revoke`).set(as(adminToken)).send({ reason: "customer IP" }).expect(200);
      expect((await request.get(`/edl/blocklist.txt?token=${EDL_TOKEN}`)).text).toBe("");
    });

    it("never publishes an address the policy refuses, even if the DB says active", async () => {
      // Simulate a row that bypassed the API (or a never-block list that changed later).
      await pool.query("UPDATE proposed_actions SET status = 'active', activated_at = NOW() WHERE id = $1", [ids.stale]);
      await pool.query(
        `INSERT INTO proposed_actions (incident_id, action_type, target, reason, ttl_hours, proposed_by, status, activated_at)
         SELECT incident_id, 'block_ip', '10.0.0.1', 'x', 1, 'rules', 'active', NOW() FROM proposed_actions LIMIT 1`
      );
      expect((await request.get(`/edl/blocklist.txt?token=${EDL_TOKEN}`)).text).toBe("");
    });
  });
});
