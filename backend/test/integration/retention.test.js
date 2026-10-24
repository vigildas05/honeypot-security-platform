// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)("data retention (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
  });

  afterAll(async () => {
    await pool?.end();
  });

  /** @param {string} ip @param {number} daysAgo */
  const event = async (ip, daysAgo) =>
    (await pool.query(
      `INSERT INTO events (ts, sensor_id, protocol, event_type, src_ip) VALUES (NOW() - ($2 || ' days')::interval, 't', 'ssh', 'connect', $1) RETURNING id`,
      [ip, String(daysAgo)]
    )).rows[0].id;

  /** @param {string} ip @param {string} status @param {number} daysAgo @param {string[]} eventIds */
  const incident = async (ip, status, daysAgo, eventIds) => {
    const id = (await pool.query(
      `INSERT INTO incidents (src_ip, status, first_seen, last_seen) VALUES ($1, $2, NOW() - ($3 || ' days')::interval, NOW() - ($3 || ' days')::interval) RETURNING id`,
      [ip, status, String(daysAgo)]
    )).rows[0].id;
    for (const e of eventIds) await pool.query("INSERT INTO incident_events VALUES ($1, $2)", [id, e]);
    return id;
  };

  it("deletes only data that is old and no longer in use", async () => {
    const oldClosed = await incident("91.92.93.1", "closed", 120, [await event("91.92.93.1", 120)]);
    const oldClosedWithBlock = await incident("91.92.93.2", "closed", 120, [await event("91.92.93.2", 120)]);
    await pool.query(
      `INSERT INTO proposed_actions (incident_id, action_type, target, reason, ttl_hours, proposed_by, status)
       VALUES ($1, 'block_ip', '91.92.93.2', 'x', 24, 'rules', 'active')`,
      [oldClosedWithBlock]
    );
    const recentClosed = await incident("91.92.93.3", "closed", 45, [await event("91.92.93.3", 45)]);
    const longOpenEvent = await event("91.92.93.4", 40);
    const open = await incident("91.92.93.4", "open", 0, [longOpenEvent]);
    const freshEvent = await event("91.92.93.5", 1);
    await pool.query("INSERT INTO audit_log (actor, action) VALUES ('t', 'keep.me')");

    const { applyRetention, loadRetentionConfig } = await import("../../src/services/retention.js");
    const r = await applyRetention(pool, loadRetentionConfig({}));

    const incidents = (await pool.query("SELECT id FROM incidents ORDER BY id")).rows.map((x) => x.id);
    expect(incidents).toEqual([oldClosedWithBlock, recentClosed, open]);
    expect(incidents).not.toContain(oldClosed);

    const events = (await pool.query("SELECT id FROM events ORDER BY id")).rows.map((x) => x.id);
    expect(events).toContain(longOpenEvent); // belongs to an open incident
    expect(events).toContain(freshEvent);
    expect(r.incidents).toBe(1);
    expect(r.events).toBeGreaterThanOrEqual(2); // old closed + recent-closed's 45-day-old event

    // The recent closed incident keeps its row (and stats) even though its raw event aged out.
    expect((await pool.query("SELECT 1 FROM incidents WHERE id = $1", [recentClosed])).rowCount).toBe(1);
    expect((await pool.query("SELECT 1 FROM audit_log WHERE action = 'keep.me'")).rowCount).toBe(1);
  });

  it("rejects nonsense config", async () => {
    const { loadRetentionConfig } = await import("../../src/services/retention.js");
    expect(() => loadRetentionConfig({ EVENT_RETENTION_DAYS: "0" })).toThrow();
    expect(() => loadRetentionConfig({ INCIDENT_RETENTION_DAYS: "abc" })).toThrow();
  });
});
