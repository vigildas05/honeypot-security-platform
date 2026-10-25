// Proposed-action lifecycle (human-in-the-loop):
//
//   pending ──approve──▶ approved ──(activation)──▶ active ──ttl/revoke──▶ expired
//      └─────reject───▶ rejected
//
// Every transition is a single conditional UPDATE (WHERE status = <expected>),
// so concurrent decisions can't both succeed, and each one is audit-logged
// in the same transaction.

import { audit } from "../agent/analyze.js";
import { pool } from "../db/pool.js";

export class ActionStateError extends Error {}
export class ActionPolicyError extends Error {}

const SELECT = `
  SELECT a.id, a.incident_id, a.report_id, a.action_type, host(a.target) AS target, a.reason, a.ttl_hours,
         a.status, a.proposed_by, a.decided_by, a.decided_at, a.decision_reason, a.activated_at,
         a.expires_at, a.created_at, i.severity AS incident_severity, i.tags AS incident_tags
  FROM proposed_actions a JOIN incidents i ON i.id = a.incident_id`;

/**
 * @param {{ status?: string, incidentId?: string, limit?: number }} [filter]
 */
export async function listActions({ status, incidentId, limit = 100 } = {}) {
  const where = [];
  /** @type {unknown[]} */
  const params = [];
  if (status) {
    params.push(status);
    where.push(`a.status = $${params.length}`);
  }
  if (incidentId) {
    params.push(incidentId);
    where.push(`a.incident_id = $${params.length}`);
  }
  params.push(Math.min(limit, 500));
  const r = await pool.query(
    `${SELECT} ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY a.created_at DESC LIMIT $${params.length}`,
    params
  );
  return r.rows;
}

/** @param {string} id */
export async function getAction(id) {
  const r = await pool.query(`${SELECT} WHERE a.id = $1`, [id]);
  return r.rows[0] ?? null;
}

/**
 * @typedef {{ username: string, role: string, requestId?: string }} Actor
 */

/**
 * Approve a pending action and activate it. Re-runs the policy check first
 * (the never-block list may have changed since the proposal was made).
 * @param {string} id
 * @param {Actor} actor
 * @param {string} reason
 * @param {{ isAllowedTarget: (ip: string) => { ok: boolean, code?: string } }} policyCheck
 */
export async function approveAction(id, actor, reason, policyCheck) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query(
      "SELECT id, action_type, host(target) AS target, ttl_hours, status FROM proposed_actions WHERE id = $1 FOR UPDATE",
      [id]
    );
    const row = current.rows[0];
    if (!row) throw new ActionStateError("not_found");
    if (row.status !== "pending") throw new ActionStateError(`action is ${row.status}, not pending`);

    if (row.target) {
      const check = policyCheck.isAllowedTarget(row.target);
      if (!check.ok) {
        await audit(client, actor.username, "policy.violation", "proposed_action", id,
          { code: check.code, stage: "approval", target: row.target }, { role: actor.role, requestId: actor.requestId });
        await client.query("COMMIT");
        throw new ActionPolicyError(`target no longer allowed by policy (${check.code})`);
      }
    }

    await client.query(
      `UPDATE proposed_actions SET status = 'approved', decided_by = $2, decided_at = NOW(), decision_reason = $3
       WHERE id = $1 AND status = 'pending'`,
      [id, actor.username, reason]
    );
    await audit(client, actor.username, "action.approved", "proposed_action", id,
      { type: row.action_type, target: row.target, ttl_hours: row.ttl_hours, reason }, { role: actor.role, requestId: actor.requestId });

    const activated = await client.query(
      `UPDATE proposed_actions SET status = 'active', activated_at = NOW(),
              expires_at = CASE WHEN ttl_hours IS NULL THEN NULL ELSE NOW() + (ttl_hours || ' hours')::interval END
       WHERE id = $1 AND status = 'approved'
       RETURNING activated_at, expires_at`,
      [id]
    );
    await audit(client, "system:lifecycle", "action.activated", "proposed_action", id,
      { expires_at: activated.rows[0].expires_at }, { requestId: actor.requestId });

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return getAction(id);
}

/**
 * @param {string} id
 * @param {Actor} actor
 * @param {string} reason
 */
export async function rejectAction(id, actor, reason) {
  return transition(id, actor, reason, {
    from: "pending",
    sql: `UPDATE proposed_actions SET status = 'rejected', decided_by = $2, decided_at = NOW(), decision_reason = $3
          WHERE id = $1 AND status = 'pending' RETURNING id`,
    auditAction: "action.rejected"
  });
}

/**
 * End an active action early.
 * @param {string} id
 * @param {Actor} actor
 * @param {string} reason
 */
export async function revokeAction(id, actor, reason) {
  return transition(id, actor, reason, {
    from: "active",
    sql: `UPDATE proposed_actions SET status = 'expired', expires_at = NOW(),
            decision_reason = COALESCE(decision_reason || ' | ', '') || 'revoked by ' || $2 || ': ' || $3
          WHERE id = $1 AND status = 'active' RETURNING id`,
    auditAction: "action.revoked"
  });
}

/**
 * @param {string} id
 * @param {Actor} actor
 * @param {string} reason
 * @param {{ from: string, sql: string, auditAction: string }} spec
 */
async function transition(id, actor, reason, { from, sql, auditAction }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(sql, [id, actor.username, reason]);
    if (!r.rowCount) {
      const cur = await client.query("SELECT status FROM proposed_actions WHERE id = $1", [id]);
      throw new ActionStateError(cur.rowCount ? `action is ${cur.rows[0].status}, not ${from}` : "not_found");
    }
    await audit(client, actor.username, auditAction, "proposed_action", id, { reason }, { role: actor.role, requestId: actor.requestId });
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return getAction(id);
}

/**
 * Expire active actions whose TTL has passed. Called by the worker.
 * @param {import("pg").Pool} [db]
 */
export async function expireActions(db = pool) {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `UPDATE proposed_actions SET status = 'expired'
       WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()
       RETURNING id, action_type, host(target) AS target`
    );
    for (const row of r.rows) {
      await audit(client, "system:lifecycle", "action.expired", "proposed_action", row.id, { type: row.action_type, target: row.target });
    }
    await client.query("COMMIT");
    return r.rowCount ?? 0;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Currently enforced blocks (approved, active, unexpired).
 */
export async function activeBlocks() {
  const r = await pool.query(
    `SELECT a.id, host(a.target) AS ip, a.incident_id, a.reason, a.ttl_hours, a.activated_at, a.expires_at,
            a.decided_by, a.proposed_by, i.severity AS incident_severity
     FROM proposed_actions a JOIN incidents i ON i.id = a.incident_id
     WHERE a.action_type = 'block_ip' AND a.status = 'active'
       AND (a.expires_at IS NULL OR a.expires_at > NOW())
     ORDER BY a.activated_at DESC`
  );
  return r.rows;
}

/**
 * @param {{ limit?: number, action?: string }} [filter]
 */
export async function listAudit({ limit = 200, action } = {}) {
  const r = await pool.query(
    `SELECT id, ts, actor, actor_role, action, target_type, target_id, details, request_id
     FROM audit_log ${action ? "WHERE action = $2" : ""} ORDER BY id DESC LIMIT $1`,
    action ? [Math.min(limit, 1000), action] : [Math.min(limit, 1000)]
  );
  return r.rows;
}
