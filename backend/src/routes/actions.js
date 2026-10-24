import express from "express";
import { z } from "zod";
import { createPolicyEngine } from "../agent/policy.js";
import { loadAgentConfig } from "../config/agent.js";
import { forViewer } from "../lib/mask.js";
import { requireDashboardAuth, requireRole } from "../middleware/auth.js";
import {
  ActionPolicyError,
  ActionStateError,
  activeBlocks,
  approveAction,
  getAction,
  listActions,
  listAudit,
  rejectAction,
  revokeAction
} from "../services/actionService.js";

const router = express.Router();
const policy = createPolicyEngine(loadAgentConfig(process.env).policy);

const STATUSES = ["pending", "approved", "rejected", "active", "expired"];
const idParam = z.string().regex(/^\d{1,18}$/);
const decisionBody = z.object({ reason: z.string().trim().min(3).max(500) }).strict();

/** @param {import("express").Request} req */
const actorOf = (req) => ({
  username: /** @type {NonNullable<typeof req.user>} */ (req.user).username,
  role: /** @type {NonNullable<typeof req.user>} */ (req.user).role,
  requestId: req.id === undefined ? undefined : String(req.id)
});

router.get("/actions", requireDashboardAuth, async (req, res, next) => {
  try {
    const status = typeof req.query.status === "string" && STATUSES.includes(req.query.status) ? req.query.status : undefined;
    const incidentId = typeof req.query.incident_id === "string" && idParam.safeParse(req.query.incident_id).success
      ? req.query.incident_id
      : undefined;
    res.json(forViewer(req, await listActions({ status, incidentId })));
  } catch (error) {
    next(error);
  }
});

router.get("/actions/:id", requireDashboardAuth, async (req, res, next) => {
  try {
    if (!idParam.safeParse(req.params.id).success) return res.status(400).json({ error: "Invalid id" });
    const action = await getAction(req.params.id);
    if (!action) return res.status(404).json({ error: "Not found" });
    return res.json(forViewer(req, action));
  } catch (error) {
    return next(error);
  }
});

/**
 * @param {(id: string, actor: ReturnType<typeof actorOf>, reason: string) => Promise<unknown>} decide
 */
const decisionRoute = (decide) =>
  /**
   * @param {import("express").Request} req
   * @param {import("express").Response} res
   * @param {import("express").NextFunction} next
   */
  async (req, res, next) => {
    try {
      if (!idParam.safeParse(req.params.id).success) return res.status(400).json({ error: "Invalid id" });
      const body = decisionBody.safeParse(req.body);
      if (!body.success) return res.status(400).json({ error: "A reason (3-500 characters) is required" });
      const updated = await decide(req.params.id, actorOf(req), body.data.reason);
      return res.json(updated);
    } catch (error) {
      if (error instanceof ActionStateError) {
        return res.status(error.message === "not_found" ? 404 : 409).json({ error: error.message === "not_found" ? "Not found" : error.message });
      }
      if (error instanceof ActionPolicyError) return res.status(409).json({ error: error.message });
      return next(error);
    }
  };

// Mutations: admin only, enforced server-side (the demo role is also refused
// by requireDashboardAuth's default-deny for non-GET methods).
router.post("/actions/:id/approve", requireDashboardAuth, requireRole("admin"),
  decisionRoute((id, actor, reason) => approveAction(id, actor, reason, policy)));
router.post("/actions/:id/reject", requireDashboardAuth, requireRole("admin"), decisionRoute(rejectAction));
router.post("/actions/:id/revoke", requireDashboardAuth, requireRole("admin"), decisionRoute(revokeAction));

router.get("/blocklist", requireDashboardAuth, async (req, res, next) => {
  try {
    res.json(forViewer(req, await activeBlocks()));
  } catch (error) {
    next(error);
  }
});

router.get("/audit", requireDashboardAuth, requireRole("admin"), async (req, res, next) => {
  try {
    const action = typeof req.query.action === "string" && /^[a-z_.]{1,64}$/.test(req.query.action) ? req.query.action : undefined;
    res.json(await listAudit({ action }));
  } catch (error) {
    next(error);
  }
});

export default router;
