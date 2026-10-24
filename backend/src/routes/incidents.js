import express from "express";
import { z } from "zod";
import { forViewer } from "../lib/mask.js";
import { requireDashboardAuth } from "../middleware/auth.js";
import { SEVERITIES, getIncidentDetail, listIncidents } from "../services/incidentService.js";
import { getDashboardMetrics } from "../services/metricsService.js";

const router = express.Router();

const listQuery = z.object({
  severity: z
    .string()
    .optional()
    .transform((v) => (v ? v.split(",").filter((s) => SEVERITIES.includes(s)) : undefined)),
  technique: z.string().regex(/^T\d{4}(\.\d{3})?$/).optional(),
  tag: z.string().regex(/^[a-z0-9-]{1,40}$/).optional(),
  status: z.enum(["open", "closed"]).optional(),
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(100_000).optional()
});

router.get("/incidents", requireDashboardAuth, async (req, res, next) => {
  try {
    const q = listQuery.safeParse(req.query);
    if (!q.success) return res.status(400).json({ error: "Invalid filter" });
    const result = await listIncidents({
      ...q.data,
      from: q.data.from ? new Date(q.data.from) : undefined,
      to: q.data.to ? new Date(q.data.to) : undefined
    });
    return res.json(forViewer(req, result));
  } catch (error) {
    return next(error);
  }
});

router.get("/incidents/:id", requireDashboardAuth, async (req, res, next) => {
  try {
    if (!/^\d{1,18}$/.test(req.params.id)) return res.status(400).json({ error: "Invalid id" });
    const detail = await getIncidentDetail(req.params.id);
    if (!detail) return res.status(404).json({ error: "Not found" });
    return res.json(forViewer(req, detail));
  } catch (error) {
    return next(error);
  }
});

router.get("/metrics/dashboard", requireDashboardAuth, async (req, res, next) => {
  try {
    const days = Number(req.query.days ?? 7);
    if (!Number.isInteger(days) || days < 1 || days > 90) return res.status(400).json({ error: "days must be 1-90" });
    return res.json(forViewer(req, await getDashboardMetrics({ days })));
  } catch (error) {
    return next(error);
  }
});

export default router;
