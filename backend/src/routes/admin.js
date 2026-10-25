import crypto from "node:crypto";
import express from "express";
import { requireDashboardAuth, requireRole } from "../middleware/auth.js";
import { getObservabilityMetrics, toPrometheus } from "../services/observabilityService.js";

const router = express.Router();
const metricsToken = process.env.METRICS_TOKEN ?? "";

/** @param {string} a @param {string} b */
const safeEqual = (a, b) =>
  crypto.timingSafeEqual(crypto.createHash("sha256").update(a).digest(), crypto.createHash("sha256").update(b).digest());

/**
 * Admin JWT, or (for Prometheus scrapers) `Authorization: Bearer <METRICS_TOKEN>`
 * when METRICS_TOKEN is configured.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
function requireMetricsAccess(req, res, next) {
  const header = req.headers.authorization ?? "";
  if (metricsToken.length >= 24 && header.startsWith("Bearer ") && safeEqual(header.slice(7), metricsToken)) {
    return next();
  }
  return requireDashboardAuth(req, res, () => requireRole("admin")(req, res, next));
}

router.get("/admin/metrics", requireMetricsAccess, async (req, res, next) => {
  try {
    const metrics = await getObservabilityMetrics();
    res.set("Cache-Control", "no-store");
    if (req.query.format === "prometheus") {
      return res.type("text/plain; version=0.0.4").send(toPrometheus(metrics));
    }
    return res.json(metrics);
  } catch (error) {
    return next(error);
  }
});

export default router;
