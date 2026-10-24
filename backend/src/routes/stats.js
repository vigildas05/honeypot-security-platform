import express from "express";
import { forViewer } from "../lib/mask.js";
import { requireDashboardAuth } from "../middleware/auth.js";
import { getStats } from "../services/attackService.js";

const router = express.Router();

router.get("/stats", requireDashboardAuth, async (req, res, next) => {
  try {
    return res.json(forViewer(req, await getStats()));
  } catch (error) {
    return next(error);
  }
});

router.get("/top-ip", requireDashboardAuth, async (req, res, next) => {
  try {
    const stats = await getStats();
    return res.json(forViewer(req, stats.topIps));
  } catch (error) {
    return next(error);
  }
});

router.get("/top-passwords", requireDashboardAuth, async (_req, res, next) => {
  try {
    const stats = await getStats();
    return res.json(stats.topPasswords);
  } catch (error) {
    return next(error);
  }
});

router.get("/countries", requireDashboardAuth, async (_req, res, next) => {
  try {
    const stats = await getStats();
    return res.json(stats.countries);
  } catch (error) {
    return next(error);
  }
});

router.get("/timeline", requireDashboardAuth, async (_req, res, next) => {
  try {
    const stats = await getStats();
    return res.json(stats.timeline);
  } catch (error) {
    return next(error);
  }
});

router.get("/services", requireDashboardAuth, async (_req, res, next) => {
  try {
    const stats = await getStats();
    return res.json(stats.services);
  } catch (error) {
    return next(error);
  }
});

export default router;
