import express from "express";
import { requireDashboardAuth } from "../middleware/auth.js";
import { listAttacks } from "../services/attackService.js";

const router = express.Router();

router.get("/attacks", requireDashboardAuth, async (req, res, next) => {
  try {
    const requested = Number(req.query.limit ?? 100);
    const limit = Number.isInteger(requested) && requested > 0 ? Math.min(requested, 500) : 100;
    const attacks = await listAttacks(limit);
    return res.json(attacks);
  } catch (error) {
    return next(error);
  }
});

export default router;
