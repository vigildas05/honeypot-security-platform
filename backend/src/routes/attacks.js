import express from "express";
import { z } from "zod";
import { requireDashboardAuth, requireHoneypotToken } from "../middleware/auth.js";
import { createAttack, listAttacks } from "../services/attackService.js";

const router = express.Router();

const attackSchema = z.object({
  ip: z.string().min(1),
  country: z.string().optional(),
  protocol: z.string().min(1),
  service: z.string().min(1),
  username: z.string().optional(),
  password: z.string().optional(),
  userAgent: z.string().optional(),
  method: z.string().optional(),
  path: z.string().optional(),
  headers: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional(),
  status: z.string().optional(),
  connectionDurationMs: z.number().int().nonnegative().optional()
});

router.post("/attack", requireHoneypotToken, async (req, res, next) => {
  try {
    const parsed = attackSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid attack payload" });
    }

    const attack = await createAttack(parsed.data);
    return res.status(201).json(attack);
  } catch (error) {
    return next(error);
  }
});

router.get("/attacks", requireDashboardAuth, async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit ?? 100), 500);
    const attacks = await listAttacks(limit);
    return res.json(attacks);
  } catch (error) {
    return next(error);
  }
});

export default router;
