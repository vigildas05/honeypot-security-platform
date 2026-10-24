import express from "express";
import rateLimit from "express-rate-limit";
import { env } from "../config/env.js";
import { parseEvent } from "../ingest/eventSchema.js";
import { legacyAttackToWireEvent } from "../ingest/legacy.js";
import { requireHoneypotToken } from "../middleware/auth.js";
import { insertEvents } from "../services/eventService.js";

const router = express.Router();

// Sensors get their own, much higher budget keyed by sensor id, so a
// brute-force burst against the honeypot doesn't cause dropped telemetry or
// starve dashboard users.
const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: env.ingestRateLimitPerMinute,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req) => `sensor:${req.sensorId}`
});

/**
 * @param {unknown[]} items
 * @param {string} sensorId
 */
async function ingest(items, sensorId) {
  const valid = [];
  const rejected = [];
  for (const [index, item] of items.entries()) {
    const result = parseEvent(item, sensorId);
    if (result.ok) valid.push(result.event);
    else rejected.push({ index, error: result.error });
  }
  const inserted = await insertEvents(valid);
  if (rejected.length > 0) {
    console.warn(`ingest: sensor=${sensorId} rejected=${rejected.length} accepted=${inserted.length}`);
  }
  return { inserted, rejected };
}

router.post("/ingest/v1/events", requireHoneypotToken, ingestLimiter, async (req, res, next) => {
  try {
    const body = req.body;
    const items = Array.isArray(body?.events) ? body.events : body ? [body] : [];
    if (items.length === 0) {
      return res.status(400).json({ error: "No events in request" });
    }
    if (items.length > env.ingestMaxBatch) {
      return res.status(413).json({ error: `Batch exceeds ${env.ingestMaxBatch} events` });
    }

    const { inserted, rejected } = await ingest(items, /** @type {string} */ (req.sensorId));
    if (inserted.length === 0) {
      return res.status(400).json({ error: "All events were rejected", accepted: 0, rejected });
    }
    return res.status(202).json({ accepted: inserted.length, rejected });
  } catch (error) {
    return next(error);
  }
});

// Legacy endpoint used by the original sensors. Same validation path.
router.post("/attack", requireHoneypotToken, ingestLimiter, async (req, res, next) => {
  try {
    const { inserted, rejected } = await ingest(
      [legacyAttackToWireEvent(req.body)],
      /** @type {string} */ (req.sensorId)
    );
    if (inserted.length === 0) {
      return res.status(400).json({ error: "Invalid attack payload", details: rejected[0]?.error });
    }
    return res.status(201).json({ id: inserted[0].id });
  } catch (error) {
    return next(error);
  }
});

export default router;
