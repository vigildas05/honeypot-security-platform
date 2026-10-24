import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { env } from "./config/env.js";
import { pool } from "./db/pool.js";
import { denyReadOnlyWrites } from "./middleware/auth.js";
import { requestId } from "./middleware/requestId.js";
import actionRoutes from "./routes/actions.js";
import attackRoutes from "./routes/attacks.js";
import authRoutes from "./routes/auth.js";
import edlRoutes from "./routes/edl.js";
import ingestRoutes from "./routes/ingest.js";
import statsRoutes from "./routes/stats.js";

export const app = express();

app.disable("x-powered-by");
// Only trust X-Forwarded-For from a known number of proxy hops (e.g. Render's LB).
app.set("trust proxy", env.trustProxy);

app.use(requestId);
app.use(helmet());
app.use(express.json({ limit: "256kb" }));
app.use(
  cors({
    origin: env.corsOrigins,
    credentials: true
  })
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "honeypot-backend" });
});

app.get("/health/ready", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "ok" });
  } catch {
    res.status(503).json({ status: "unavailable", database: "unreachable" });
  }
});

// Sensor ingest has its own token-keyed rate limit (see routes/ingest.js).
app.use(ingestRoutes);
// Firewall EDL has its own credentials and rate limit.
app.use(edlRoutes);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: env.apiRateLimitPerMinute,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// Everything below the ingest routes is dashboard traffic; mount the limiter
// once so a request falling through several routers is counted once.
app.use(apiLimiter);
app.use(denyReadOnlyWrites);
app.use("/auth", authRoutes);
app.use(attackRoutes);
app.use(statsRoutes);
app.use(actionRoutes);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

/**
 * @param {any} err
 * @param {import("express").Request} _req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} _next
 */
const errorHandler = (err, _req, res, _next) => {
  // Body-parser errors: client problems, not server faults.
  if (err?.type === "entity.too.large") {
    return res.status(413).json({ error: "Payload too large" });
  }
  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON" });
  }
  console.error(err);
  return res.status(500).json({ error: "Internal server error" });
};

app.use(errorHandler);
