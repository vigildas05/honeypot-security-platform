import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { env } from "./config/env.js";
import attackRoutes from "./routes/attacks.js";
import authRoutes from "./routes/auth.js";
import statsRoutes from "./routes/stats.js";

export const app = express();

app.use(helmet());
app.use(express.json({ limit: "200kb" }));
app.use(
  cors({
    origin: env.corsOrigins,
    credentials: true
  })
);
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120
  })
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "honeypot-backend" });
});

app.use("/auth", authRoutes);
app.use(attackRoutes);
app.use(statsRoutes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});
