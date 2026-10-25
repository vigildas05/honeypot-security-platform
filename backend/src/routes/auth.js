import express from "express";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { env } from "../config/env.js";
import { verifyCredentials } from "../services/userService.js";

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: env.loginRateLimitPer15Min,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: "Too many login attempts, try again later" }
});

const loginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256)
});

router.post("/login", loginLimiter, async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid login payload" });
    }

    const user = await verifyCredentials(parsed.data.username, parsed.data.password);
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role },
      env.jwtSecret,
      /** @type {jwt.SignOptions} */ ({
        algorithm: "HS256",
        subject: user.id,
        expiresIn: env.jwtTtl
      })
    );
    return res.json({ token, role: user.role, username: user.username });
  } catch (error) {
    return next(error);
  }
});

export default router;
