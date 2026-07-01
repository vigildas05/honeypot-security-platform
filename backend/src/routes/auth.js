import express from "express";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { env } from "../config/env.js";

const router = express.Router();

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1)
});

router.post("/login", (req, res) => {
  const parsed = loginSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid login payload" });
  }

  const { username, password } = parsed.data;
  const valid =
    username === env.dashboardUser && password === env.dashboardPassword;

  if (!valid) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = jwt.sign({ username }, env.jwtSecret, { expiresIn: "1h" });
  return res.json({ token });
});

export default router;
