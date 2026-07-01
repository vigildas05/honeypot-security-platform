import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export function requireDashboardAuth(req, res, next) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing dashboard token" });
  }

  try {
    req.user = jwt.verify(token, env.jwtSecret);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid dashboard token" });
  }
}

export function requireHoneypotToken(req, res, next) {
  const token = req.headers["x-honeypot-token"];

  if (token !== env.honeypotApiToken) {
    return res.status(401).json({ error: "Invalid honeypot token" });
  }

  return next();
}
