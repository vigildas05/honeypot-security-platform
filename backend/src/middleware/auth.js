import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

/** @param {string} value */
const sha256 = (value) => crypto.createHash("sha256").update(value).digest();

/**
 * Pre-hash configured tokens so every comparison is fixed-length and
 * constant-time, and we always scan the whole list.
 * @param {Map<string, string>} tokens token -> sensorId
 */
export function buildSensorTokenMatcher(tokens) {
  const entries = [...tokens].map(([token, sensorId]) => ({ hash: sha256(token), sensorId }));
  /** @param {string} presented @returns {string | null} */
  return (presented) => {
    const hash = sha256(presented);
    let match = null;
    for (const entry of entries) {
      if (crypto.timingSafeEqual(hash, entry.hash)) match = entry.sensorId;
    }
    return match;
  };
}

const matchSensorToken = buildSensorTokenMatcher(env.sensorTokens);

/**
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
export function requireDashboardAuth(req, res, next) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing dashboard token" });
  }

  try {
    const claims = /** @type {jwt.JwtPayload} */ (
      jwt.verify(token, env.jwtSecret, { algorithms: ["HS256"] })
    );
    if (claims.role !== "admin" && claims.role !== "demo") {
      return res.status(401).json({ error: "Invalid dashboard token" });
    }
    req.user = { id: String(claims.sub), username: String(claims.username), role: claims.role };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid dashboard token" });
  }
}

/**
 * Server-side role gate. Must come after requireDashboardAuth.
 * @param {...("admin" | "demo")} roles
 */
export function requireRole(...roles) {
  /**
   * @param {import("express").Request} req
   * @param {import("express").Response} res
   * @param {import("express").NextFunction} next
   */
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient role" });
    }
    return next();
  };
}

/**
 * Sensor ingest auth. Accepts `Authorization: Bearer <token>` or the legacy
 * `x-honeypot-token` header, and binds the request to that token's sensor id.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
export function requireHoneypotToken(req, res, next) {
  const auth = req.headers.authorization ?? "";
  const legacy = req.headers["x-honeypot-token"];
  const presented = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : typeof legacy === "string"
      ? legacy
      : "";

  const sensorId = presented ? matchSensorToken(presented) : null;
  if (!sensorId) {
    return res.status(401).json({ error: "Invalid honeypot token" });
  }

  req.sensorId = sensorId;
  return next();
}
