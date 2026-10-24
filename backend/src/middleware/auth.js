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
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

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
    // Default-deny for the read-only demo role: any mutating method is refused
    // here, so endpoints added later are protected even if they forget requireRole.
    if (req.user.role !== "admin" && !SAFE_METHODS.has(req.method)) {
      return res.status(403).json({ error: "Read-only account" });
    }
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid dashboard token" });
  }
}

/**
 * Global default-deny for the read-only demo role, mounted before every
 * dashboard router: a valid demo JWT on any non-GET/HEAD/OPTIONS request is
 * refused, whether or not the route itself remembered to check roles.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
export function denyReadOnlyWrites(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const header = req.headers.authorization ?? "";
  if (!header.startsWith("Bearer ")) return next();
  try {
    const claims = /** @type {jwt.JwtPayload} */ (jwt.verify(header.slice(7), env.jwtSecret, { algorithms: ["HS256"] }));
    if (claims.role !== "admin") return res.status(403).json({ error: "Read-only account" });
  } catch {
    // Invalid tokens are handled (401) by requireDashboardAuth on real routes.
  }
  return next();
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
