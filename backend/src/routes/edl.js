// External Dynamic List for firewalls (e.g. PAN-OS "IP List" EDL type):
// plain text, one IP per line, only approved + active + unexpired blocks.
import crypto from "node:crypto";
import express from "express";
import rateLimit from "express-rate-limit";
import { createPolicyEngine } from "../agent/policy.js";
import { loadAgentConfig } from "../config/agent.js";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";
import { incrementCounters } from "../lib/metrics.js";

const router = express.Router();
const policy = createPolicyEngine(loadAgentConfig(process.env).policy);

/** @param {string} a @param {string} b */
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/**
 * @param {import("express").Request} req
 * @param {typeof env.edl} cfg
 */
export function edlAuthorized(req, cfg) {
  const tokenAllowed = cfg.mode !== "basic" && cfg.token.length > 0;
  const basicAllowed = cfg.mode !== "token" && cfg.basicUser.length > 0 && cfg.basicPassword.length > 0;

  if (tokenAllowed && typeof req.query.token === "string" && safeEqual(req.query.token, cfg.token)) return true;

  const header = req.headers.authorization ?? "";
  if (basicAllowed && header.startsWith("Basic ")) {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx > 0) {
      // Evaluate both comparisons to avoid short-circuit timing differences.
      const userOk = safeEqual(decoded.slice(0, idx), cfg.basicUser);
      const passOk = safeEqual(decoded.slice(idx + 1), cfg.basicPassword);
      if (userOk && passOk) return true;
    }
  }
  return false;
}

const edlEnabled = (/** @type {typeof env.edl} */ cfg) =>
  (cfg.mode !== "basic" && cfg.token.length > 0) || (cfg.mode !== "token" && cfg.basicUser.length > 0 && cfg.basicPassword.length > 0);

const limiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: "draft-7", legacyHeaders: false });

router.get("/edl/blocklist.txt", limiter, async (req, res, next) => {
  try {
    res.set("Cache-Control", "no-store");
    if (!edlEnabled(env.edl)) return res.status(404).type("text/plain").send("Not found\n");
    if (!edlAuthorized(req, env.edl)) {
      if (env.edl.mode !== "token") res.set("WWW-Authenticate", 'Basic realm="edl", charset="UTF-8"');
      return res.status(401).type("text/plain").send("Unauthorized\n");
    }

    const r = await pool.query(
      `SELECT DISTINCT host(target) AS ip FROM proposed_actions
       WHERE action_type = 'block_ip' AND status = 'active'
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY 1`
    );
    // Defense in depth: never publish an address the policy would refuse today.
    const ips = r.rows.map((row) => row.ip).filter((ip) => policy.isAllowedTarget(ip).ok);
    await incrementCounters(pool, { "edl.fetches": 1 });
    return res.type("text/plain; charset=utf-8").send(ips.length ? `${ips.join("\n")}\n` : "");
  } catch (error) {
    return next(error);
  }
});

export default router;
