import crypto from "node:crypto";

/**
 * Attach a request id (reuse a well-formed incoming X-Request-Id, otherwise
 * generate one) and echo it back. Used in logs and the audit log.
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 */
export function requestId(req, res, next) {
  const incoming = req.headers["x-request-id"];
  req.id = typeof incoming === "string" && /^[a-zA-Z0-9_-]{8,64}$/.test(incoming) ? incoming : crypto.randomUUID();
  res.setHeader("x-request-id", req.id);
  next();
}
