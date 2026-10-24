/**
 * Map the original `POST /attack` payload onto the normalized wire format so
 * old sensors keep working. The result still goes through `parseEvent`.
 * @param {any} body
 * @returns {unknown}
 */
export function legacyAttackToWireEvent(body) {
  if (!body || typeof body !== "object") return body;
  const protocol = typeof body.protocol === "string" ? body.protocol.toLowerCase() : body.protocol;
  const timestamp = new Date().toISOString();
  const optString = (/** @type {unknown} */ v) => (typeof v === "string" ? v : undefined);

  if (protocol === "ssh") {
    return {
      timestamp,
      protocol: "ssh",
      event_type: "auth_attempt",
      src_ip: body.ip,
      ssh: {
        username: optString(body.username),
        password: optString(body.password),
        auth_method: optString(body.metadata?.authMethod),
        auth_success: body.status === "accepted"
      }
    };
  }

  if (protocol === "http") {
    /** @type {Record<string, string | string[]>} */
    const headers = {};
    if (body.headers && typeof body.headers === "object") {
      for (const [k, v] of Object.entries(body.headers)) {
        if (typeof v === "string" || (Array.isArray(v) && v.every((x) => typeof x === "string"))) {
          headers[k] = v;
        }
      }
    }
    return {
      timestamp,
      protocol: "http",
      event_type: "request",
      src_ip: body.ip,
      raw: optString(body.metadata?.bodyPreview),
      http: {
        method: optString(body.method),
        path: optString(body.path),
        user_agent: optString(body.userAgent),
        username: optString(body.username),
        password: optString(body.password),
        headers
      }
    };
  }

  // Unknown protocol: let schema validation reject it.
  return { protocol, src_ip: body.ip, timestamp };
}
