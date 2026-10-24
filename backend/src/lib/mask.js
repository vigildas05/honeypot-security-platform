import net from "node:net";

/**
 * Mask the host part of an IP for the read-only demo role. Applied
 * server-side, so the full address never reaches a demo user's browser.
 *   IPv4: 91.92.93.94      -> 91.92.93.x
 *   IPv6: 2001:db8:1:2::5  -> 2001:db8:1:2::x   (keeps the /64 prefix)
 * @param {string | null | undefined} ip
 */
export function maskIp(ip) {
  if (!ip) return ip;
  if (net.isIPv4(ip)) return ip.replace(/\.\d+$/, ".x");
  if (net.isIPv6(ip)) {
    const [head] = ip.split("::");
    const groups = (ip.includes("::") ? head : ip).split(":").filter(Boolean).slice(0, 4);
    return `${groups.join(":")}::x`;
  }
  return "x";
}

/**
 * Recursively mask IP-valued fields (by key name) in API payloads.
 * @template T
 * @param {T} value
 * @param {Set<string>} [keys]
 * @returns {T}
 */
export function maskIpFields(value, keys = new Set(["ip", "src_ip", "target", "value_ip"])) {
  if (Array.isArray(value)) return /** @type {T} */ (value.map((v) => maskIpFields(v, keys)));
  if (value && typeof value === "object" && !(value instanceof Date)) {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = keys.has(k) && typeof v === "string" ? maskIp(v) : maskIpFields(v, keys);
    }
    return /** @type {T} */ (out);
  }
  return value;
}

/**
 * @param {import("express").Request} req
 * @param {unknown} payload
 */
export function forViewer(req, payload) {
  return req.user?.role === "admin" ? payload : maskIpFields(payload);
}
