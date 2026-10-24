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

// Not part of a longer dotted number on either side (a sentence-ending "." is fine).
const IPV4_IN_TEXT = /(?<!\d|\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)/g;
// Candidate IPv6 literals (embedded-IPv4 form tried first); confirmed with net.isIPv6.
const IPV6_IN_TEXT = /(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4})(?![\w:]|\.\d)/g;

/**
 * Mask every IP literal embedded in free text (report summaries, technique
 * evidence, attacker strings, audit details...).
 * @param {string} text
 */
export function maskIpsInText(text) {
  return text
    .replace(IPV6_IN_TEXT, (m) => (net.isIPv6(m) ? maskIp(m) ?? m : m))
    .replace(IPV4_IN_TEXT, (m) => (net.isIPv4(m) ? maskIp(m) ?? m : m));
}

// `network`, `hostname` and `domain` (from threat intel) also identify the host.
export const MASKED_KEYS = new Set(["ip", "src_ip", "target", "network", "hostname", "domain"]);

/**
 * Recursively mask IPs in API payloads: whole values under IP-ish keys, and
 * IP literals inside any other string.
 * @template T
 * @param {T} value
 * @param {Set<string>} [keys]
 * @returns {T}
 */
export function maskIpFields(value, keys = MASKED_KEYS) {
  if (typeof value === "string") return /** @type {T} */ (maskIpsInText(value));
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
