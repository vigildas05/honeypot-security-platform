import net from "node:net";
import { normalizeIp } from "../ingest/eventSchema.js";

/**
 * Non-globally-routable ranges, from the IANA IPv4/IPv6 Special-Purpose
 * Address Registries (RFC 6890 and updates). Each entry: [cidr, category].
 * Categories matter to the policy engine: none of these may ever be blocked,
 * and none are ever sent to threat-intel providers.
 * @type {[string, string][]}
 */
export const SPECIAL_RANGES = [
  // IPv4
  ["0.0.0.0/8", "unspecified"],
  ["10.0.0.0/8", "private"],
  ["100.64.0.0/10", "cgnat"],
  ["127.0.0.0/8", "loopback"],
  ["169.254.0.0/16", "link-local"],
  ["172.16.0.0/12", "private"],
  ["192.0.0.0/24", "reserved"],
  ["192.0.2.0/24", "documentation"],
  ["192.88.99.0/24", "reserved"],
  ["192.168.0.0/16", "private"],
  ["198.18.0.0/15", "benchmarking"],
  ["198.51.100.0/24", "documentation"],
  ["203.0.113.0/24", "documentation"],
  ["224.0.0.0/4", "multicast"],
  ["240.0.0.0/4", "reserved"],
  ["255.255.255.255/32", "broadcast"],
  // IPv6
  ["::/128", "unspecified"],
  ["::1/128", "loopback"],
  ["100::/64", "reserved"],
  ["2001::/23", "reserved"],
  ["2001:db8::/32", "documentation"],
  ["2002::/16", "reserved"],
  ["3fff::/20", "documentation"],
  ["5f00::/16", "reserved"],
  ["fc00::/7", "private"],
  ["fe80::/10", "link-local"],
  ["fec0::/10", "reserved"],
  ["ff00::/8", "multicast"]
];

/** @type {Map<string, net.BlockList>} */
const byCategory = new Map();
for (const [cidr, category] of SPECIAL_RANGES) {
  const [address, prefix] = cidr.split("/");
  const list = byCategory.get(category) ?? new net.BlockList();
  list.addSubnet(address, Number(prefix), net.isIPv6(address) ? "ipv6" : "ipv4");
  byCategory.set(category, list);
}

/**
 * Extract an embedded IPv4 address from IPv4-mapped (::ffff:a.b.c.d) or
 * NAT64 (64:ff9b::/96) IPv6 forms, so they're classified as the IPv4 they are.
 * @param {string} ip canonical IPv6
 * @returns {string | null}
 */
function embeddedIpv4(ip) {
  const full = expandIpv6(ip);
  if (full.startsWith("0000:0000:0000:0000:0000:ffff:") || full.startsWith("0064:ff9b:0000:0000:0000:0000:")) {
    const hex = full.slice(30).replace(":", "");
    const n = Number.parseInt(hex, 16);
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  return null;
}

/** @param {string} ip */
function expandIpv6(ip) {
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  if (t.length && t[t.length - 1].includes(".")) {
    const v4 = t.pop()?.split(".").map(Number) ?? [];
    t.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16));
  }
  const missing = ip.includes("::") ? 8 - h.length - t.length : 0;
  return [...h, ...Array(missing).fill("0"), ...t].map((p) => p.padStart(4, "0")).join(":");
}

/**
 * Classify an IP literal.
 * @param {string} value
 * @returns {{ ip: string | null, valid: boolean, public: boolean, category: string, family: 4 | 6 | null }}
 */
export function classifyIp(value) {
  const ip = typeof value === "string" ? normalizeIp(value) : null;
  if (!ip) return { ip: null, valid: false, public: false, category: "invalid", family: null };

  const family = /** @type {4 | 6} */ (net.isIP(ip));
  if (family === 6) {
    const v4 = embeddedIpv4(ip);
    if (v4) {
      const inner = classifyIp(v4);
      return { ...inner, ip, family: 6 };
    }
  }
  const type = family === 6 ? "ipv6" : "ipv4";
  for (const [category, list] of byCategory) {
    if (list.check(ip, type)) return { ip, valid: true, public: false, category, family };
  }
  return { ip, valid: true, public: true, category: "public", family };
}

/** @param {string} value */
export const isPublicIp = (value) => classifyIp(value).public;

/**
 * Build a matcher for a list of IPs/CIDRs (e.g. the never-block list).
 * Invalid entries throw so a typo in config can't silently disable protection.
 * @param {string[]} entries
 */
export function buildCidrMatcher(entries) {
  const list = new net.BlockList();
  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;
    const [address, prefix] = entry.split("/");
    const ip = normalizeIp(address);
    if (!ip) throw new Error(`Invalid IP/CIDR in list: ${entry}`);
    const family = net.isIPv6(ip) ? "ipv6" : "ipv4";
    if (prefix === undefined) {
      list.addAddress(ip, family);
    } else {
      const bits = Number(prefix);
      const max = family === "ipv6" ? 128 : 32;
      if (!Number.isInteger(bits) || bits < 0 || bits > max) throw new Error(`Invalid prefix in list: ${entry}`);
      list.addSubnet(ip, bits, family);
    }
  }
  /** @param {string} value */
  return (value) => {
    const ip = normalizeIp(value);
    if (!ip) return false;
    if (net.isIPv6(ip)) {
      const v4 = embeddedIpv4(ip);
      if (v4 && list.check(v4, "ipv4")) return true;
      return list.check(ip, "ipv6");
    }
    return list.check(ip, "ipv4");
  };
}
