// Threat-intel providers. Each provider declares how to fetch one IP and how
// to reduce the response to a small, allow-listed object.
//
// Provider responses are UNTRUSTED too: fields like AbuseIPDB `domain` or
// ipinfo `hostname` come from reverse DNS, which the attacker controls. Every
// string is sanitized and clipped before it is stored or shown to the LLM.

import { sanitizeString } from "../ingest/eventSchema.js";

const MAX_STR = 200;

/** @param {unknown} v */
const s = (v) => (typeof v === "string" ? sanitizeString(v, MAX_STR).value : null);
/** @param {unknown} v */
const n = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
/** @param {unknown} v */
const b = (v) => (typeof v === "boolean" ? v : null);

/**
 * @typedef {object} ProviderResult
 * @property {boolean} found
 * @property {Record<string, unknown>} [data]
 */

/**
 * @typedef {object} HttpProvider
 * @property {string} name
 * @property {"http"} kind
 * @property {(ip: string, apiKey: string) => { url: string, headers: Record<string, string> }} request
 * @property {(status: number, body: any) => ProviderResult} parse
 */

/** @param {number} status */
function assertOk(status) {
  if (status === 429) throw new Error("provider rate limited (HTTP 429)");
  if (status === 401 || status === 403) throw new Error(`provider rejected API key (HTTP ${status})`);
  if (status < 200 || status >= 300) throw new Error(`provider error (HTTP ${status})`);
}

/** @type {HttpProvider} */
export const abuseipdb = {
  name: "abuseipdb",
  kind: "http",
  request: (ip, apiKey) => ({
    url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    headers: { Key: apiKey, Accept: "application/json" }
  }),
  parse: (status, body) => {
    assertOk(status);
    const d = body?.data ?? {};
    return {
      found: true,
      data: {
        abuse_confidence: n(d.abuseConfidenceScore),
        total_reports: n(d.totalReports),
        distinct_reporters: n(d.numDistinctUsers),
        last_reported_at: s(d.lastReportedAt),
        country: s(d.countryCode),
        usage_type: s(d.usageType),
        isp: s(d.isp),
        domain: s(d.domain),
        is_tor: b(d.isTor),
        is_whitelisted: b(d.isWhitelisted)
      }
    };
  }
};

/** @type {HttpProvider} */
export const virustotal = {
  name: "virustotal",
  kind: "http",
  request: (ip, apiKey) => ({
    url: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
    headers: { "x-apikey": apiKey, Accept: "application/json" }
  }),
  parse: (status, body) => {
    if (status === 404) return { found: false };
    assertOk(status);
    const a = body?.data?.attributes ?? {};
    const stats = a.last_analysis_stats ?? {};
    return {
      found: true,
      data: {
        malicious: n(stats.malicious),
        suspicious: n(stats.suspicious),
        harmless: n(stats.harmless),
        undetected: n(stats.undetected),
        reputation: n(a.reputation),
        country: s(a.country),
        asn: n(a.asn),
        as_owner: s(a.as_owner),
        network: s(a.network)
      }
    };
  }
};

/** @type {HttpProvider} */
export const greynoise = {
  name: "greynoise",
  kind: "http",
  request: (ip, apiKey) => ({
    url: `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
    headers: { key: apiKey, Accept: "application/json" }
  }),
  parse: (status, body) => {
    // 404 = "IP not observed scanning the internet", a meaningful answer.
    if (status === 404) return { found: false, data: { noise: false, riot: false } };
    assertOk(status);
    return {
      found: true,
      data: {
        noise: b(body?.noise),
        riot: b(body?.riot),
        classification: s(body?.classification),
        name: s(body?.name),
        last_seen: s(body?.last_seen)
      }
    };
  }
};

/** @type {HttpProvider} */
export const ipinfo = {
  name: "ipinfo",
  kind: "http",
  request: (ip, apiKey) => ({
    url: `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
    headers: { Authorization: `Bearer ${apiKey}`, Accept: "application/json" }
  }),
  parse: (status, body) => {
    assertOk(status);
    const org = s(body?.org);
    const asMatch = org ? /^AS(\d+)\s+(.*)$/.exec(org) : null;
    const [lat, lon] = typeof body?.loc === "string" ? body.loc.split(",").map(Number) : [null, null];
    return {
      found: true,
      data: {
        country: s(body?.country),
        region: s(body?.region),
        city: s(body?.city),
        latitude: n(lat),
        longitude: n(lon),
        asn: asMatch ? Number(asMatch[1]) : null,
        as_org: asMatch ? asMatch[2] : org,
        hostname: s(body?.hostname)
      }
    };
  }
};

export const HTTP_PROVIDERS = [abuseipdb, virustotal, greynoise, ipinfo];

/**
 * Local MaxMind GeoLite2 lookup (no network, no quota). Returns null if no
 * database is configured or the `maxmind` reader can't be loaded.
 * @param {{ cityDbPath: string, asnDbPath: string }} cfg
 */
export async function openMaxmind(cfg) {
  if (!cfg.cityDbPath && !cfg.asnDbPath) return null;
  const { default: maxmind } = await import("maxmind");
  /** @type {any} */
  const city = cfg.cityDbPath ? await maxmind.open(cfg.cityDbPath) : null;
  /** @type {any} */
  const asn = cfg.asnDbPath ? await maxmind.open(cfg.asnDbPath) : null;
  return {
    name: "maxmind",
    /** @param {string} ip @returns {ProviderResult} */
    lookup(ip) {
      const c = city?.get(ip);
      const a = asn?.get(ip);
      if (!c && !a) return { found: false };
      return {
        found: true,
        data: {
          country: s(c?.country?.iso_code ?? c?.registered_country?.iso_code),
          country_name: s(c?.country?.names?.en),
          city: s(c?.city?.names?.en),
          latitude: n(c?.location?.latitude),
          longitude: n(c?.location?.longitude),
          asn: n(a?.autonomous_system_number),
          as_org: s(a?.autonomous_system_organization)
        }
      };
    }
  };
}
