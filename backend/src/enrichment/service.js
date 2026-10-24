import { classifyIp } from "../lib/ip.js";
import { createMinuteWindow, reserveDailyCall } from "../lib/quota.js";
import { HTTP_PROVIDERS, openMaxmind } from "./providers.js";

/**
 * @typedef {"ok" | "cached" | "not_found" | "error" | "rate_limited"} ProviderStatus
 * @typedef {{ status: ProviderStatus, data: Record<string, unknown> | null, error?: string | null, fetched_at?: string }} ProviderOutcome
 * @typedef {{ ip: string, skipped: string | null, providers: Record<string, ProviderOutcome>, summary: Partial<ReturnType<typeof summarize>> }} EnrichmentResult
 */

/**
 * @param {{
 *   db: import("pg").Pool,
 *   config: ReturnType<typeof import("../config/enrichment.js").loadEnrichmentConfig>,
 *   fetchImpl?: typeof fetch,
 *   log?: (msg: string) => void,
 *   providers?: typeof HTTP_PROVIDERS,
 *   maxmind?: Awaited<ReturnType<typeof openMaxmind>>
 * }} deps
 */
export async function createEnrichmentService({
  db,
  config,
  fetchImpl = fetch,
  log = console.warn,
  providers = HTTP_PROVIDERS,
  maxmind
}) {
  const geo = maxmind === undefined ? await openMaxmind(config.providers.maxmind).catch((error) => {
    log(`enrichment: MaxMind disabled (${error.message})`);
    return null;
  }) : maxmind;

  const enabled = providers
    .map((provider) => {
      const cfg = /** @type {Record<string, { apiKey: string, perMinute: number, perDay: number }>} */ (
        /** @type {unknown} */ (config.providers)
      )[provider.name];
      return cfg?.apiKey ? { provider, cfg, window: createMinuteWindow(cfg.perMinute) } : null;
    })
    .filter((x) => x !== null);

  const ttlMs = config.cacheTtlHours * 3600_000;
  const errorTtlMs = config.errorTtlMinutes * 60_000;

  /**
   * @param {string} ip
   * @param {string} name
   */
  async function readCache(ip, name) {
    const r = await db.query(
      `SELECT data, error, fetched_at, expires_at > NOW() AS fresh
       FROM ip_enrichment_cache WHERE ip = $1 AND provider = $2`,
      [ip, name]
    );
    return r.rows[0] ?? null;
  }

  /**
   * @param {string} ip
   * @param {string} name
   * @param {unknown} data
   * @param {string | null} error
   * @param {number} ttl
   */
  async function writeCache(ip, name, data, error, ttl) {
    await db.query(
      `INSERT INTO ip_enrichment_cache (ip, provider, data, error, fetched_at, expires_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW() + ($5 || ' milliseconds')::interval)
       ON CONFLICT (ip, provider) DO UPDATE SET
         data = COALESCE(EXCLUDED.data, ip_enrichment_cache.data),
         error = EXCLUDED.error,
         fetched_at = EXCLUDED.fetched_at,
         expires_at = EXCLUDED.expires_at`,
      [ip, name, data === null ? null : JSON.stringify(data), error, String(ttl)]
    );
  }

  /**
   * @param {string} ip
   * @param {(typeof enabled)[number]} entry
   * @returns {Promise<ProviderOutcome>}
   */
  async function lookupProvider(ip, { provider, cfg, window }) {
    const cached = await readCache(ip, provider.name);
    if (cached?.fresh) {
      return { status: cached.error ? "error" : "cached", data: cached.data, error: cached.error, fetched_at: cached.fetched_at };
    }

    if (!window.tryTake() || !(await reserveDailyCall(db, `intel:${provider.name}`, cfg.perDay))) {
      return { status: "rate_limited", data: cached?.data ?? null };
    }

    try {
      const { url, headers } = provider.request(ip, cfg.apiKey);
      const response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(config.timeoutMs) });
      const body = await response.json().catch(() => null);
      const result = provider.parse(response.status, body);
      const data = result.data ?? {};
      await writeCache(ip, provider.name, { found: result.found, ...data }, null, ttlMs);
      return { status: result.found ? "ok" : "not_found", data: { found: result.found, ...data } };
    } catch (error) {
      const message = /** @type {Error} */ (error).message.slice(0, 200);
      log(`enrichment: ${provider.name} failed for ${ip}: ${message}`);
      await writeCache(ip, provider.name, null, message, errorTtlMs);
      return { status: "error", data: cached?.data ?? null, error: message };
    }
  }

  /**
   * Enrich one IP across all configured providers.
   * Never contacts any provider for private/reserved/loopback/etc. addresses.
   * @param {string} value
   * @returns {Promise<EnrichmentResult>}
   */
  async function enrich(value) {
    const ip = classifyIp(value);
    if (!ip.valid || !ip.public || !ip.ip) {
      return { ip: ip.ip ?? value, skipped: ip.category, providers: {}, summary: {} };
    }
    const address = ip.ip;

    /** @type {Record<string, ProviderOutcome>} */
    const outcomes = {};
    if (geo) {
      try {
        const r = geo.lookup(address);
        outcomes.maxmind = { status: r.found ? "ok" : "not_found", data: r.data ?? null };
      } catch (error) {
        outcomes.maxmind = { status: "error", data: null, error: /** @type {Error} */ (error).message };
      }
    }
    const results = await Promise.all(enabled.map((entry) => lookupProvider(address, entry)));
    enabled.forEach((entry, i) => {
      outcomes[entry.provider.name] = results[i];
    });

    return { ip: address, skipped: null, providers: outcomes, summary: summarize(outcomes) };
  }

  return {
    enrich,
    enabledProviders: [...(geo ? ["maxmind"] : []), ...enabled.map((e) => e.provider.name)]
  };
}

/**
 * Merge provider outputs into the few fields the rules, agent and UI use.
 * @param {Record<string, ProviderOutcome>} outcomes
 */
export function summarize(outcomes) {
  /** @param {string} p */
  const d = (p) => /** @type {Record<string, any>} */ (outcomes[p]?.data ?? {});
  const geo = d("maxmind");
  const info = d("ipinfo");
  const abuse = d("abuseipdb");
  const vt = d("virustotal");
  const gn = d("greynoise");
  const first = (/** @type {unknown[]} */ ...values) => values.find((v) => v !== undefined && v !== null) ?? null;

  return {
    country: first(geo.country, info.country, abuse.country, vt.country),
    city: first(geo.city, info.city),
    asn: first(geo.asn, info.asn, vt.asn),
    as_org: first(geo.as_org, info.as_org, vt.as_owner, abuse.isp),
    abuse_confidence: first(abuse.abuse_confidence),
    abuse_reports: first(abuse.total_reports),
    is_tor: first(abuse.is_tor),
    vt_malicious: first(vt.malicious),
    vt_suspicious: first(vt.suspicious),
    greynoise_classification: first(gn.classification),
    greynoise_noise: first(gn.noise),
    greynoise_riot: first(gn.riot)
  };
}
