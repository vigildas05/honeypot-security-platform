/**
 * Threat-intel enrichment config. Every provider is optional: a missing API
 * key (or mmdb path) simply disables it. Default quotas sit safely below each
 * provider's free tier; override via env.
 * @param {NodeJS.ProcessEnv} raw
 */
export function loadEnrichmentConfig(raw) {
  const num = (/** @type {string | undefined} */ v, /** @type {number} */ d) => {
    if (v === undefined || v === "") return d;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error(`Invalid number in enrichment config: ${v}`);
    return n;
  };

  return {
    cacheTtlHours: num(raw.ENRICHMENT_CACHE_TTL_HOURS, 24),
    errorTtlMinutes: num(raw.ENRICHMENT_ERROR_TTL_MINUTES, 60),
    timeoutMs: num(raw.ENRICHMENT_TIMEOUT_MS, 8000),
    providers: {
      abuseipdb: {
        apiKey: raw.ABUSEIPDB_API_KEY ?? "",
        // Free tier: 1,000 checks/day.
        perMinute: num(raw.ABUSEIPDB_RATE_PER_MINUTE, 20),
        perDay: num(raw.ABUSEIPDB_DAILY_LIMIT, 900)
      },
      virustotal: {
        apiKey: raw.VIRUSTOTAL_API_KEY ?? "",
        // Public API: 4 requests/minute, 500/day.
        perMinute: num(raw.VIRUSTOTAL_RATE_PER_MINUTE, 4),
        perDay: num(raw.VIRUSTOTAL_DAILY_LIMIT, 450)
      },
      greynoise: {
        apiKey: raw.GREYNOISE_API_KEY ?? "",
        // Community API quotas are small and change; keep this conservative.
        perMinute: num(raw.GREYNOISE_RATE_PER_MINUTE, 5),
        perDay: num(raw.GREYNOISE_DAILY_LIMIT, 25)
      },
      ipinfo: {
        apiKey: raw.IPINFO_TOKEN ?? "",
        // Free tier: 50,000/month.
        perMinute: num(raw.IPINFO_RATE_PER_MINUTE, 60),
        perDay: num(raw.IPINFO_DAILY_LIMIT, 1500)
      },
      maxmind: {
        cityDbPath: raw.GEOIP_CITY_MMDB ?? "",
        asnDbPath: raw.GEOIP_ASN_MMDB ?? ""
      }
    }
  };
}
