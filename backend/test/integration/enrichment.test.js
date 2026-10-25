// Integration tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.
// WARNING: drops and recreates the `public` schema of that database.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { loadEnrichmentConfig } from "../../src/config/enrichment.js";

const url = process.env.TEST_DATABASE_URL;
const ATTACKER = "91.92.93.94"; // arbitrary public address used as a fixture

/** @param {number} status @param {unknown} body */
const reply = (status, body) => /** @type {any} */ ({ status, json: async () => body });

describe.skipIf(!url)("enrichment service (postgres)", () => {
  /** @type {import("pg").Pool} */
  let pool;
  /** @type {typeof import("../../src/enrichment/service.js").createEnrichmentService} */
  let createEnrichmentService;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    ({ pool } = await import("../../src/db/pool.js"));
    const { runMigrations } = await import("../../src/db/migrations.js");
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(pool, { log: () => {} });
    ({ createEnrichmentService } = await import("../../src/enrichment/service.js"));
  });

  beforeEach(async () => {
    await pool.query("TRUNCATE ip_enrichment_cache, provider_usage");
  });

  afterAll(async () => {
    await pool?.end();
  });

  const abuseBody = { data: { abuseConfidenceScore: 95, totalReports: 40, countryCode: "RU" } };

  /** @param {Record<string, string>} env @param {any} fetchImpl */
  const make = (env, fetchImpl) =>
    createEnrichmentService({
      db: pool,
      config: loadEnrichmentConfig(env),
      fetchImpl,
      log: () => {},
      maxmind: null
    });

  it("does nothing when no provider keys are configured", async () => {
    const fetchImpl = vi.fn();
    const svc = await make({}, fetchImpl);
    expect(svc.enabledProviders).toEqual([]);
    const r = await svc.enrich(ATTACKER);
    expect(r.providers).toEqual({});
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each(["10.0.0.5", "127.0.0.1", "100.64.1.1", "169.254.169.254", "::1", "fe80::1", "203.0.113.9"])(
    "never looks up non-public address %s",
    async (ip) => {
      const fetchImpl = vi.fn();
      const svc = await make({ ABUSEIPDB_API_KEY: "k" }, fetchImpl);
      const r = await svc.enrich(ip);
      expect(r.skipped).not.toBeNull();
      expect(fetchImpl).not.toHaveBeenCalled();
    }
  );

  it("fetches once, then serves from cache", async () => {
    const fetchImpl = vi.fn(async () => reply(200, abuseBody));
    const svc = await make({ ABUSEIPDB_API_KEY: "k" }, fetchImpl);

    const first = await svc.enrich(ATTACKER);
    expect(first.providers.abuseipdb.status).toBe("ok");
    expect(first.summary).toMatchObject({ abuse_confidence: 95, country: "RU" });

    const second = await svc.enrich(ATTACKER);
    expect(second.providers.abuseipdb.status).toBe("cached");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("enforces the daily quota in the database", async () => {
    const fetchImpl = vi.fn(async () => reply(200, abuseBody));
    const svc = await make({ ABUSEIPDB_API_KEY: "k", ABUSEIPDB_DAILY_LIMIT: "2" }, fetchImpl);
    await svc.enrich("91.92.93.1");
    await svc.enrich("91.92.93.2");
    const third = await svc.enrich("91.92.93.3");
    expect(third.providers.abuseipdb.status).toBe("rate_limited");
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    // A fresh service instance (e.g. after a restart) still sees the used quota.
    const restarted = await make({ ABUSEIPDB_API_KEY: "k", ABUSEIPDB_DAILY_LIMIT: "2" }, fetchImpl);
    expect((await restarted.enrich("91.92.93.4")).providers.abuseipdb.status).toBe("rate_limited");
  });

  it("enforces the per-minute window", async () => {
    const fetchImpl = vi.fn(async () => reply(200, {}));
    const svc = await make({ VIRUSTOTAL_API_KEY: "k", VIRUSTOTAL_RATE_PER_MINUTE: "1" }, fetchImpl);
    await svc.enrich("91.92.93.10");
    expect((await svc.enrich("91.92.93.11")).providers.virustotal.status).toBe("rate_limited");
  });

  it("caches errors briefly instead of hammering a failing provider", async () => {
    const fetchImpl = vi.fn(async () => reply(500, {}));
    const svc = await make({ ABUSEIPDB_API_KEY: "k" }, fetchImpl);
    expect((await svc.enrich(ATTACKER)).providers.abuseipdb.status).toBe("error");
    expect((await svc.enrich(ATTACKER)).providers.abuseipdb.status).toBe("error");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("survives network timeouts", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
    });
    const svc = await make({ GREYNOISE_API_KEY: "k" }, fetchImpl);
    const r = await svc.enrich(ATTACKER);
    expect(r.providers.greynoise).toMatchObject({ status: "error" });
  });
});
