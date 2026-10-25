import { describe, expect, it, vi } from "vitest";
import { cleanRemoteAddress, createReporter, loadSensorConfig } from "../common/reporter.js";

/** @param {number} status @param {unknown} [body] */
const respond = (status, body = {}) =>
  /** @type {any} */ ({ status, json: async () => body });

describe("loadSensorConfig", () => {
  it("fails closed in production without https and a strong token", () => {
    expect(() =>
      loadSensorConfig({ NODE_ENV: "production", SENSOR_INGEST_URL: "http://backend/ingest/v1/events" })
    ).toThrow(/https[\s\S]*SENSOR_INGEST_TOKEN/);
  });

  it.each(["DATABASE_URL", "LLM_API_KEY", "ABUSEIPDB_API_KEY", "JWT_SECRET_KEY", "EDL_TOKEN"])(
    "refuses to start when a backend secret (%s) is present, in any mode",
    (name) => {
      expect(() => loadSensorConfig({ NODE_ENV: "development", [name]: "x" })).toThrow(new RegExp(`remove: ${name}`));
    }
  );

  it("accepts a valid production config", () => {
    const cfg = loadSensorConfig({
      NODE_ENV: "production",
      SENSOR_INGEST_URL: "https://api.example.com/ingest/v1/events",
      SENSOR_INGEST_TOKEN: "t".repeat(32),
      SENSOR_ID: "oracle-1"
    });
    expect(cfg.sensorId).toBe("oracle-1");
  });
});

describe("createReporter", () => {
  const base = { ingestUrl: "http://x/ingest", token: "tok", log: () => {} };

  it("batches events with a bearer token", async () => {
    const fetchImpl = vi.fn(async () => respond(202, { accepted: 2, rejected: [] }));
    const r = createReporter({ ...base, fetchImpl, sensorId: "s1" });
    r.enqueue({ a: 1 });
    r.enqueue({ a: 2 });
    await r.flush();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [, init] = /** @type {any} */ (fetchImpl.mock.calls[0]);
    expect(init.headers.authorization).toBe("Bearer tok");
    expect(JSON.parse(init.body).events).toEqual([{ a: 1, sensor_id: "s1" }, { a: 2, sensor_id: "s1" }]);
    expect(r.stats.sent).toBe(2);
    expect(r.queued).toBe(0);
  });

  it("requeues on network failure and backs off", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const r = createReporter({ ...base, fetchImpl });
    r.enqueue({ a: 1 });
    await r.flush();
    expect(r.queued).toBe(1);
    await r.flush(); // still backing off: no second call
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("bounds the queue by dropping the oldest events", () => {
    const r = createReporter({ ...base, fetchImpl: vi.fn(), maxQueue: 3, batchSize: 100 });
    for (let i = 0; i < 5; i++) r.enqueue({ i });
    expect(r.queued).toBe(3);
    expect(r.stats.dropped).toBe(2);
  });

  it("drops (does not retry) batches refused for auth", async () => {
    const r = createReporter({ ...base, fetchImpl: vi.fn(async () => respond(401)) });
    r.enqueue({ a: 1 });
    await r.flush();
    expect(r.queued).toBe(0);
    expect(r.stats.dropped).toBe(1);
  });
});

describe("cleanRemoteAddress", () => {
  it("unwraps IPv4-mapped addresses only", () => {
    expect(cleanRemoteAddress("::ffff:203.0.113.1")).toBe("203.0.113.1");
    expect(cleanRemoteAddress("2001:db8::1")).toBe("2001:db8::1");
    expect(cleanRemoteAddress(undefined)).toBe("0.0.0.0");
  });
});
