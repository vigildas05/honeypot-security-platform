import { describe, expect, it } from "vitest";
import { loadConfig, parseSensorTokens } from "../../src/config/env.js";
import { buildSensorTokenMatcher } from "../../src/middleware/auth.js";

const strong = "x".repeat(40);

describe("loadConfig", () => {
  it("falls back to dev defaults outside production", () => {
    const cfg = loadConfig({ NODE_ENV: "development" });
    expect(cfg.sensorTokens.size).toBe(1);
    expect(cfg.jwtSecret.length).toBeGreaterThan(0);
  });

  it("fails closed in production when secrets are missing", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/unsafe configuration/);
  });

  it("rejects known weak secrets in production", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        DATABASE_URL: "postgres://x",
        JWT_SECRET_KEY: "change-this-dev-secret",
        SENSOR_TOKENS: `s1:${strong}`
      })
    ).toThrow(/JWT_SECRET_KEY/);

    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        DATABASE_URL: "postgres://x",
        JWT_SECRET_KEY: strong,
        HONEYPOT_API_TOKEN: "dev-honeypot-token"
      })
    ).toThrow(/sensor token/);
  });

  it("accepts a strong production config", () => {
    const cfg = loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://x",
      JWT_SECRET_KEY: strong,
      SENSOR_TOKENS: `oracle-1:${strong}`
    });
    expect(cfg.sensorTokens.get(strong)).toBe("oracle-1");
  });
});

describe("parseSensorTokens", () => {
  it("parses id:token pairs, allowing ':' in tokens", () => {
    const m = parseSensorTokens("a:tok1, b:tok:2");
    expect(m.get("tok1")).toBe("a");
    expect(m.get("tok:2")).toBe("b");
  });

  it("rejects malformed entries", () => {
    expect(() => parseSensorTokens("justatoken")).toThrow();
    expect(() => parseSensorTokens("bad id:tok")).toThrow();
  });
});

describe("buildSensorTokenMatcher", () => {
  const match = buildSensorTokenMatcher(new Map([["token-a", "sensor-a"], ["token-b", "sensor-b"]]));

  it("maps a token to its sensor id", () => {
    expect(match("token-b")).toBe("sensor-b");
  });

  it("returns null for unknown or prefix tokens", () => {
    expect(match("token-")).toBeNull();
    expect(match("")).toBeNull();
  });
});
