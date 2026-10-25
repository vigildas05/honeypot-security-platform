import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config/env.js";

describe("database URL selection", () => {
  it("uses DATABASE_URL_UNPOOLED as the direct URL when Neon provides it", () => {
    const cfg = loadConfig({ DATABASE_URL: "postgres://u:p@ep-x-pooler.neon.tech/db", DATABASE_URL_UNPOOLED: "postgres://u:p@ep-x.neon.tech/db" });
    expect(cfg.databaseUrl).toContain("-pooler");
    expect(cfg.databaseUrlDirect).not.toContain("-pooler");
  });

  it("falls back to DATABASE_URL for both when no unpooled URL is set", () => {
    const cfg = loadConfig({ DATABASE_URL: "postgres://u:p@localhost/db" });
    expect(cfg.databaseUrlDirect).toBe(cfg.databaseUrl);
  });

  it("ignores an empty DATABASE_URL_UNPOOLED", () => {
    const cfg = loadConfig({ DATABASE_URL: "postgres://u:p@localhost/db", DATABASE_URL_UNPOOLED: "" });
    expect(cfg.databaseUrlDirect).toBe("postgres://u:p@localhost/db");
  });
});

describe("withVerifiedTls", async () => {
  const { withVerifiedTls } = await import("../../src/db/pool.js");

  it.each(["require", "prefer", "verify-ca"])("upgrades sslmode=%s to verify-full, keeping other params", (mode) => {
    const out = withVerifiedTls(`postgresql://u:p@ep-x.neon.tech/db?sslmode=${mode}&channel_binding=require`);
    expect(new URL(out).searchParams.get("sslmode")).toBe("verify-full");
    expect(new URL(out).searchParams.get("channel_binding")).toBe("require");
  });

  it("leaves URLs without sslmode (local dev) and verify-full/disable untouched", () => {
    expect(withVerifiedTls("postgresql://u:p@localhost:5432/db")).toBe("postgresql://u:p@localhost:5432/db");
    expect(withVerifiedTls("postgresql://h/db?sslmode=verify-full")).toBe("postgresql://h/db?sslmode=verify-full");
    expect(withVerifiedTls("postgresql://h/db?sslmode=disable")).toBe("postgresql://h/db?sslmode=disable");
  });
});

describe("database URL hygiene", () => {
  const good = "postgresql://u:secretpw@ep-x.neon.tech/db?sslmode=require";
  const prod = { NODE_ENV: "production", JWT_SECRET_KEY: "x".repeat(40), SENSOR_TOKENS: `s:${"t".repeat(30)}` };

  it("strips surrounding quotes and whitespace from pasted URLs", () => {
    expect(loadConfig({ DATABASE_URL: `  "${good}"\n` }).databaseUrl).toBe(good);
    expect(loadConfig({ DATABASE_URL: good, DATABASE_URL_UNPOOLED: ` '${good}' ` }).databaseUrlDirect).toBe(good);
  });

  it.each([
    ["a DATABASE_URL= prefix", `DATABASE_URL=${good}`],
    ["a psql prefix", `psql '${good}'`],
    ["a line break inside", good.replace("?", "?\n")],
    ["no scheme", "ep-x.neon.tech/db"]
  ])("fails clearly on %s, without echoing the password", (_name, value) => {
    let message = "";
    try { loadConfig({ ...prod, DATABASE_URL: value }); } catch (e) { message = String(e); }
    expect(message).toMatch(/DATABASE_URL must be one line starting with postgres/);
    expect(message).not.toContain("secretpw");
  });
});
