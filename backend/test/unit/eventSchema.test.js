import { describe, expect, it } from "vitest";
import {
  FIELD_LIMITS,
  normalizeIp,
  parseEvent,
  sanitizeString
} from "../../src/ingest/eventSchema.js";

const now = () => new Date().toISOString();

const sshAuth = (overrides = {}) => ({
  timestamp: now(),
  protocol: "ssh",
  event_type: "auth_attempt",
  src_ip: "203.0.113.7",
  src_port: 51234,
  session_id: "abc-123",
  ssh: { username: "root", password: "123456", auth_method: "password", auth_success: false },
  ...overrides
});

const httpReq = (overrides = {}) => ({
  timestamp: now(),
  protocol: "http",
  event_type: "request",
  src_ip: "198.51.100.20",
  http: {
    method: "GET",
    path: "/.env",
    user_agent: "curl/8.0",
    headers: { host: "example.com", "user-agent": "curl/8.0", "x-secret-internal": "drop me" }
  },
  ...overrides
});

describe("normalizeIp", () => {
  it("collapses IPv4-mapped IPv6 and strips zone ids", () => {
    expect(normalizeIp("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(normalizeIp("FE80::1%eth0")).toBe("fe80::1");
  });

  it("rejects non-literals", () => {
    expect(normalizeIp("example.com")).toBeNull();
    expect(normalizeIp("1.2.3.4; DROP TABLE events")).toBeNull();
    expect(normalizeIp("999.1.1.1")).toBeNull();
  });
});

describe("sanitizeString", () => {
  it("escapes NUL and terminal control characters", () => {
    expect(sanitizeString("a\u0000b\u001b[31m", 100).value).toBe("a\\x00b\\x1b[31m");
  });

  it("escapes bidi override characters (Trojan Source style spoofing)", () => {
    expect(sanitizeString("admin\u202egnp.exe", 100).value).toBe("admin\\u{202e}gnp.exe");
    expect(sanitizeString("a\u2066b\u2069", 100).value).toBe("a\\u{2066}b\\u{2069}");
  });

  it("keeps tabs and newlines", () => {
    expect(sanitizeString("a\tb\nc", 100).value).toBe("a\tb\nc");
  });

  it("replaces lone surrogates", () => {
    expect(sanitizeString("x\ud800y", 100).value).toBe("x\ufffdy");
  });

  it("truncates without splitting a surrogate pair", () => {
    const r = sanitizeString(`ab${String.fromCodePoint(0x1f600)}cd`, 3);
    expect(r).toEqual({ value: "ab", truncated: true });
  });
});

describe("parseEvent", () => {
  it("accepts a valid ssh auth attempt and binds the sensor id from the token", () => {
    const r = parseEvent(sshAuth(), "sensor-1");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event).toMatchObject({
      sensor_id: "sensor-1",
      protocol: "ssh",
      src_ip: "203.0.113.7",
      username: "root",
      password: "123456",
      auth_success: false,
      truncated: false
    });
  });

  it("rejects a payload sensor_id that doesn't match the token", () => {
    const r = parseEvent(sshAuth({ sensor_id: "someone-else" }), "sensor-1");
    expect(r).toEqual({ ok: false, error: expect.stringContaining("sensor_id") });
  });

  it("truncates oversized attacker strings and flags the event", () => {
    const r = parseEvent(
      sshAuth({ ssh: { username: "u".repeat(5000), password: "p" } }),
      "s"
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event.username).toHaveLength(FIELD_LIMITS.username);
    expect(r.event.truncated).toBe(true);
  });

  it("rejects absurdly large strings outright", () => {
    const r = parseEvent(sshAuth({ ssh: { command: "x".repeat(20_000) } }), "s");
    expect(r.ok).toBe(false);
  });

  it("keeps only allowlisted headers", () => {
    const r = parseEvent(httpReq(), "s");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event.http_headers).toEqual({ host: "example.com", "user-agent": "curl/8.0" });
    expect(r.event.user_agent).toBe("curl/8.0");
  });

  it("caps the number of stored headers", () => {
    /** @type {Record<string, string>} */
    const headers = {};
    for (const name of ["host", "accept", "accept-language", "accept-encoding", "cookie", "origin",
      "referer", "connection", "upgrade", "content-type", "content-length", "authorization",
      "x-requested-with", "x-forwarded-for", "x-real-ip", "forwarded", "via", "user-agent"]) {
      headers[name] = "v";
    }
    const r = parseEvent(httpReq({ http: { headers } }), "s");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(Object.keys(r.event.http_headers).length).toBeLessThanOrEqual(FIELD_LIMITS.max_headers);
  });

  it.each([
    ["missing src_ip", { src_ip: undefined }],
    ["hostname src_ip", { src_ip: "evil.example" }],
    ["bad port", { src_port: 70000 }],
    ["unknown protocol", { protocol: "ftp" }],
    ["bad event_type", { event_type: "request" }],
    ["unparseable timestamp", { timestamp: "yesterday" }],
    ["future timestamp", { timestamp: new Date(Date.now() + 3600_000).toISOString() }],
    ["ancient timestamp", { timestamp: "2001-01-01T00:00:00Z" }],
    ["unknown top-level key", { is_admin: true }],
    ["session id with spaces", { session_id: "a b" }]
  ])("rejects malformed event: %s", (_name, overrides) => {
    expect(parseEvent(sshAuth(overrides), "s").ok).toBe(false);
  });

  it("rejects http fields on an ssh event", () => {
    const r = parseEvent({ ...sshAuth(), http: { path: "/" } }, "s");
    expect(r.ok).toBe(false);
  });

  it("rejects non-object input", () => {
    expect(parseEvent(null, "s").ok).toBe(false);
    expect(parseEvent("hello", "s").ok).toBe(false);
    expect(parseEvent([1, 2], "s").ok).toBe(false);
  });

  it("never echoes attacker values in error messages", () => {
    const marker = "ATTACKER_MARKER_<script>";
    const r = parseEvent(sshAuth({ src_ip: marker, protocol: "ssh" }), "s");
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).not.toContain(marker);
  });
});
