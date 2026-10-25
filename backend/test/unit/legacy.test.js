import { describe, expect, it } from "vitest";
import { parseEvent } from "../../src/ingest/eventSchema.js";
import { legacyAttackToWireEvent } from "../../src/ingest/legacy.js";

describe("legacyAttackToWireEvent", () => {
  it("maps the old SSH payload", () => {
    const r = parseEvent(
      legacyAttackToWireEvent({
        ip: "::ffff:203.0.113.5",
        protocol: "SSH",
        service: "ssh-honeypot",
        username: "root",
        password: "toor",
        status: "rejected",
        metadata: { authMethod: "password" }
      }),
      "legacy"
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event).toMatchObject({
      protocol: "ssh",
      event_type: "auth_attempt",
      src_ip: "203.0.113.5",
      username: "root",
      auth_success: false,
      auth_method: "password"
    });
  });

  it("maps the old HTTP payload and drops non-string headers", () => {
    const r = parseEvent(
      legacyAttackToWireEvent({
        ip: "198.51.100.1",
        protocol: "HTTP",
        service: "http-honeypot",
        method: "POST",
        path: "/login",
        userAgent: "Mozilla",
        headers: { host: "x", "content-length": 12, cookie: "a=b" },
        metadata: { bodyPreview: "username=admin" }
      }),
      "legacy"
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event.http_headers).toEqual({ host: "x", cookie: "a=b" });
    expect(r.event.raw).toBe("username=admin");
  });

  it("still rejects garbage", () => {
    expect(parseEvent(legacyAttackToWireEvent({ ip: "nope", protocol: "SSH" }), "l").ok).toBe(false);
    expect(parseEvent(legacyAttackToWireEvent({ ip: "1.2.3.4", protocol: "FTP" }), "l").ok).toBe(false);
  });
});
