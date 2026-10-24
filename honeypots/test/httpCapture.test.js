import { describe, expect, it } from "vitest";
import { buildHttpEvent, extractCredentials } from "../http/src/capture.js";

/** @param {Partial<Record<string, any>>} overrides */
const fakeReq = (overrides = {}) =>
  /** @type {any} */ ({
    method: "POST",
    originalUrl: "/login",
    httpVersion: "1.1",
    headers: {
      "user-agent": "python-requests/2.31",
      "x-forwarded-for": "8.8.8.8",
      host: "victim.example"
    },
    socket: { remoteAddress: "::ffff:203.0.113.44", remotePort: 40001 },
    body: { username: "admin", password: "hunter2" },
    ...overrides
  });

describe("buildHttpEvent", () => {
  it("takes src_ip from the socket and ignores spoofed X-Forwarded-For", () => {
    const e = buildHttpEvent(fakeReq());
    expect(e.src_ip).toBe("203.0.113.44");
    expect(e.src_port).toBe(40001);
    // Kept only as evidence:
    expect(e.http.headers["x-forwarded-for"]).toBe("8.8.8.8");
  });

  it("captures credentials from form bodies", () => {
    const e = buildHttpEvent(fakeReq());
    expect(e.http).toMatchObject({ method: "POST", path: "/login", username: "admin", password: "hunter2" });
  });
});

describe("extractCredentials", () => {
  it("reads JSON and urlencoded strings", () => {
    expect(extractCredentials('{"user":"a","pass":"b"}')).toEqual({ username: "a", password: "b" });
    expect(extractCredentials("log=wp&pwd=x")).toEqual({ username: "wp", password: "x" });
  });

  it("ignores non-string fields and junk", () => {
    expect(extractCredentials('{"username":{"$ne":null}}')).toEqual({ username: undefined, password: undefined });
    expect(extractCredentials("{not json")).toEqual({});
    expect(extractCredentials(null)).toEqual({});
  });
});
