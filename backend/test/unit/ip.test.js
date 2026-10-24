import { describe, expect, it } from "vitest";
import { buildCidrMatcher, classifyIp } from "../../src/lib/ip.js";

describe("classifyIp", () => {
  it.each([
    ["10.1.2.3", "private"],
    ["172.31.255.255", "private"],
    ["192.168.0.1", "private"],
    ["100.64.0.1", "cgnat"],
    ["100.127.255.254", "cgnat"],
    ["127.0.0.1", "loopback"],
    ["169.254.169.254", "link-local"],
    ["224.0.0.251", "multicast"],
    ["239.255.255.250", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "reserved"], // inside 240.0.0.0/4
    ["0.0.0.0", "unspecified"],
    ["192.0.2.10", "documentation"],
    ["203.0.113.5", "documentation"],
    ["::1", "loopback"],
    ["::", "unspecified"],
    ["fe80::1", "link-local"],
    ["fd12:3456::1", "private"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    // Embedded IPv4 is classified as the IPv4 it carries:
    ["::ffff:10.0.0.1", "private"],
    ["::ffff:7f00:1", "loopback"],
    ["64:ff9b::a00:1", "private"]
  ])("%s is %s (not public)", (ip, category) => {
    const c = classifyIp(ip);
    expect(c.category).toBe(category);
    expect(c.public).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "91.92.93.94", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"])(
    "%s is public",
    (ip) => {
      expect(classifyIp(ip)).toMatchObject({ valid: true, public: true, category: "public" });
    }
  );

  it.each(["", "localhost", "1.2.3", "8.8.8.8/32", "::ffff:999.1.1.1", "1.1.1.1 "])(
    "%j is handled safely",
    (ip) => {
      const c = classifyIp(ip);
      if (c.valid) expect(c.ip).toBe("1.1.1.1"); // only the trailing-space case normalizes
      else expect(c.public).toBe(false);
    }
  );
});

describe("buildCidrMatcher", () => {
  const match = buildCidrMatcher(["8.8.8.8", "1.1.1.0/24", "2606:4700:4700::/48"]);

  it("matches single addresses, subnets and IPv6", () => {
    expect(match("8.8.8.8")).toBe(true);
    expect(match("1.1.1.200")).toBe(true);
    expect(match("::ffff:1.1.1.1")).toBe(true);
    expect(match("2606:4700:4700::1001")).toBe(true);
    expect(match("8.8.4.4")).toBe(false);
  });

  it("throws on invalid entries instead of silently ignoring them", () => {
    expect(() => buildCidrMatcher(["8.8.8.8/33"])).toThrow();
    expect(() => buildCidrMatcher(["dns.google"])).toThrow();
  });
});
