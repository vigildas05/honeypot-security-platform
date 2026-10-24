import { describe, expect, it } from "vitest";
import { maskIp, maskIpFields } from "../../src/lib/mask.js";

describe("maskIp", () => {
  it.each([
    ["91.92.93.94", "91.92.93.x"],
    ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::x"],
    ["2001:db8::5", "2001:db8::x"],
    ["not-an-ip", "x"]
  ])("%s -> %s", (ip, masked) => {
    expect(maskIp(ip)).toBe(masked);
  });

  it("masks nested ip fields but leaves other data alone", () => {
    expect(maskIpFields({ topIps: [{ ip: "1.2.3.4", count: 3 }], incident: { src_ip: "5.6.7.8", severity: "high" } })).toEqual({
      topIps: [{ ip: "1.2.3.x", count: 3 }],
      incident: { src_ip: "5.6.7.x", severity: "high" }
    });
  });
});
