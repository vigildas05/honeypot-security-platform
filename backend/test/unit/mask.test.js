import { describe, expect, it } from "vitest";
import { maskIp, maskIpFields, maskIpsInText } from "../../src/lib/mask.js";

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

describe("maskIpsInText", () => {
  it.each([
    ["14 events from 91.92.93.94. 8 failed logins", "14 events from 91.92.93.x. 8 failed logins"],
    ["block 8.8.8.8 and 1.1.1.1!", "block 8.8.8.x and 1.1.1.x!"],
    ["from 2001:db8:1:2::5 via ::ffff:10.0.0.1", "from 2001:db8:1:2::x via ::x"],
    ["2026-10-25T02:26:08.000Z", "2026-10-25T02:26:08.000Z"],
    ["T1059.004 and v1.2.3 and 999.1.1.1.1", "T1059.004 and v1.2.3 and 999.1.1.1.1"],
    ["mac aa:bb:cc and time 12:30:45", "mac aa:bb:cc and time 12:30:45"]
  ])("%j", (input, expected) => {
    expect(maskIpsInText(input)).toBe(expected);
  });

  it("is applied to every nested string for demo payloads", () => {
    const masked = maskIpFields({ report: { summary: "events from 91.92.93.94", techniques: [{ evidence: "seen 91.92.93.94" }] } });
    expect(JSON.stringify(masked)).not.toContain("91.92.93.94");
  });
});
