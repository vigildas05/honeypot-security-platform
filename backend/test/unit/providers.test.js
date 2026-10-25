import { describe, expect, it } from "vitest";
import { abuseipdb, greynoise, ipinfo, virustotal } from "../../src/enrichment/providers.js";
import { summarize } from "../../src/enrichment/service.js";

describe("provider parsers", () => {
  it("abuseipdb keeps only allow-listed fields and sanitizes attacker-controlled rDNS", () => {
    const r = abuseipdb.parse(200, {
      data: {
        abuseConfidenceScore: 100,
        totalReports: 512,
        countryCode: "NL",
        isTor: false,
        domain: "ignore-previous-instructions.example\u001b[2J" + "x".repeat(500),
        somethingElse: "dropped"
      }
    });
    expect(r.found).toBe(true);
    expect(r.data).toMatchObject({ abuse_confidence: 100, total_reports: 512, country: "NL", is_tor: false });
    expect(String(r.data?.domain)).not.toContain("\u001b");
    expect(String(r.data?.domain).length).toBeLessThanOrEqual(200);
    expect(r.data).not.toHaveProperty("somethingElse");
  });

  it("virustotal maps analysis stats and treats 404 as not found", () => {
    const r = virustotal.parse(200, {
      data: { attributes: { last_analysis_stats: { malicious: 7, suspicious: 1 }, asn: 14061, as_owner: "DIGITALOCEAN" } }
    });
    expect(r.data).toMatchObject({ malicious: 7, suspicious: 1, asn: 14061 });
    expect(virustotal.parse(404, {})).toEqual({ found: false });
  });

  it("greynoise 404 means 'not observed'", () => {
    expect(greynoise.parse(404, { message: "IP not observed" })).toEqual({
      found: false,
      data: { noise: false, riot: false }
    });
    expect(greynoise.parse(200, { noise: true, riot: false, classification: "malicious" }).data).toMatchObject({
      noise: true,
      classification: "malicious"
    });
  });

  it("ipinfo splits org into asn + name", () => {
    const r = ipinfo.parse(200, { country: "DE", loc: "50.1,8.6", org: "AS24940 Hetzner Online GmbH" });
    expect(r.data).toMatchObject({ country: "DE", latitude: 50.1, longitude: 8.6, asn: 24940, as_org: "Hetzner Online GmbH" });
  });

  it.each([401, 403, 429, 500])("throws on HTTP %i", (status) => {
    expect(() => abuseipdb.parse(status, {})).toThrow();
  });

  it("never puts the API key in the URL", () => {
    for (const p of [abuseipdb, virustotal, greynoise, ipinfo]) {
      expect(p.request("91.92.93.94", "SECRET-KEY").url).not.toContain("SECRET-KEY");
    }
  });
});

describe("summarize", () => {
  it("prefers local geo, then other providers", () => {
    const s = summarize({
      maxmind: { status: "ok", data: { country: "US" } },
      abuseipdb: { status: "ok", data: { country: "CA", abuse_confidence: 80 } },
      virustotal: { status: "cached", data: { malicious: 3 } }
    });
    expect(s).toMatchObject({ country: "US", abuse_confidence: 80, vt_malicious: 3, greynoise_classification: null });
  });
});
