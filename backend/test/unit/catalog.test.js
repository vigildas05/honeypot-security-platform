import { describe, expect, it } from "vitest";
import { ATTACK_VERSION, attackUrl, getTechnique, isKnownTechnique } from "../../src/attack/catalog.js";

describe("ATT&CK catalog", () => {
  it("is the bundled enterprise list", () => {
    expect(ATTACK_VERSION).toBeTruthy();
    expect(getTechnique("T1110.003")?.name).toBe("Password Spraying");
  });

  it.each(["T9999", "T1110.999", "t1110", "T1110 ", "__proto__", "constructor", "", null, 1110])(
    "rejects unknown or malformed id %j",
    (id) => {
      expect(isKnownTechnique(id)).toBe(false);
    }
  );

  it("builds attack.mitre.org URLs for sub-techniques", () => {
    expect(attackUrl("T1059.004")).toBe("https://attack.mitre.org/techniques/T1059/004/");
  });
});
