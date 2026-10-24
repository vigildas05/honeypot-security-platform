// Deterministic ATT&CK technique mapping and severity scoring. No LLM involved.
//
// Every rule is one row in RULES: technique id, tactic, weight, and a `match`
// function that returns human-readable evidence (or null). Severity is the sum
// of matched weights plus enrichment modifiers, with documented floors.

/** @typedef {import("./features.js").IncidentFeatures} IncidentFeatures */

export const DEFAULT_THRESHOLDS = Object.freeze({
  bruteForceMinFailed: 5,
  bruteForceHeavy: 100,
  sprayMinUsernames: 5,
  guessingMinPasswords: 5,
  scanMinPaths: 5
});

/** Known exploit / sensitive-file probe paths (matched case-insensitively). */
export const EXPLOIT_PATH_PATTERNS = [
  /\/cgi-bin\//i,
  /\/\.env(\b|$)/i,
  /\/\.git\//i,
  /\/wp-login\.php/i,
  /\/wp-admin/i,
  /\/xmlrpc\.php/i,
  /\/phpmyadmin/i,
  /\/vendor\/phpunit\//i,
  /\/boaform\//i,
  /\/HNAP1/i,
  /\/GponForm\//i,
  /\/setup\.cgi/i,
  /\/manager\/html/i,
  /\/actuator(\/|$)/i,
  /\/solr\//i,
  /\/druid\//i,
  /\/owa\/|\/autodiscover\//i,
  /\/remote\/fgt_lang/i, // Fortinet SSL-VPN
  /\/\+CSCOE\+\//i, // Cisco ASA
  /\/global-protect\//i, // PAN-OS GlobalProtect
  /\/api\/jsonws/i,
  /\\think\\app|invokefunction/i, // ThinkPHP RCE
  /(\.\.\/|%2e%2e%2f|\.\.%2f)/i, // path traversal
  /\/etc\/passwd/i,
  /\$\{jndi:/i // Log4Shell
];

const DOWNLOAD_RE = /\b(wget|curl|tftp|ftpget|fetch|scp)\b|\/dev\/tcp\//i;
const CRON_RE = /\bcrontab\b|\/etc\/cron|\/var\/spool\/cron/i;
const AUTHKEYS_RE = /authorized_keys/i;
const MINER_RE =
  /\b(xmrig|xmr-stak|minerd|cpuminer|cgminer|kdevtmpfsi|kinsing|c3pool|supportxmr|nanopool|2miners|nicehash|cryptonight|randomx)\b|stratum\+(tcp|ssl):\/\//i;
const SYSINFO_RE = /\b(uname|lscpu|nproc|free)\b|\/proc\/(cpuinfo|meminfo|version)|\/etc\/(os-release|issue)/i;
const USERINFO_RE = /^\s*(whoami|id|w|who|last)\b/i;
const HISTORY_RE = /history\s+-c|unset\s+HISTFILE|HISTFILE=\/dev\/null|rm\s+.*\.bash_history|export\s+HISTSIZE=0/i;
const CHMOD_RE = /\bchmod\s+(\+x|[0-7]*7[0-7]{2}|u\+x|a\+x)/i;

/** @param {string[]} list @param {RegExp} re @param {number} [max] */
function matching(list, re, max = 5) {
  const hits = list.filter((item) => re.test(item));
  return hits.length ? { count: hits.length, samples: [...new Set(hits)].slice(0, max) } : null;
}

/**
 * @typedef {object} Rule
 * @property {string} id ATT&CK technique id
 * @property {string} name
 * @property {string} tactic
 * @property {string} tag incident tag added when the rule fires
 * @property {number} weight severity points
 * @property {(f: IncidentFeatures, t: typeof DEFAULT_THRESHOLDS) => string | null} match evidence or null
 */

/** @type {Rule[]} */
export const RULES = [
  {
    id: "T1595",
    name: "Active Scanning",
    tactic: "reconnaissance",
    tag: "scanning",
    weight: 5,
    match: (f, t) =>
      f.distinct_paths >= t.scanMinPaths ? `${f.distinct_paths} distinct HTTP paths probed` : null
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "initial-access",
    tag: "exploit-attempt",
    weight: 20,
    match: (f) => {
      const blobs = [...f._paths, ...f._http_blobs];
      const hits = blobs.filter((p) => EXPLOIT_PATH_PATTERNS.some((re) => re.test(p)));
      if (!hits.length) return null;
      return `${hits.length} request(s) to known exploit/sensitive paths, e.g. ${[...new Set(f._paths.filter((p) => EXPLOIT_PATH_PATTERNS.some((re) => re.test(p))))].slice(0, 3).join(", ") || "(in headers)"}`;
    }
  },
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "credential-access",
    tag: "brute-force",
    weight: 15,
    match: (f, t) => {
      const failed = f.failed_logins + f.http_credential_posts;
      return failed >= t.bruteForceMinFailed ? `${failed} failed login attempts` : null;
    }
  },
  {
    id: "T1110.001",
    name: "Password Guessing",
    tactic: "credential-access",
    tag: "brute-force",
    weight: 5,
    match: (f, t) =>
      f.distinct_passwords >= t.guessingMinPasswords && f.distinct_usernames <= 2
        ? `${f.distinct_passwords} passwords tried against ${f.distinct_usernames} username(s)`
        : null
  },
  {
    id: "T1110.003",
    name: "Password Spraying",
    tactic: "credential-access",
    tag: "brute-force",
    weight: 5,
    match: (f, t) =>
      f.distinct_usernames >= t.sprayMinUsernames &&
      f.distinct_passwords <= Math.max(2, Math.floor(f.distinct_usernames / 5))
        ? `${f.distinct_usernames} usernames tried with only ${f.distinct_passwords} password(s)`
        : null
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "initial-access",
    tag: "credential-success",
    weight: 25,
    match: (f) => (f.successful_logins > 0 ? `${f.successful_logins} successful login(s) to the fake SSH shell` : null)
  },
  {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    tactic: "execution",
    tag: "interactive-session",
    weight: 15,
    match: (f) => (f.command_count > 0 ? `${f.command_count} shell command(s) issued` : null)
  },
  {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "discovery",
    tag: "discovery",
    weight: 5,
    match: (f) => {
      const m = matching(f._commands, SYSINFO_RE);
      return m ? `${m.count} system discovery command(s)` : null;
    }
  },
  {
    id: "T1033",
    name: "System Owner/User Discovery",
    tactic: "discovery",
    tag: "discovery",
    weight: 3,
    match: (f) => {
      const m = matching(f._commands, USERINFO_RE);
      return m ? `${m.count} user discovery command(s)` : null;
    }
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "command-and-control",
    tag: "malware-download",
    weight: 25,
    match: (f) => {
      const m = matching(f._commands, DOWNLOAD_RE);
      return m ? `${m.count} download command(s) (wget/curl/tftp/...)` : null;
    }
  },
  {
    id: "T1222.002",
    name: "Linux and Mac File and Directory Permissions Modification",
    tactic: "defense-impairment",
    tag: "defense-evasion",
    weight: 5,
    match: (f) => {
      const m = matching(f._commands, CHMOD_RE);
      return m ? `${m.count} chmod making files executable` : null;
    }
  },
  {
    id: "T1070.003",
    name: "Indicator Removal: Clear Command History",
    tactic: "stealth",
    tag: "defense-evasion",
    weight: 10,
    match: (f) => {
      const m = matching(f._commands, HISTORY_RE);
      return m ? `${m.count} attempt(s) to clear or disable shell history` : null;
    }
  },
  {
    id: "T1053.003",
    name: "Scheduled Task/Job: Cron",
    tactic: "persistence",
    tag: "persistence",
    weight: 25,
    match: (f) => {
      const m = matching(f._commands, CRON_RE);
      return m ? `${m.count} crontab modification command(s)` : null;
    }
  },
  {
    id: "T1098.004",
    name: "Account Manipulation: SSH Authorized Keys",
    tactic: "persistence",
    tag: "persistence",
    weight: 30,
    match: (f) => {
      const m = matching(f._commands, AUTHKEYS_RE);
      return m ? `${m.count} command(s) touching authorized_keys` : null;
    }
  },
  {
    id: "T1496",
    name: "Resource Hijacking",
    tactic: "impact",
    tag: "cryptomining",
    weight: 30,
    match: (f) => {
      const m = matching(f._commands, MINER_RE);
      return m ? `${m.count} command(s) referencing cryptominers or mining pools` : null;
    }
  }
];

export const SEVERITY_LEVELS = /** @type {const} */ (["low", "medium", "high", "critical"]);

/**
 * Score thresholds (inclusive lower bounds).
 *   low: < 20   medium: 20-44   high: 45-69   critical: >= 70
 */
export const SEVERITY_THRESHOLDS = { medium: 20, high: 45, critical: 70 };

/** @param {number} score */
export function levelForScore(score) {
  if (score >= SEVERITY_THRESHOLDS.critical) return "critical";
  if (score >= SEVERITY_THRESHOLDS.high) return "high";
  if (score >= SEVERITY_THRESHOLDS.medium) return "medium";
  return "low";
}

/**
 * @param {IncidentFeatures} features
 * @param {Partial<{ abuse_confidence: number | null, vt_malicious: number | null, greynoise_classification: string | null, greynoise_riot: boolean | null }>} [intel]
 * @param {Partial<typeof DEFAULT_THRESHOLDS>} [thresholds]
 */
export function evaluateIncident(features, intel = {}, thresholds = {}) {
  const t = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const techniques = [];
  const tags = new Set();
  const reasons = [];
  let score = 0;

  for (const rule of RULES) {
    const evidence = rule.match(features, t);
    if (!evidence) continue;
    techniques.push({ id: rule.id, name: rule.name, tactic: rule.tactic, evidence, source: "rules" });
    tags.add(rule.tag);
    score += rule.weight;
    reasons.push(`+${rule.weight} ${rule.id} ${rule.name}`);
  }

  const failed = features.failed_logins + features.http_credential_posts;
  if (failed >= t.bruteForceHeavy) {
    score += 5;
    reasons.push(`+5 heavy brute force (${failed} attempts)`);
  }

  // Threat-intel modifiers (only when a provider actually answered).
  if ((intel.abuse_confidence ?? 0) >= 75) {
    score += 10;
    reasons.push(`+10 AbuseIPDB confidence ${intel.abuse_confidence}`);
  }
  if ((intel.vt_malicious ?? 0) >= 3) {
    score += 10;
    reasons.push(`+10 VirusTotal: ${intel.vt_malicious} engines flag this IP`);
  }
  if (intel.greynoise_classification === "malicious") {
    score += 5;
    reasons.push("+5 GreyNoise classifies as malicious");
  }
  if (intel.greynoise_riot || intel.greynoise_classification === "benign") {
    score -= 10;
    reasons.push("-10 GreyNoise: known benign scanner/business service");
  }
  score = Math.max(0, score);

  let level = levelForScore(score);
  const ids = new Set(techniques.map((x) => x.id));
  const postCompromise = ["T1105", "T1053.003", "T1098.004", "T1496"].some((id) => ids.has(id));

  // Floors: a successful login plus payload/persistence is always critical,
  // and any successful login is at least high.
  if (ids.has("T1078") && postCompromise && level !== "critical") {
    level = "critical";
    reasons.push("floor: successful login followed by payload/persistence => critical");
  } else if (ids.has("T1078") && (level === "low" || level === "medium")) {
    level = "high";
    reasons.push("floor: successful login => at least high");
  }

  return { techniques, tags: [...tags].sort(), severity: level, score, reasons };
}
