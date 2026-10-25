// Heuristic prompt-injection scanner for attacker-controlled fields.
//
// This is a *signal*, not the defense. The defenses are structural: attacker
// data only ever sits inside a delimited, JSON-escaped data block; the model's
// output is schema-validated; and every action goes through the policy engine
// and a human. Detection lets us tag and surface the attempt on the dashboard.

export const INJECTION_TAG = "prompt-injection-attempt";

/** @type {{ id: string, re: RegExp }[]} */
export const INJECTION_PATTERNS = [
  { id: "ignore_instructions", re: /\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the|system)\b.{0,30}\b(instructions?|prompts?|rules?|directives?|guidelines?|context)\b/i },
  { id: "new_instructions", re: /\b(new|updated|real|actual)\s+(system\s+)?(instructions?|prompt|task)\s*[:=]/i },
  { id: "role_override", re: /\b(you are now|from now on,? you|act as (an?|the)|pretend (to be|you are)|roleplay as|developer mode|DAN mode|jailbreak)\b/i },
  { id: "prompt_extraction", re: /\b(reveal|show|print|repeat|output|leak|dump|tell me)\b.{0,30}\b(system prompt|your (instructions|prompt|rules)|the prompt|hidden (instructions|prompt)|canary|(confidential|secret|hidden) (token|key))\b/i },
  { id: "chat_markup", re: /<\|?(im_start|im_end|system|endoftext|assistant|user)\|?>|\[\/?INST\]|<<\/?SYS>>|^\s*(###\s*)?(system|assistant)\s*:/im },
  { id: "fake_delimiter", re: /<\/?\s*(untrusted|incident|data|system|instructions?)[_\s-]?(data|block|prompt)?\s*>|<<<\s*(END_)?(INCIDENT|UNTRUSTED)/i },
  { id: "action_injection", re: /\b(block_ip|recommended_actions|watchlist|no_action)\b|"type"\s*:\s*"(block|allow|whitelist)/i },
  { id: "block_request", re: /\b(block|ban|blacklist|firewall|blocklist)\b.{0,30}\b(\d{1,3}(\.\d{1,3}){3}|ip|address|everyone|all)\b/i },
  { id: "llm_address", re: /\b(dear|hey|hello|attention)\s+(ai|llm|assistant|model|gpt|claude|gemini|chatbot|analyst bot)\b|\b(as an ai|ai (agent|analyst|model)s?)\b.{0,20}\b(must|should|will)\b/i },
  { id: "severity_manipulation", re: /\b(mark|classify|rate|report)\b.{0,30}\b(as )?(benign|safe|harmless|false positive|low severity|not malicious)\b/i }
];

const ZERO_WIDTH = /[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]/g;

/**
 * Fold common obfuscations before matching: NFKC (fullwidth letters etc.),
 * zero-width chars, URL-encoding, and separators used to split keywords.
 * @param {string} text
 */
export function normalizeForScan(text) {
  let out = text.normalize("NFKC").replace(ZERO_WIDTH, "");
  if (/%[0-9a-f]{2}/i.test(out)) {
    try {
      out = decodeURIComponent(out.replace(/\+/g, " "));
    } catch {
      out = out.replace(/%20/gi, " ");
    }
  }
  // Collapse escaped whitespace and underscore/dot word splitting: "ignore_previous.instructions"
  return out.replace(/\\[nrt]/g, " ").replace(/(?<=[a-z])[_.](?=[a-z])/gi, " ");
}

/**
 * @typedef {{ field: string, pattern: string, sample: string }} InjectionFinding
 */

/**
 * @param {{ field: string, value: string | null | undefined }[]} items
 * @param {{ maxFindings?: number }} [options]
 * @returns {InjectionFinding[]}
 */
export function scanForInjection(items, { maxFindings = 20 } = {}) {
  /** @type {InjectionFinding[]} */
  const findings = [];
  const seen = new Set();
  for (const { field, value } of items) {
    if (!value || typeof value !== "string") continue;
    // Match against both the raw and the de-obfuscated text: normalization
    // helps with split/encoded keywords but can break literal markup tokens.
    const raw = value.slice(0, 8192);
    const normalized = normalizeForScan(raw);
    for (const { id, re } of INJECTION_PATTERNS) {
      if (!re.test(raw) && !re.test(normalized)) continue;
      const key = `${field}:${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ field, pattern: id, sample: value.slice(0, 160) });
      if (findings.length >= maxFindings) return findings;
    }
  }
  return findings;
}

/**
 * Collect every attacker-controlled string from event rows.
 * @param {import("../correlation/features.js").EventRow[]} events
 */
export function attackerFields(events) {
  /** @type {{ field: string, value: string | null | undefined }[]} */
  const items = [];
  for (const e of events) {
    items.push(
      { field: "username", value: e.username },
      { field: "password", value: e.password },
      { field: "command", value: e.command },
      { field: "http_path", value: e.http_path },
      { field: "user_agent", value: e.user_agent }
    );
    for (const [name, value] of Object.entries(e.http_headers ?? {})) {
      items.push({ field: `header:${name}`, value });
    }
  }
  return items;
}
