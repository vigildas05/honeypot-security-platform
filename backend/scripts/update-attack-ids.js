// Regenerate src/attack/techniques.json from MITRE's Enterprise ATT&CK STIX bundle.
//
// Usage:
//   curl -sSfL -o /tmp/attack/enterprise-attack.json \
//     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//   node scripts/update-attack-ids.js /tmp/attack/enterprise-attack.json
//
// Only active (non-revoked, non-deprecated) techniques and sub-techniques are kept.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const input = process.argv[2];
if (!input) {
  console.error("Usage: node scripts/update-attack-ids.js <enterprise-attack.json>");
  process.exit(1);
}

const bundle = JSON.parse(fs.readFileSync(input, "utf8"));
if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) {
  throw new Error("Not a STIX bundle");
}

const collection = bundle.objects.find((/** @type {any} */ o) => o.type === "x-mitre-collection");
const ID_RE = /^T\d{4}(\.\d{3})?$/;
const TACTIC_RE = /^[a-z-]{1,40}$/;

/** @type {Record<string, { name: string, tactics: string[] }>} */
const techniques = {};
for (const o of bundle.objects) {
  if (o.type !== "attack-pattern" || o.revoked || o.x_mitre_deprecated) continue;
  const ref = (o.external_references ?? []).find((/** @type {any} */ r) => r.source_name === "mitre-attack");
  const id = ref?.external_id;
  if (typeof id !== "string" || !ID_RE.test(id)) continue;
  const name = String(o.name ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, 120);
  const tactics = (o.kill_chain_phases ?? [])
    .filter((/** @type {any} */ p) => p.kill_chain_name === "mitre-attack" && TACTIC_RE.test(p.phase_name))
    .map((/** @type {any} */ p) => p.phase_name)
    .sort();
  techniques[id] = { name, tactics };
}

const sorted = Object.fromEntries(Object.entries(techniques).sort(([a], [b]) => (a < b ? -1 : 1)));
const out = {
  source: "https://github.com/mitre-attack/attack-stix-data (enterprise-attack)",
  attack_version: collection?.x_mitre_version ?? null,
  modified: collection?.modified ?? null,
  count: Object.keys(sorted).length,
  techniques: sorted
};

const here = path.dirname(fileURLToPath(import.meta.url));
const target = path.resolve(here, "../src/attack/techniques.json");
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, `${JSON.stringify(out, null, 1)}\n`);
console.log(`Wrote ${out.count} techniques (ATT&CK v${out.attack_version}) to ${target}`);
