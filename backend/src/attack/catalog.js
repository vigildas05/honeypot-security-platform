import { createRequire } from "node:module";

// Bundled MITRE Enterprise ATT&CK technique list.
// Regenerate with scripts/update-attack-ids.js.
const require = createRequire(import.meta.url);
/** @type {{ attack_version: string, count: number, techniques: Record<string, { name: string, tactics: string[] }> }} */
const catalog = require("./techniques.json");

const ID_RE = /^T\d{4}(\.\d{3})?$/;

export const ATTACK_VERSION = catalog.attack_version;

/** @param {unknown} id */
export function isKnownTechnique(id) {
  return typeof id === "string" && ID_RE.test(id) && Object.hasOwn(catalog.techniques, id);
}

/** @param {string} id */
export function getTechnique(id) {
  return isKnownTechnique(id) ? { id, ...catalog.techniques[id] } : null;
}

/** @param {string} id */
export function attackUrl(id) {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}
