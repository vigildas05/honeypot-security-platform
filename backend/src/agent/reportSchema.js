import { z } from "zod";
import { getTechnique, isKnownTechnique } from "../attack/catalog.js";

// Strict schema for the LLM's report. Unknown keys are rejected, every string
// is length-limited, and lists are bounded. Action *semantics* (which IPs may
// be blocked, TTL caps) are enforced separately by the policy engine.

const text = (/** @type {number} */ max) => z.string().trim().min(1).max(max);

export const llmReportSchema = z
  .object({
    summary: text(1500),
    attacker_profile: text(800),
    techniques: z
      .array(
        z
          .object({
            id: z.string().regex(/^T\d{4}(\.\d{3})?$/, "must be an ATT&CK technique id like T1110 or T1110.003"),
            reasoning: text(500)
          })
          .strict()
      )
      .max(12),
    severity: z.enum(["low", "medium", "high", "critical"]),
    recommended_actions: z
      .array(
        z
          .object({
            type: z.string().max(32),
            target: z.string().max(64).nullable(),
            reason: text(500),
            ttl_hours: z.number().int().min(0).max(100_000).nullable()
          })
          .strict()
      )
      .max(8)
  })
  .strict();

/** @typedef {z.infer<typeof llmReportSchema>} LlmReport */

/**
 * Pull a JSON object out of a model reply. Accepts a bare object or one
 * wrapped in a ```json fence; anything else is invalid.
 * @param {string} reply
 */
export function extractJson(reply) {
  const trimmed = reply.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed);
  const body = fenced ? fenced[1] : trimmed;
  if (!body.startsWith("{") || !body.endsWith("}")) {
    throw new Error("reply is not a single JSON object");
  }
  return JSON.parse(body);
}

/**
 * Full validation of a model reply.
 * @param {string} reply
 * @param {{ canary: string }} ctx
 * @returns {{ ok: true, report: LlmReport } | { ok: false, reason: string, canaryLeak?: boolean }}
 */
export function validateLlmReply(reply, { canary }) {
  if (typeof reply !== "string" || reply.length === 0) return { ok: false, reason: "empty reply" };
  if (reply.length > 20_000) return { ok: false, reason: "reply too long" };

  // Canary check runs on the raw text first, before any parsing, and also
  // catches the token split by whitespace or in a different case.
  if (containsCanary(reply, canary)) {
    return { ok: false, reason: "canary token leaked in model output", canaryLeak: true };
  }

  let data;
  try {
    data = extractJson(reply);
  } catch (error) {
    return { ok: false, reason: `invalid JSON: ${/** @type {Error} */ (error).message.slice(0, 120)}` };
  }

  const parsed = llmReportSchema.safeParse(data);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 5)
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    return { ok: false, reason: `schema violation: ${issues}` };
  }

  const unknown = parsed.data.techniques.map((t) => t.id).filter((id) => !isKnownTechnique(id));
  if (unknown.length > 0) {
    return { ok: false, reason: `unknown ATT&CK technique id(s): ${unknown.slice(0, 5).join(", ")}` };
  }

  return { ok: true, report: parsed.data };
}

/**
 * @param {string} text
 * @param {string} canary
 */
export function containsCanary(text, canary) {
  if (!canary) return false;
  const squash = (/** @type {string} */ s) => s.normalize("NFKC").replace(/[\s\u200b-\u200f\ufeff"'`.,:;_-]/g, "").toLowerCase();
  const secret = canary.split("-").pop() ?? canary;
  const hay = squash(text);
  return hay.includes(squash(canary)) || hay.includes(squash(secret));
}

/**
 * Attach catalog names to validated technique ids.
 * @param {LlmReport["techniques"]} techniques
 */
export function withTechniqueNames(techniques) {
  return techniques.map((t) => ({ ...t, name: getTechnique(t.id)?.name ?? null }));
}
