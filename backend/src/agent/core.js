// SOC agent core: given an incident and its events, produce a validated report
// and policy-checked action proposals. All I/O is injected (LLM client, budget,
// policy), so the adversarial test suite runs fully offline.

import { attackerFields, scanForInjection } from "./injection.js";
import { buildIncidentSummary, buildPrompt, newCanary, retryMessage } from "./prompt.js";
import { validateLlmReply, withTechniqueNames } from "./reportSchema.js";
import { buildRuleReport, ruleActions } from "./ruleReport.js";

export const MAX_LLM_ATTEMPTS = 2; // first try + one retry

/**
 * @typedef {{ attempt: number, outcome: "valid" | "invalid" | "canary_leak" | "error", detail: string | null, latencyMs: number | null, tokensIn: number, tokensOut: number, model: string | null }} CallRecord
 * @typedef {{ tryReserveCall: () => Promise<boolean>, recordTokens: (n: number) => Promise<void> }} Budget
 */

/**
 * @param {{
 *   incident: { id: string, src_ip: string, first_seen: any, last_seen: any, event_count: number, severity: string, severity_score: number, techniques: any[], tags: string[], stats: any },
 *   events: import("../correlation/features.js").EventRow[],
 *   llm: import("./llmClient.js").LlmClient | null,
 *   budget: Budget,
 *   policy: ReturnType<typeof import("./policy.js").createPolicyEngine>,
 *   canaryFactory?: () => string
 * }} input
 */
export async function runAgent({ incident, events, llm, budget, policy, canaryFactory = newCanary }) {
  const injectionFindings = scanForInjection(attackerFields(events));
  const tags = injectionFindings.length && !incident.tags.includes("prompt-injection-attempt")
    ? [...incident.tags, "prompt-injection-attempt"]
    : incident.tags;
  const summary = buildIncidentSummary({ incident: { ...incident, tags }, injectionSignals: injectionFindings });

  /** @type {CallRecord[]} */
  const calls = [];
  let canaryLeak = false;
  /** @type {import("./reportSchema.js").LlmReport | null} */
  let llmReport = null;
  /** @type {string | null} */
  let fallbackReason = null;

  if (!llm) {
    fallbackReason = "llm_not_configured";
  } else {
    /** @type {string | null} */
    let lastError = null;
    for (let attempt = 1; attempt <= MAX_LLM_ATTEMPTS; attempt++) {
      if (!(await budget.tryReserveCall())) {
        fallbackReason = "budget_exhausted";
        break;
      }
      // Fresh canary and delimiter nonce on every call.
      const canary = canaryFactory();
      const { system, user } = buildPrompt({ summary, canary });
      /** @type {import("./llmClient.js").ChatMessage[]} */
      const messages = [
        { role: "system", content: system },
        { role: "user", content: user }
      ];
      if (lastError) messages.push({ role: "user", content: retryMessage(lastError) });

      try {
        const completion = await llm.complete(messages);
        await budget.recordTokens(completion.tokensIn + completion.tokensOut);
        const result = validateLlmReply(completion.text, { canary });
        const record = {
          attempt,
          latencyMs: completion.latencyMs,
          tokensIn: completion.tokensIn,
          tokensOut: completion.tokensOut,
          model: completion.model
        };
        if (result.ok) {
          calls.push({ ...record, outcome: "valid", detail: null });
          llmReport = result.report;
          break;
        }
        if (result.canaryLeak) {
          calls.push({ ...record, outcome: "canary_leak", detail: result.reason });
          canaryLeak = true;
          fallbackReason = "canary_leak";
          break; // never retry a model that just leaked the canary
        }
        calls.push({ ...record, outcome: "invalid", detail: result.reason });
        lastError = result.reason;
      } catch (error) {
        const detail = /** @type {Error} */ (error).message.slice(0, 200);
        calls.push({ attempt, outcome: "error", detail, latencyMs: null, tokensIn: 0, tokensOut: 0, model: llm.model });
        lastError = "the request failed; reply with the JSON object only";
      }
    }
    // Every attempt failed at the request level (HTTP error, timeout, unknown
    // model): the model never answered, so nothing failed validation.
    if (!llmReport && !fallbackReason) {
      fallbackReason = calls.length > 0 && calls.every((c) => c.outcome === "error") ? "llm_error" : "validation_failed";
    }
  }

  const incidentIps = [incident.src_ip];
  if (llmReport) {
    const { allowed, violations } = policy.evaluate(llmReport.recommended_actions, { incidentIps });
    return {
      source: /** @type {const} */ ("llm"),
      aiGenerated: true,
      validationStatus: calls.length > 1 ? "retried_valid" : "valid",
      fallbackReason: null,
      report: { ...llmReport, techniques: withTechniqueNames(llmReport.techniques) },
      actions: allowed,
      violations,
      injectionFindings,
      tags,
      canaryLeak,
      calls
    };
  }

  const report = buildRuleReport({ ...incident, tags });
  const { allowed, violations } = policy.evaluate(ruleActions(incident), { incidentIps });
  return {
    source: /** @type {const} */ ("rules"),
    aiGenerated: false,
    validationStatus: "fallback",
    fallbackReason,
    report: { ...report, techniques: withTechniqueNames(report.techniques) },
    actions: allowed,
    violations,
    injectionFindings,
    tags,
    canaryLeak,
    calls
  };
}

/**
 * Has the incident changed enough since the last analysis to re-run the agent?
 * @param {{ event_count: number, analyzed_event_count: number, analyzed_signature: string | null, last_analyzed_at: Date | null }} incident
 * @param {string} signature current signature
 * @param {number} growthFactor
 */
export function isSignificantUpdate(incident, signature, growthFactor) {
  if (!incident.last_analyzed_at) return true;
  if (incident.analyzed_signature !== signature) return true;
  return incident.event_count >= Math.max(incident.analyzed_event_count * growthFactor, incident.analyzed_event_count + 10);
}

/**
 * @param {{ severity: string, techniques: { id: string }[], tags: string[] }} incident
 */
export function incidentSignature(incident) {
  const ids = (incident.techniques ?? []).map((t) => t.id).sort().join(",");
  return `${incident.severity}|${ids}|${[...(incident.tags ?? [])].sort().join(",")}`;
}
