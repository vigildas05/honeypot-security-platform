// Deterministic, template-based report. Used when no LLM is configured, the
// daily budget is spent, or the model's output fails validation twice.
// Contains no attacker strings beyond counts and the source IP.

/**
 * @param {{ src_ip: string, event_count: number, severity: string, techniques: any[], stats: any, tags: string[] }} incident
 */
export function buildRuleReport(incident) {
  const f = incident.stats?.features ?? {};
  const intel = incident.stats?.intel ?? {};
  const techniques = (incident.techniques ?? []).map((/** @type {any} */ t) => ({
    id: t.id,
    reasoning: `Rule match: ${t.evidence}`
  }));

  const parts = [`${incident.event_count} events from ${incident.src_ip}.`];
  if (f.failed_logins) parts.push(`${f.failed_logins} failed logins across ${f.distinct_usernames} usernames and ${f.distinct_passwords} passwords.`);
  if (f.successful_logins) parts.push(`${f.successful_logins} successful login(s) into the fake shell.`);
  if (f.command_count) parts.push(`${f.command_count} shell commands (${f.distinct_commands} distinct).`);
  if (f.http_requests) parts.push(`${f.http_requests} HTTP requests to ${f.distinct_paths} distinct paths.`);
  if (techniques.length) parts.push(`Matched techniques: ${techniques.map((/** @type {any} */ t) => t.id).join(", ")}.`);
  if (incident.tags?.includes("prompt-injection-attempt")) {
    parts.push("Attacker input contained prompt-injection-style text.");
  }

  const profile = [];
  if (intel.country) profile.push(`Geolocated to ${intel.country}`);
  if (intel.as_org) profile.push(`network ${intel.as_org}`);
  if (intel.abuse_confidence !== null && intel.abuse_confidence !== undefined) profile.push(`AbuseIPDB confidence ${intel.abuse_confidence}`);
  if (intel.greynoise_classification) profile.push(`GreyNoise: ${intel.greynoise_classification}`);
  const automated = (f.duration_seconds ?? 0) > 0 && (incident.event_count / Math.max(1, f.duration_seconds)) > 0.5;
  profile.push(automated ? "activity rate suggests automated tooling" : "activity rate is consistent with manual or low-rate tooling");

  return {
    summary: parts.join(" "),
    attacker_profile: `${profile.join("; ")}.`,
    techniques,
    severity: incident.severity,
    recommended_actions: ruleActions(incident)
  };
}

/**
 * Deterministic proposals by rule severity. Still subject to the policy
 * engine and human approval.
 * @param {{ src_ip: string, severity: string }} incident
 */
export function ruleActions(incident) {
  switch (incident.severity) {
    case "critical":
      return [{ type: "block_ip", target: incident.src_ip, reason: "Critical rule-based severity (post-compromise activity).", ttl_hours: 168 }];
    case "high":
      return [{ type: "block_ip", target: incident.src_ip, reason: "High rule-based severity.", ttl_hours: 24 }];
    case "medium":
      return [{ type: "watchlist", target: incident.src_ip, reason: "Medium rule-based severity.", ttl_hours: null }];
    default:
      return [{ type: "no_action", target: null, reason: "Low severity; background internet noise.", ttl_hours: null }];
  }
}
