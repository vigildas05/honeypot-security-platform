// SOC agent / LLM / response-policy config.

/** Public DNS resolvers and other infrastructure that must never be blocked. */
export const DEFAULT_NEVER_BLOCK = [
  // Google
  "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
  // Cloudflare
  "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
  // Quad9
  "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
  // OpenDNS
  "208.67.222.222", "208.67.220.220",
  // Root DNS server a.root-servers.net (representative; extend via env)
  "198.41.0.4"
];

/**
 * @param {NodeJS.ProcessEnv} raw
 */
export function loadAgentConfig(raw) {
  const num = (/** @type {string | undefined} */ v, /** @type {number} */ d) => {
    if (v === undefined || v === "") return d;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error(`Invalid number in agent config: ${v}`);
    return n;
  };
  const list = (/** @type {string | undefined} */ v) =>
    (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  const maxTtl = num(raw.BLOCK_MAX_TTL_HOURS, 168);
  return {
    llm: {
      // Any OpenAI-compatible /chat/completions endpoint: OpenAI, Gemini's
      // OpenAI-compat endpoint, Groq, NVIDIA NIM, or a local Ollama.
      baseUrl: (raw.LLM_BASE_URL ?? "").replace(/\/+$/, ""),
      apiKey: raw.LLM_API_KEY ?? "",
      model: raw.LLM_MODEL ?? "",
      jsonMode: raw.LLM_JSON_MODE !== "false",
      temperature: num(raw.LLM_TEMPERATURE, 0.2),
      maxOutputTokens: num(raw.LLM_MAX_OUTPUT_TOKENS, 1200),
      timeoutMs: num(raw.LLM_TIMEOUT_MS, 60_000),
      dailyCallBudget: num(raw.LLM_DAILY_CALL_BUDGET, 200),
      dailyTokenBudget: num(raw.LLM_DAILY_TOKEN_BUDGET, 300_000)
    },
    debounceSeconds: num(raw.AGENT_DEBOUNCE_SECONDS, 120),
    /** Re-analyze when the incident has grown by this factor since the last report. */
    reanalyzeGrowthFactor: num(raw.AGENT_REANALYZE_GROWTH_FACTOR, 2),
    incidentWindowMinutes: num(raw.INCIDENT_WINDOW_MINUTES, 30),
    correlateIntervalSeconds: num(raw.CORRELATE_INTERVAL_SECONDS, 10),
    policy: {
      maxBlockTtlHours: maxTtl,
      defaultBlockTtlHours: Math.min(num(raw.BLOCK_DEFAULT_TTL_HOURS, 24), maxTtl),
      maxActionsPerReport: 5,
      neverBlock: [...DEFAULT_NEVER_BLOCK, ...list(raw.NEVER_BLOCK_IPS)]
    }
  };
}

/** @typedef {ReturnType<typeof loadAgentConfig>} AgentConfig */

/** @param {AgentConfig} cfg */
export const llmConfigured = (cfg) => Boolean(cfg.llm.baseUrl && cfg.llm.model);
