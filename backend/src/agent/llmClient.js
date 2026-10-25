// Minimal client for any OpenAI-compatible /chat/completions endpoint:
// OpenAI, Gemini (generativelanguage.googleapis.com/v1beta/openai), Groq
// (api.groq.com/openai/v1), NVIDIA NIM (integrate.api.nvidia.com/v1), or a
// local Ollama (http://localhost:11434/v1).

/**
 * @typedef {{ role: "system" | "user" | "assistant", content: string }} ChatMessage
 * @typedef {{ text: string, tokensIn: number, tokensOut: number, latencyMs: number, model: string }} Completion
 * @typedef {{ complete: (messages: ChatMessage[]) => Promise<Completion>, model: string }} LlmClient
 */

/**
 * @param {{ baseUrl: string, apiKey: string, model: string, jsonMode: boolean, temperature: number, maxOutputTokens: number, timeoutMs: number }} cfg
 * @param {typeof fetch} [fetchImpl]
 * @returns {LlmClient}
 */
export function createOpenAICompatibleClient(cfg, fetchImpl = fetch) {
  const url = `${cfg.baseUrl}/chat/completions`;
  return {
    model: cfg.model,
    async complete(messages) {
      const started = Date.now();
      /** @type {Record<string, unknown>} */
      const body = {
        model: cfg.model,
        messages,
        temperature: cfg.temperature,
        max_tokens: cfg.maxOutputTokens
      };
      if (cfg.jsonMode) body.response_format = { type: "json_object" };

      const response = await fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {})
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(cfg.timeoutMs)
      });
      const json = /** @type {any} */ (await response.json().catch(() => null));
      if (!response.ok) {
        // Never include the request (it contains attacker data) or the key.
        const msg = typeof json?.error?.message === "string" ? json.error.message.slice(0, 200) : "";
        throw new Error(`LLM HTTP ${response.status}${msg ? `: ${msg}` : ""}`);
      }
      const text = json?.choices?.[0]?.message?.content;
      if (typeof text !== "string") throw new Error("LLM reply had no message content");
      return {
        text,
        tokensIn: Number(json?.usage?.prompt_tokens ?? 0) || 0,
        tokensOut: Number(json?.usage?.completion_tokens ?? 0) || 0,
        latencyMs: Date.now() - started,
        model: typeof json?.model === "string" ? json.model.slice(0, 100) : cfg.model
      };
    }
  };
}
