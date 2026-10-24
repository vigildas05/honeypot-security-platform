import { describe, expect, it, vi } from "vitest";
import { incidentSignature, isSignificantUpdate } from "../../src/agent/core.js";
import { createOpenAICompatibleClient } from "../../src/agent/llmClient.js";
import { loadAgentConfig, llmConfigured } from "../../src/config/agent.js";

describe("re-analysis debounce decision", () => {
  const sig = incidentSignature({ severity: "medium", techniques: [{ id: "T1110" }], tags: ["brute-force"] });
  const analyzed = { event_count: 30, analyzed_event_count: 20, analyzed_signature: sig, last_analyzed_at: new Date() };

  it("always analyzes a never-analyzed incident", () => {
    expect(isSignificantUpdate({ ...analyzed, last_analyzed_at: null }, sig, 2)).toBe(true);
  });

  it("skips small growth with the same signature", () => {
    expect(isSignificantUpdate(analyzed, sig, 2)).toBe(false);
  });

  it("re-analyzes on severity/technique/tag change", () => {
    const changed = incidentSignature({ severity: "high", techniques: [{ id: "T1110" }, { id: "T1078" }], tags: ["brute-force"] });
    expect(isSignificantUpdate(analyzed, changed, 2)).toBe(true);
  });

  it("re-analyzes when the incident has doubled (and grown by at least 10)", () => {
    expect(isSignificantUpdate({ ...analyzed, event_count: 40 }, sig, 2)).toBe(true);
    expect(isSignificantUpdate({ ...analyzed, event_count: 3, analyzed_event_count: 1 }, sig, 2)).toBe(false);
  });

  it("signature is order-independent", () => {
    expect(incidentSignature({ severity: "low", techniques: [{ id: "B" }, { id: "A" }], tags: ["y", "x"] })).toBe(
      incidentSignature({ severity: "low", techniques: [{ id: "A" }, { id: "B" }], tags: ["x", "y"] })
    );
  });
});

describe("agent config", () => {
  it("is LLM-less unless base URL and model are set", () => {
    expect(llmConfigured(loadAgentConfig({}))).toBe(false);
    expect(llmConfigured(loadAgentConfig({ LLM_BASE_URL: "http://localhost:11434/v1", LLM_MODEL: "llama3.1" }))).toBe(true);
  });

  it("never lets the default TTL exceed the cap", () => {
    const cfg = loadAgentConfig({ BLOCK_MAX_TTL_HOURS: "12", BLOCK_DEFAULT_TTL_HOURS: "48" });
    expect(cfg.policy.defaultBlockTtlHours).toBe(12);
  });

  it("rejects a malformed never-block entry at startup", async () => {
    const { createPolicyEngine } = await import("../../src/agent/policy.js");
    expect(() => createPolicyEngine(loadAgentConfig({ NEVER_BLOCK_IPS: "my-server.example" }).policy)).toThrow();
  });
});

describe("OpenAI-compatible client", () => {
  const cfg = { baseUrl: "https://llm.example/v1", apiKey: "sk-test", model: "m", jsonMode: true, temperature: 0.2, maxOutputTokens: 100, timeoutMs: 1000 };

  it("posts chat/completions with JSON mode and a bearer key", async () => {
    const fetchImpl = vi.fn(async () => /** @type {any} */ ({
      ok: true, status: 200,
      json: async () => ({ model: "m-2", choices: [{ message: { content: "{}" } }], usage: { prompt_tokens: 7, completion_tokens: 3 } })
    }));
    const client = createOpenAICompatibleClient(cfg, fetchImpl);
    const r = await client.complete([{ role: "user", content: "hi" }]);
    expect(r).toMatchObject({ text: "{}", tokensIn: 7, tokensOut: 3, model: "m-2" });
    const [url, init] = /** @type {any} */ (fetchImpl.mock.calls[0]);
    expect(url).toBe("https://llm.example/v1/chat/completions");
    expect(init.headers.authorization).toBe("Bearer sk-test");
    const body = JSON.parse(init.body);
    expect(body).toMatchObject({ model: "m", response_format: { type: "json_object" }, max_tokens: 100 });
    expect(init.body).not.toContain("sk-test");
  });

  it("omits the auth header for keyless local endpoints (Ollama)", async () => {
    const fetchImpl = vi.fn(async () => /** @type {any} */ ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "{}" } }] }) }));
    await createOpenAICompatibleClient({ ...cfg, apiKey: "" }, fetchImpl).complete([]);
    expect(/** @type {any} */ (fetchImpl.mock.calls[0])[1].headers).not.toHaveProperty("authorization");
  });

  it("errors do not include the prompt", async () => {
    const fetchImpl = vi.fn(async () => /** @type {any} */ ({ ok: false, status: 429, json: async () => ({ error: { message: "rate limited" } }) }));
    const client = createOpenAICompatibleClient(cfg, fetchImpl);
    await expect(client.complete([{ role: "user", content: "ATTACKER_SECRET_PAYLOAD" }])).rejects.toThrow(/^LLM HTTP 429: rate limited$/);
  });
});
