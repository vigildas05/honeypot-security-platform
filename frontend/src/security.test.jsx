// XSS-safety and role tests for the dashboard. Attacker strings must only ever
// become text nodes; links must only point at attack.mitre.org.
import fs from "node:fs";
import path from "node:path";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildCsp } from "../csp.js";
import { ActionCard } from "./components/ActionCard.jsx";
import { TechniqueLink, Untrusted } from "./components/ui.jsx";
import { IncidentDetail } from "./pages/IncidentDetail.jsx";

const XSS = [
  `<img src=x onerror="window.__pwned=1">`,
  `<script>window.__pwned=1</script>`,
  `"><svg onload=window.__pwned=1>`,
  `javascript:window.__pwned=1`,
  `<a href="javascript:window.__pwned=1">click</a>`
];

/** @param {"admin" | "demo"} role */
const setRole = (role) => localStorage.setItem("dashboardSession", JSON.stringify({ token: "t", role, username: role }));

beforeEach(() => {
  /** @type {any} */ (window).__pwned = 0;
});
afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

/** Every element in the container must be one our components create, never attacker markup. */
function assertInert(container) {
  expect(container.querySelector("script, img, svg[onload], iframe, object, embed")).toBeNull();
  for (const el of container.querySelectorAll("*")) {
    for (const attr of el.attributes) {
      expect(attr.name.startsWith("on"), `${el.tagName} has ${attr.name}`).toBe(false);
    }
  }
  for (const a of container.querySelectorAll("a[href]")) {
    const href = a.getAttribute("href");
    expect(href.startsWith("https://attack.mitre.org/") || href.startsWith("/")).toBe(true);
  }
  expect(/** @type {any} */ (window).__pwned).toBe(0);
}

describe("Untrusted", () => {
  it.each(XSS)("renders %j as text only", (payload) => {
    const { container } = render(<Untrusted value={payload} />);
    expect(container.textContent).toBe(payload);
    assertInert(container);
  });
});

describe("TechniqueLink", () => {
  it("links validated ids to attack.mitre.org", () => {
    render(<MemoryRouter><TechniqueLink id="T1059.004" name="Unix Shell" /></MemoryRouter>);
    expect(screen.getByRole("link").getAttribute("href")).toBe("https://attack.mitre.org/techniques/T1059/004/");
    expect(screen.getByRole("link").getAttribute("rel")).toBe("noopener noreferrer");
  });

  it.each(["javascript:alert(1)", "T1110/../../evil", "https://evil.example"])("does not link invalid id %j", (id) => {
    const { container } = render(<TechniqueLink id={id} />);
    expect(container.querySelector("a")).toBeNull();
  });
});

describe("IncidentDetail with hostile data", () => {
  const incident = {
    id: "7", src_ip: "91.92.93.94", status: "open", first_seen: "2026-10-01T10:00:00Z", last_seen: "2026-10-01T10:05:00Z",
    event_count: 2, severity: "critical", severity_score: 90, tags: ["prompt-injection-attempt"],
    stats: { severity_reasons: [XSS[0]] },
    techniques: [{ id: "T1078", name: "Valid Accounts", tactic: "initial-access", evidence: XSS[1], url: "javascript:alert(1)" }],
    intel: { summary: { country: XSS[2], as_org: XSS[0] }, providers: [{ provider: "abuseipdb", data: { domain: XSS[1] }, fetched_at: "2026-10-01T10:00:00Z" }] },
    reports: [{
      id: 1, ai_generated: true, model: "mock", validation_status: "valid", created_at: "2026-10-01T10:06:00Z",
      report: { summary: XSS[1], attacker_profile: XSS[2], severity: "high",
        techniques: [{ id: "javascript:alert(1)", reasoning: XSS[0] }, { id: "T1110", name: "Brute Force", reasoning: XSS[4] }] }
    }],
    actions: [{ id: 3, incident_id: "7", action_type: "block_ip", target: "91.92.93.94", reason: XSS[0], ttl_hours: 24, status: "pending", proposed_by: "llm", created_at: "2026-10-01T10:06:00Z" }],
    events: [
      { id: 1, ts: "2026-10-01T10:00:00Z", protocol: "ssh", event_type: "auth_attempt", username: XSS[0], password: XSS[1], auth_success: true },
      { id: 2, ts: "2026-10-01T10:01:00Z", protocol: "http", event_type: "request", http_method: "GET", http_path: XSS[3], user_agent: XSS[4], http_headers: { referer: XSS[0] } }
    ],
    events_capped: false
  };

  /** @param {"admin" | "demo"} role */
  async function renderDetail(role) {
    setRole(role);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => incident })));
    const view = render(
      <MemoryRouter initialEntries={["/incidents/7"]}>
        <Routes><Route path="/incidents/:id" element={<IncidentDetail />} /></Routes>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText(/Incident #7/)).toBeTruthy());
    return view;
  }

  it("renders every attacker field inertly", async () => {
    const { container } = await renderDetail("admin");
    for (const payload of [XSS[0], XSS[1], XSS[2]]) {
      expect(container.textContent).toContain(payload);
    }
    assertInert(container);
  });

  it("labels the AI report and surfaces the injection signal", async () => {
    await renderDetail("admin");
    expect(screen.getAllByText(/AI-generated/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Prompt-injection attempt detected/)).toBeTruthy();
  });

  it("shows approval controls to admins only", async () => {
    await renderDetail("demo");
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    cleanup();
    await renderDetail("admin");
    expect(screen.getByRole("button", { name: "Approve" })).toBeTruthy();
  });
});

describe("ActionCard", () => {
  const action = { id: 1, incident_id: 2, action_type: "block_ip", target: "91.92.93.94", reason: "r", ttl_hours: 24, status: "active", proposed_by: "rules" };

  it("offers revoke on active actions to admins, nothing to demo users", () => {
    setRole("admin");
    render(<MemoryRouter><ActionCard action={action} /></MemoryRouter>);
    expect(screen.getByRole("button", { name: "Revoke now" })).toBeTruthy();
    cleanup();
    setRole("demo");
    render(<MemoryRouter><ActionCard action={action} /></MemoryRouter>);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});

describe("source hygiene", () => {
  it("never uses HTML sinks anywhere in src/", () => {
    /** @param {string} dir @returns {string[]} */
    const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
      d.isDirectory() ? walk(path.join(dir, d.name)) : [path.join(dir, d.name)]);
    const files = walk(path.resolve(__dirname)).filter((f) => /\.(js|jsx)$/.test(f) && !f.includes(".test."));
    expect(files.length).toBeGreaterThan(5);
    for (const f of files) {
      const src = fs.readFileSync(f, "utf8");
      expect(src, f).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(/);
    }
  });
});

describe("CSP", () => {
  it("allows only self plus the API origin, with no unsafe-inline", () => {
    const csp = buildCsp("https://api.example.com/v1");
    expect(csp).toContain("connect-src 'self' https://api.example.com");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
  });

  it("rejects a relative API base", () => {
    expect(() => buildCsp("/api")).toThrow();
  });
});
