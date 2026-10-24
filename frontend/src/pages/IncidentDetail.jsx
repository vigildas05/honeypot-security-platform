import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { apiGet } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ActionCard } from "../components/ActionCard.jsx";
import { ErrorBox, SeverityBadge, SourceBadge, Tag, TechniqueLink, Time, Untrusted } from "../components/ui.jsx";

const FALLBACK_TEXT = {
  llm_not_configured: "No LLM is configured; this is the deterministic rule-based report.",
  budget_exhausted: "The daily LLM budget was used up; this is the rule-based report.",
  validation_failed: "The LLM's output failed validation twice and was discarded; this is the rule-based report.",
  canary_leak: "The LLM output leaked the prompt canary (likely prompt injection) and was discarded; this is the rule-based report."
};

export function IncidentDetail() {
  const { id = "" } = useParams();
  const { data: inc, error, reload } = useApi(() => apiGet(`/incidents/${encodeURIComponent(id)}`), [id], { pollMs: 20000 });

  if (error) return <ErrorBox message={error} />;
  if (!inc) return <p className="muted">Loading…</p>;

  const report = inc.reports?.[0];
  const injection = inc.tags?.includes("prompt-injection-attempt");

  return (
    <>
      <p><Link to="/incidents">← All incidents</Link></p>
      <section className="panel incident-head">
        <div>
          <h2>Incident #{inc.id} <SeverityBadge level={inc.severity} /></h2>
          <p>
            Source <code className="ip">{inc.src_ip}</code>
            {inc.intel?.summary?.country ? ` · ${inc.intel.summary.country}` : ""} · {inc.event_count} events · {inc.status}
          </p>
          <p className="muted">
            <Time value={inc.first_seen} /> → <Time value={inc.last_seen} />
          </p>
          <div className="wrap">{(inc.tags ?? []).map((/** @type {string} */ t) => <Tag key={t} tag={t} />)}</div>
        </div>
        <div className="score">
          <span>Rule score</span>
          <strong>{inc.severity_score}</strong>
        </div>
      </section>

      {injection ? (
        <p className="warning" role="status">
          <strong>Prompt-injection attempt detected.</strong> Attacker input in this incident contains text aimed at the AI
          analyst. It is shown below as inert text; any AI output for this incident deserves extra scrutiny.
        </p>
      ) : null}

      <section className="dashboard-grid">
        <div className="panel">
          <h2>ATT&amp;CK techniques <span className="badge rules">Rule engine</span></h2>
          {inc.techniques?.length ? (
            <table className="compact">
              <tbody>
                {inc.techniques.map((/** @type {any} */ t) => (
                  <tr key={t.id}>
                    <td><TechniqueLink id={t.id} name={t.name} /></td>
                    <td className="muted">{t.tactic}</td>
                    <td>{t.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No techniques matched.</p>}
          <details>
            <summary>Why this severity?</summary>
            <ul>{(inc.stats?.severity_reasons ?? []).map((/** @type {string} */ r, /** @type {number} */ i) => <li key={i}>{r}</li>)}</ul>
          </details>
        </div>
        <div className="panel">
          <h2>Threat intel</h2>
          <IntelSummary summary={inc.intel?.summary ?? {}} />
          <details>
            <summary>Provider details ({inc.intel?.providers?.length ?? 0})</summary>
            <table className="compact">
              <tbody>
                {(inc.intel?.providers ?? []).map((/** @type {any} */ p) => (
                  <tr key={p.provider}>
                    <td><strong>{p.provider}</strong></td>
                    <td>{p.error ? <span className="muted">error: {p.error}</span> : <Untrusted value={JSON.stringify(p.data)} max={400} />}</td>
                    <td className="muted"><Time value={p.fetched_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </div>
      </section>

      <section className="panel">
        <h2>Analyst report {report ? <SourceBadge ai={report.ai_generated} model={report.model} /> : null}</h2>
        {report ? <Report report={report} /> : <p className="muted">No report yet. The agent runs after a short debounce.</p>}
        {inc.reports?.length > 1 ? (
          <details>
            <summary>Report history ({inc.reports.length})</summary>
            <ul>
              {inc.reports.map((/** @type {any} */ r) => (
                <li key={r.id}>
                  <Time value={r.created_at} /> · {r.ai_generated ? "AI-generated" : "rule-based"} · {r.validation_status}
                  {r.fallback_reason ? ` (${r.fallback_reason})` : ""}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </section>

      <section className="panel">
        <h2>Proposed actions</h2>
        <p className="muted">Proposals never take effect on their own. An admin must approve them before they reach the blocklist.</p>
        {inc.actions?.length ? (
          <div className="action-list">
            {inc.actions.map((/** @type {any} */ a) => <ActionCard key={a.id} action={a} onChanged={reload} />)}
          </div>
        ) : <p className="muted">No proposals.</p>}
      </section>

      <Timeline events={inc.events ?? []} capped={inc.events_capped} />
    </>
  );
}

/** @param {{ summary: Record<string, any> }} props */
function IntelSummary({ summary }) {
  const rows = [
    ["Country", summary.country],
    ["Network", summary.as_org ? `${summary.as_org}${summary.asn ? ` (AS${summary.asn})` : ""}` : null],
    ["AbuseIPDB confidence", summary.abuse_confidence],
    ["AbuseIPDB reports", summary.abuse_reports],
    ["VirusTotal malicious", summary.vt_malicious],
    ["GreyNoise", summary.greynoise_classification ?? (summary.greynoise_noise === false ? "not observed scanning" : null)],
    ["Tor exit", summary.is_tor === null || summary.is_tor === undefined ? null : summary.is_tor ? "yes" : "no"]
  ].filter(([, v]) => v !== null && v !== undefined);
  if (!rows.length) return <p className="muted">No threat-intel data (no provider keys configured, or a private/reserved address).</p>;
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={String(k)} className="kv-row"><dt>{k}</dt><dd><Untrusted value={v} max={120} /></dd></div>
      ))}
    </dl>
  );
}

/** @param {{ report: any }} props */
function Report({ report }) {
  const body = report.report ?? {};
  return (
    <div className={`report ${report.ai_generated ? "report-ai" : ""}`}>
      {report.ai_generated ? (
        <p className="ai-note">
          This text was written by an LLM from attacker-influenced data. It was schema-validated and canary-checked, but it can
          still be wrong. The severity and ATT&amp;CK mapping above come from the deterministic rule engine.
        </p>
      ) : report.fallback_reason ? (
        <p className="muted">{FALLBACK_TEXT[/** @type {keyof typeof FALLBACK_TEXT} */ (report.fallback_reason)] ?? report.fallback_reason}</p>
      ) : null}
      <h3>Summary</h3>
      {/* LLM output is rendered as plain text too: it may echo attacker strings. */}
      <Untrusted value={body.summary} max={1500} block />
      <h3>Attacker profile</h3>
      <Untrusted value={body.attacker_profile} max={800} block />
      <h3>Techniques {report.ai_generated ? "cited by the AI" : ""}</h3>
      <ul>
        {(body.techniques ?? []).map((/** @type {any} */ t, /** @type {number} */ i) => (
          <li key={`${t.id}-${i}`}>
            <TechniqueLink id={t.id} name={t.name} />: <Untrusted value={t.reasoning} max={500} />
          </li>
        ))}
      </ul>
      {report.ai_generated ? <p className="muted">AI-suggested severity: {String(body.severity)}</p> : null}
      {body.injection_signals?.length ? (
        <p className="muted">
          Injection signals: {body.injection_signals.map((/** @type {any} */ s) => `${s.pattern} in ${s.field}`).join(", ")}
        </p>
      ) : null}
    </div>
  );
}

/** @param {{ events: any[], capped: boolean }} props */
function Timeline({ events, capped }) {
  const [open, setOpen] = useState(/** @type {string | null} */ (null));
  return (
    <section className="panel">
      <h2>Event timeline {capped ? <span className="muted">(first 1,000 events)</span> : null}</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>User</th>
              <th>Password</th>
              <th>Command / request</th>
              <th>User agent</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className={e.auth_success ? "row-success" : undefined}>
                <td><Time value={e.ts} /></td>
                <td>
                  {e.protocol}/{e.event_type}
                  {e.auth_success === true ? <span className="badge sev-high"> login OK</span> : null}
                  {e.truncated ? <span className="muted" title="Oversized attacker input was truncated at ingest"> (truncated)</span> : null}
                </td>
                <td><Untrusted value={e.username} max={40} /></td>
                <td><Untrusted value={e.password} max={40} /></td>
                <td>
                  {e.command ? <Untrusted value={e.command} max={160} /> : null}
                  {e.http_path ? (
                    <>
                      <span className="muted">{e.http_method} </span>
                      <Untrusted value={e.http_path} max={160} />
                      {Object.keys(e.http_headers ?? {}).length ? (
                        <button className="link" onClick={() => setOpen(open === e.id ? null : e.id)}>headers</button>
                      ) : null}
                      {open === e.id ? <Untrusted value={JSON.stringify(e.http_headers, null, 1)} max={4000} block /> : null}
                    </>
                  ) : null}
                </td>
                <td><Untrusted value={e.user_agent} max={60} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
