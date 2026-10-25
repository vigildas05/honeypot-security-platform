import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet, getSession } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ErrorBox, IncidentLink, Meter, RankList, SeverityBadge, Stat, TechniqueLink, Time } from "../components/ui.jsx";

export function Metrics() {
  const [days, setDays] = useState(7);
  const { data: m, error } = useApi(() => apiGet("/metrics/dashboard", { days }), [days], { pollMs: 30000 });

  if (error) return <ErrorBox message={error} />;
  if (!m) return <p className="muted">Loading…</p>;

  const hourly = m.events_per_hour.map((/** @type {any} */ b) => ({
    hour: new Date(b.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    count: b.count
  }));
  const sev = m.incidents_by_severity ?? {};
  const worker = m.worker;

  return (
    <>
      <div className="segmented">
        {[1, 7, 30].map((d) => (
          <button key={d} className={days === d ? "" : "secondary"} onClick={() => setDays(d)}>
            {d === 1 ? "24 hours" : `${d} days`}
          </button>
        ))}
      </div>

      <section className="metrics-grid">
        <Stat label={`Events (${days}d)`} value={m.totals.events.toLocaleString()} />
        <Stat label={`Incidents (${days}d)`} value={m.totals.incidents.toLocaleString()} />
        <Stat label="Pending approvals" value={m.totals.pending_actions} />
        <Stat label="Active blocks" value={m.totals.active_blocks} />
      </section>

      <section className="panel">
        <h2>Events per hour (last 48h)</h2>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={hourly}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="hour" interval={5} />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Bar dataKey="count" fill="#2563eb" />
          </BarChart>
        </ResponsiveContainer>
      </section>

      <section className="dashboard-grid three">
        <div className="panel">
          <h2>Top source IPs</h2>
          <RankList items={m.top_source_ips.map((/** @type {any} */ x) => ({ value: x.ip, count: x.count }))} />
        </div>
        <div className="panel">
          <h2>Top countries</h2>
          <RankList items={m.top_countries.map((/** @type {any} */ x) => ({ value: x.country, count: x.count }))} />
        </div>
        <div className="panel">
          <h2>Incidents by severity</h2>
          <ul className="rank-list">
            {["critical", "high", "medium", "low"].map((s) => (
              <li key={s}><SeverityBadge level={s} /><strong>{sev[s] ?? 0}</strong></li>
            ))}
          </ul>
        </div>
        <div className="panel">
          <h2>Top usernames</h2>
          <RankList items={m.top_usernames} />
        </div>
        <div className="panel">
          <h2>Top passwords</h2>
          <RankList items={m.top_passwords} />
        </div>
        <div className="panel">
          <h2>Top techniques</h2>
          {m.top_techniques.length ? (
            <ul className="rank-list">
              {m.top_techniques.map((/** @type {any} */ t) => (
                <li key={t.id}><TechniqueLink id={t.id} name={t.name} /><strong>{t.incidents}</strong></li>
              ))}
            </ul>
          ) : <p className="muted">No data yet</p>}
        </div>
      </section>

      <section className="dashboard-grid">
        <div className="panel">
          <h2>Prompt-injection attempts</h2>
          <p className="big-number">{m.injection.incidents}</p>
          <p className="muted">incidents in the window whose attacker input targeted the AI analyst</p>
          <ul>
            {m.injection.recent.map((/** @type {any} */ i) => (
              <li key={i.id}>
                <IncidentLink id={i.id} /> <code className="ip">{i.src_ip}</code> <SeverityBadge level={i.severity} /> <Time value={i.last_seen} />
              </li>
            ))}
          </ul>
        </div>
        <div className="panel">
          <h2>AI agent</h2>
          <p>
            Worker:{" "}
            {worker ? (
              <>
                <span className={`badge ${worker.alive ? "status active" : "sev-critical"}`}>{worker.alive ? "running" : "no heartbeat"}</span>{" "}
                <span className="muted">last seen <Time value={worker.last_heartbeat} /></span>
              </>
            ) : <span className="muted">never started</span>}
          </p>
          <p>
            LLM: {m.llm_budget_today.configured ? <code>{worker?.llm_model}</code> : <span className="muted">not configured (rule-only reports)</span>}
            {worker?.intel_providers ? <span className="muted"> · intel: {worker.intel_providers.join(", ") || "none"}</span> : null}
          </p>
          <Meter label="LLM calls today" used={m.llm_budget_today.calls} budget={m.llm_budget_today.call_budget} />
          <Meter label="LLM tokens today" used={m.llm_budget_today.tokens} budget={m.llm_budget_today.token_budget} />
          <table className="compact">
            <tbody>
              <tr><td>Reports (AI / rule-based)</td><td>{m.agent.reports_llm} / {m.agent.reports_rules}</td></tr>
              <tr><td>LLM calls</td><td>{m.agent.llm_calls}</td></tr>
              <tr><td>Validation failures</td><td>{m.agent.llm_validation_failures}</td></tr>
              <tr><td>LLM errors</td><td>{m.agent.llm_errors}</td></tr>
              <tr><td>Canary leaks caught</td><td>{m.agent.canary_leaks}</td></tr>
              <tr><td>Policy violations blocked</td><td>{m.agent.policy_violations_blocked}</td></tr>
              <tr><td>Actions proposed</td><td>{m.agent.actions_proposed}</td></tr>
              <tr><td>EDL fetches</td><td>{m.agent.edl_fetches}</td></tr>
              {m.agent.calls_by_outcome.map((/** @type {any} */ c) => (
                <tr key={c.outcome}><td>Calls: {c.outcome}</td><td>{c.count}{c.avg_latency_ms ? ` · avg ${c.avg_latency_ms} ms` : ""}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {getSession()?.role === "admin" ? <Observability /> : null}
    </>
  );
}

/** Admin-only pipeline/agent health, from GET /admin/metrics. */
function Observability() {
  const { data: o, error } = useApi(() => apiGet("/admin/metrics"), [], { pollMs: 30000 });
  if (error) return <ErrorBox message={error} />;
  if (!o) return null;
  const ms = (/** @type {number | null} */ v) => (v === null || v === undefined ? "-" : `${v.toLocaleString()} ms`);
  const rows = [
    ["Events ingested / rejected (today)", `${o.today.events_ingested} / ${o.today.events_rejected}`],
    ["Events not yet correlated", o.pipeline.uncorrelated_events],
    ["Events in the last hour", o.pipeline.events_last_hour],
    ["Worker heartbeat", o.worker ? `${o.worker.heartbeat_age_seconds}s ago${o.worker.alive ? "" : " (STALE)"}` : "never"],
    ["LLM latency p50 / p95 / max (24h)", `${ms(o.llm_24h.latency_ms.p50)} / ${ms(o.llm_24h.latency_ms.p95)} / ${ms(o.llm_24h.latency_ms.max)}`],
    ["LLM tokens in / out (24h)", `${o.llm_24h.tokens_in.toLocaleString()} / ${o.llm_24h.tokens_out.toLocaleString()}`],
    ["LLM validation failures (7d)", o.last_7_days.llm_validation_failures],
    ["Canary leaks caught (7d)", o.last_7_days.canary_leaks],
    ["Policy violations blocked (7d)", o.last_7_days.policy_violations_blocked],
    ["Injection incidents (7d)", o.last_7_days.injection_incidents]
  ];
  return (
    <section className="panel">
      <h2>Pipeline &amp; agent health <span className="badge role-admin">admin</span></h2>
      <p className="muted">
        Same data as <code>GET /admin/metrics</code> (JSON, or <code>?format=prometheus</code> with <code>METRICS_TOKEN</code>).
      </p>
      <div className="dashboard-grid">
        <table className="compact">
          <tbody>
            {rows.map(([k, v]) => <tr key={String(k)}><td>{k}</td><td><strong>{v}</strong></td></tr>)}
          </tbody>
        </table>
        <div>
          <h3>Job queues</h3>
          {o.queues.length ? (
            <table className="compact">
              <tbody>
                {o.queues.map((/** @type {any} */ q) => (
                  <tr key={`${q.name}-${q.state}`} className={q.state === "failed" ? "row-alert" : undefined}>
                    <td>{q.name}</td><td>{q.state}</td><td><strong>{q.count}</strong></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No queued, active or failed jobs.</p>}
        </div>
      </div>
    </section>
  );
}
