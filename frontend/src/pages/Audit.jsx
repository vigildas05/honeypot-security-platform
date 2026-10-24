import { useState } from "react";
import { apiGet } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ErrorBox, Time, Untrusted } from "../components/ui.jsx";

const ACTIONS = [
  "", "action.approved", "action.rejected", "action.revoked", "action.activated", "action.expired", "action.proposed",
  "policy.violation", "agent.injection_detected", "agent.canary_leak", "agent.report_created"
];

export function Audit() {
  const [action, setAction] = useState("");
  const { data, error } = useApi(() => apiGet("/audit", { action: action || undefined }), [action], { pollMs: 30000 });
  return (
    <section className="panel">
      <h2>Audit log</h2>
      <p className="muted">Append-only (enforced by a database trigger). Every decision and blocked policy violation is recorded.</p>
      <label className="inline">
        Event
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          {ACTIONS.map((a) => <option key={a} value={a}>{a || "All"}</option>)}
        </select>
      </label>
      <ErrorBox message={error} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((/** @type {any} */ r) => (
              <tr key={r.id} className={r.action === "policy.violation" || r.action === "agent.canary_leak" ? "row-alert" : undefined}>
                <td><Time value={r.ts} /></td>
                <td>{r.actor}{r.actor_role ? <span className="muted"> ({r.actor_role})</span> : null}</td>
                <td><code>{r.action}</code></td>
                <td>{r.target_type} {r.target_id}</td>
                <td><Untrusted value={JSON.stringify(r.details)} max={300} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
