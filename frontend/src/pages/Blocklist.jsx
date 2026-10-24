import { apiGet } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ErrorBox, IncidentLink, SeverityBadge, SourceBadge, Time, Untrusted } from "../components/ui.jsx";

export function Blocklist() {
  const { data, error } = useApi(() => apiGet("/blocklist"), [], { pollMs: 30000 });
  return (
    <section className="panel">
      <h2>Active blocklist</h2>
      <p className="muted">
        Exactly what <code>/edl/blocklist.txt</code> serves to firewalls: approved, active, unexpired blocks.
      </p>
      <ErrorBox message={error} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>Incident</th>
              <th>Proposed by</th>
              <th>Approved by</th>
              <th>Active since</th>
              <th>Expires</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((/** @type {any} */ b) => (
              <tr key={b.id}>
                <td><code className="ip">{b.ip}</code></td>
                <td><IncidentLink id={b.incident_id} /> <SeverityBadge level={b.incident_severity} /></td>
                <td><SourceBadge ai={b.proposed_by === "llm"} /></td>
                <td>{b.decided_by}</td>
                <td><Time value={b.activated_at} /></td>
                <td><Time value={b.expires_at} /></td>
                <td><Untrusted value={b.reason} max={120} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {data?.length === 0 ? <p className="muted">No active blocks.</p> : null}
      </div>
    </section>
  );
}
