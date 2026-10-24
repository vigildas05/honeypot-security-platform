import { useState } from "react";
import { apiPost, getSession } from "../api/client.js";
import { ErrorBox, IncidentLink, SourceBadge, Time, Untrusted } from "./ui.jsx";

const TYPE_LABEL = { block_ip: "Block IP", watchlist: "Watchlist", no_action: "No action" };

/**
 * A proposed response action. Approve/reject/revoke controls render only for
 * admins; the server enforces the same rule independently.
 * @param {{ action: any, onChanged?: () => void, showIncident?: boolean }} props
 */
export function ActionCard({ action, onChanged, showIncident = false }) {
  const isAdmin = getSession()?.role === "admin";
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  /** @param {"approve" | "reject" | "revoke"} verb */
  async function decide(verb) {
    if (reason.trim().length < 3) {
      setError("Please give a reason (at least 3 characters). It goes into the audit log.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await apiPost(`/actions/${encodeURIComponent(action.id)}/${verb}`, { reason: reason.trim() });
      setReason("");
      onChanged?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  const canDecide = isAdmin && action.status === "pending";
  const canRevoke = isAdmin && action.status === "active";

  return (
    <article className={`action-card status-${action.status}`}>
      <header>
        <strong>{TYPE_LABEL[/** @type {keyof typeof TYPE_LABEL} */ (action.action_type)] ?? action.action_type}</strong>
        {action.target ? <code className="ip">{action.target}</code> : null}
        <span className={`badge status ${action.status}`}>{action.status}</span>
        <SourceBadge ai={action.proposed_by === "llm"} />
        {showIncident ? <IncidentLink id={action.incident_id}>incident #{action.incident_id}</IncidentLink> : null}
      </header>
      <dl className="kv">
        <dt>Reason</dt>
        <dd><Untrusted value={action.reason} max={500} /></dd>
        {action.ttl_hours ? (<><dt>TTL</dt><dd>{action.ttl_hours} h</dd></>) : null}
        <dt>Proposed</dt>
        <dd><Time value={action.created_at} /></dd>
        {action.decided_by ? (
          <>
            <dt>Decision</dt>
            <dd>
              {action.decided_by} at <Time value={action.decided_at} />: <Untrusted value={action.decision_reason} max={300} />
            </dd>
          </>
        ) : null}
        {action.expires_at ? (<><dt>Expires</dt><dd><Time value={action.expires_at} /></dd></>) : null}
      </dl>
      {canDecide || canRevoke ? (
        <div className="decision">
          <label>
            Reason for your decision (recorded in the audit log)
            <input value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="e.g. confirmed miner session in timeline" />
          </label>
          <div className="buttons">
            {canDecide ? (
              <>
                <button disabled={busy} onClick={() => decide("approve")}>Approve</button>
                <button disabled={busy} className="danger" onClick={() => decide("reject")}>Reject</button>
              </>
            ) : (
              <button disabled={busy} className="danger" onClick={() => decide("revoke")}>Revoke now</button>
            )}
          </div>
        </div>
      ) : null}
      <ErrorBox message={error} />
    </article>
  );
}
