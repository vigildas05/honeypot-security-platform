import { useState } from "react";
import { apiGet, getSession } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ActionCard } from "../components/ActionCard.jsx";
import { ErrorBox } from "../components/ui.jsx";

const VIEWS = ["pending", "active", "rejected", "expired"];

export function Approvals() {
  const [status, setStatus] = useState("pending");
  const { data, error, reload } = useApi(() => apiGet("/actions", { status }), [status], { pollMs: 15000 });
  const isAdmin = getSession()?.role === "admin";

  return (
    <section className="panel">
      <h2>Approval queue</h2>
      <p className="muted">
        The agent and rule engine only <em>propose</em> actions, and every proposal has already passed the policy engine.
        {isAdmin ? " Approving a block publishes it to the firewall EDL until its TTL expires." : " Read-only demo accounts can't approve or reject."}
      </p>
      <div className="segmented" role="tablist">
        {VIEWS.map((v) => (
          <button key={v} role="tab" aria-selected={status === v} className={status === v ? "" : "secondary"} onClick={() => setStatus(v)}>
            {v}
          </button>
        ))}
      </div>
      <ErrorBox message={error} />
      {data?.length === 0 ? <p className="muted">Nothing {status}.</p> : null}
      <div className="action-list">
        {(data ?? []).map((/** @type {any} */ a) => <ActionCard key={a.id} action={a} onChanged={reload} showIncident />)}
      </div>
    </section>
  );
}
