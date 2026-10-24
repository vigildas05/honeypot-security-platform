import { useSearchParams } from "react-router-dom";
import { apiGet } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ErrorBox, IncidentLink, SeverityBadge, Tag, TechniqueLink, Time } from "../components/ui.jsx";

const SEVERITIES = ["critical", "high", "medium", "low"];
const TAGS = [
  "prompt-injection-attempt", "credential-success", "brute-force", "malware-download", "persistence",
  "cryptomining", "exploit-attempt", "scanning", "interactive-session", "discovery", "defense-evasion"
];
const RANGES = { "24h": 1, "7d": 7, "30d": 30, all: 0 };
const PAGE = 50;

export function Incidents() {
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "";
  const technique = params.get("technique") ?? "";
  const tag = params.get("tag") ?? "";
  const status = params.get("status") ?? "";
  const range = /** @type {keyof typeof RANGES} */ (params.get("range") ?? "7d");
  const offset = Number(params.get("offset") ?? 0) || 0;
  const techniqueValid = !technique || /^T\d{4}(\.\d{3})?$/.test(technique);

  const days = RANGES[range] ?? 7;
  const from = days ? new Date(Date.now() - days * 86400_000).toISOString() : undefined;

  const { data, error, loading } = useApi(
    () =>
      apiGet("/incidents", {
        severity: severity || undefined,
        technique: techniqueValid ? technique || undefined : undefined,
        tag: tag || undefined,
        status: status || undefined,
        from,
        limit: PAGE,
        offset
      }),
    [severity, technique, tag, status, range, offset],
    { pollMs: 15000 }
  );

  /** @param {string} key @param {string} value */
  const set = (key, value) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next);
  };
  const selected = new Set(severity ? severity.split(",") : []);
  /** @param {string} s */
  const toggleSeverity = (s) => {
    const next = new Set(selected);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    set("severity", SEVERITIES.filter((x) => next.has(x)).join(","));
  };

  return (
    <section className="panel">
      <h2>Incidents</h2>
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <fieldset>
          <legend>Severity</legend>
          {SEVERITIES.map((s) => (
            <label key={s} className="check">
              <input type="checkbox" checked={selected.has(s)} onChange={() => toggleSeverity(s)} /> {s}
            </label>
          ))}
        </fieldset>
        <label>
          Technique
          <input
            value={technique}
            placeholder="e.g. T1110.003"
            aria-invalid={!techniqueValid}
            onChange={(e) => set("technique", e.target.value.trim().toUpperCase())}
          />
        </label>
        <label>
          Tag
          <select value={tag} onChange={(e) => set("tag", e.target.value)}>
            <option value="">Any</option>
            {TAGS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>
          Status
          <select value={status} onChange={(e) => set("status", e.target.value)}>
            <option value="">Any</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
        </label>
        <label>
          Last seen
          <select value={range} onChange={(e) => set("range", e.target.value)}>
            {Object.keys(RANGES).map((r) => <option key={r} value={r}>{r === "all" ? "Any time" : `Last ${r}`}</option>)}
          </select>
        </label>
      </form>
      {!techniqueValid ? <p className="muted">Technique ids look like T1110 or T1110.003.</p> : null}
      <ErrorBox message={error} />

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Incident</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Events</th>
              <th>Techniques</th>
              <th>Tags</th>
              <th>Last seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((/** @type {any} */ i) => (
              <tr key={i.id}>
                <td><IncidentLink id={i.id} /></td>
                <td><SeverityBadge level={i.severity} /> <span className="muted">{i.severity_score}</span></td>
                <td><code className="ip">{i.src_ip}</code>{i.country ? <span className="muted"> {i.country}</span> : null}</td>
                <td>{i.event_count}</td>
                <td className="wrap">
                  {(i.technique_ids ?? []).slice(0, 4).map((/** @type {string} */ t) => <TechniqueLink key={t} id={t} />)}
                  {(i.technique_ids ?? []).length > 4 ? <span className="muted"> +{i.technique_ids.length - 4}</span> : null}
                </td>
                <td className="wrap">{(i.tags ?? []).map((/** @type {string} */ t) => <Tag key={t} tag={t} />)}</td>
                <td><Time value={i.last_seen} /></td>
                <td>
                  {i.status}
                  {i.pending_actions ? <span className="badge status pending"> {i.pending_actions} pending</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && data?.items?.length === 0 ? <p className="muted">No incidents match these filters.</p> : null}
      </div>
      {data && data.total > PAGE ? (
        <div className="pager">
          <button className="secondary" disabled={offset === 0} onClick={() => { const n = new URLSearchParams(params); n.set("offset", String(Math.max(0, offset - PAGE))); setParams(n); }}>Previous</button>
          <span>{offset + 1}–{Math.min(offset + PAGE, data.total)} of {data.total}</span>
          <button className="secondary" disabled={offset + PAGE >= data.total} onClick={() => { const n = new URLSearchParams(params); n.set("offset", String(offset + PAGE)); setParams(n); }}>Next</button>
        </div>
      ) : null}
    </section>
  );
}
