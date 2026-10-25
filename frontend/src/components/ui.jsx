import { Link } from "react-router-dom";

/**
 * Attacker-controlled text. Rendered ONLY as a React text node (escaped by
 * React), in a monospace box that wraps and isolates bidi direction. Never
 * render these values as raw HTML (eslint react/no-danger and a source-scan
 * test enforce this).
 * @param {{ value: unknown, max?: number, block?: boolean }} props
 */
export function Untrusted({ value, max = 300, block = false }) {
  if (value === null || value === undefined || value === "") return <span className="muted">-</span>;
  const text = String(value);
  const shown = text.length > max ? `${text.slice(0, max)}…` : text;
  const Tag = block ? "pre" : "code";
  return (
    <Tag className="untrusted" title={text.length > max ? text.slice(0, 2000) : undefined}>
      {shown}
    </Tag>
  );
}

const SEVERITY_CLASS = { low: "sev-low", medium: "sev-medium", high: "sev-high", critical: "sev-critical" };

/** @param {{ level: string }} props */
export function SeverityBadge({ level }) {
  return <span className={`badge ${SEVERITY_CLASS[/** @type {keyof typeof SEVERITY_CLASS} */ (level)] ?? ""}`}>{level}</span>;
}

/** @param {{ tag: string }} props */
export function Tag({ tag }) {
  return <span className={`tag ${tag === "prompt-injection-attempt" ? "tag-alert" : ""}`}>{tag}</span>;
}

/** @param {{ ai: boolean, model?: string | null }} props */
export function SourceBadge({ ai, model }) {
  return ai ? (
    <span className="badge ai" title="Written by an LLM from attacker-influenced data. Verify before acting.">
      AI-generated{model ? ` · ${model}` : ""}
    </span>
  ) : (
    <span className="badge rules" title="Deterministic, template-based report from the rule engine.">Rule-based</span>
  );
}

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;

/**
 * Link to attack.mitre.org built from a validated id. The URL is never taken
 * from API data, so a poisoned value can't become a javascript: link.
 * @param {{ id: string, name?: string | null }} props
 */
export function TechniqueLink({ id, name }) {
  if (!TECHNIQUE_ID.test(id)) return <span>{id}</span>;
  const href = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="technique">
      <strong>{id}</strong>
      {name ? ` ${name}` : ""}
    </a>
  );
}

/** @param {{ value: string | Date | null | undefined }} props */
export function Time({ value }) {
  if (!value) return <span className="muted">-</span>;
  const d = new Date(value);
  return <time dateTime={d.toISOString()} title={d.toISOString()}>{d.toLocaleString()}</time>;
}

/** @param {{ message: string }} props */
export function ErrorBox({ message }) {
  return message ? <p className="error" role="alert">{message}</p> : null;
}

/** @param {{ label: string, value: import("react").ReactNode, hint?: string }} props */
export function Stat({ label, value, hint }) {
  return (
    <section className="metric" title={hint}>
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

/** @param {{ id: string | number, children?: import("react").ReactNode }} props */
export function IncidentLink({ id, children }) {
  return <Link to={`/incidents/${encodeURIComponent(String(id))}`}>{children ?? `#${id}`}</Link>;
}

/** @param {{ items: { value: unknown, count: number }[] | undefined, empty?: string }} props */
export function RankList({ items, empty = "No data yet" }) {
  if (!items?.length) return <p className="muted">{empty}</p>;
  return (
    <ul className="rank-list">
      {items.map((item, i) => (
        <li key={`${i}-${String(item.value)}`}>
          <Untrusted value={item.value} max={60} />
          <strong>{item.count}</strong>
        </li>
      ))}
    </ul>
  );
}

/** @param {{ used: number, budget: number | null, label: string }} props */
export function Meter({ used, budget, label }) {
  const pct = budget ? Math.min(100, Math.round((used / budget) * 100)) : 0;
  return (
    <div className="meter">
      <div className="meter-label">
        <span>{label}</span>
        <span>{budget ? `${used.toLocaleString()} / ${budget.toLocaleString()} (${pct}%)` : `${used.toLocaleString()}`}</span>
      </div>
      <div className="meter-track" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className={`meter-fill ${pct >= 90 ? "hot" : ""}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
