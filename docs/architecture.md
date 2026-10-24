# Architecture notes

The diagram, feature list and threat model are in the [README](../README.md). This page
covers how data moves and where each security control sits.

## Data flow

1. **Capture.** A sensor (`honeypots/ssh`, `honeypots/http`) records an attacker action and
   queues it in memory (bounded, batched, with backoff).
2. **Ingest.** `POST /ingest/v1/events` with the sensor's bearer token. Each event is
   validated with zod (`backend/src/ingest/eventSchema.js`), sanitized, truncated, and stored
   in `events`. `sensor_id` comes from the token.
3. **Correlate.** The worker attaches new events to incidents by `src_ip` with an inactivity
   window, recomputes features, ATT&CK techniques and severity (`backend/src/correlation/`).
4. **Enrich.** For new incidents, the worker queries the configured threat-intel providers
   for public IPs only, with caching and quotas (`backend/src/enrichment/`).
5. **Analyze.** On creation or a significant change (debounced), the agent builds a delimited,
   escaped incident summary, calls the LLM if configured and within budget, validates the
   JSON, and falls back to a rule-only report otherwise (`backend/src/agent/`).
6. **Propose.** Recommended actions pass the policy engine. Survivors are stored as `pending`
   proposals; violations go to `audit_log`.
7. **Decide.** An admin approves or rejects in the dashboard with a reason. An approved block
   becomes `active` until its TTL (or a revoke) expires it.
8. **Enforce.** `GET /edl/blocklist.txt` serves active blocks to a firewall EDL or to
   `enforcer/enforcer.sh` on a separate VM.

## Trust boundaries

| Boundary | Control |
| --- | --- |
| Internet → sensor | Fake services only; no execution; connection and session limits; distroless, read-only, no-caps containers |
| Sensor → backend | HTTPS + per-sensor token; strict schema; per-sensor rate limit; sensor can't choose its `sensor_id` |
| Backend → threat intel | public IPs only; responses reduced to allow-listed, sanitized fields |
| Backend → LLM | untrusted data in a nonce-delimited, escaped block; canary; strict output schema; budgets |
| LLM → actions | policy engine in code; proposals only; human approval; TTL caps; audit log |
| Dashboard → user | JWT with server-side roles; demo masking; CSP; attacker data rendered as text only |
| Backend → firewall | EDL token or basic auth; approved, active, policy-checked IPs only |

## Processes and state

- **API** and **worker** are the same image (`backend/`) with different entrypoints, or one
  process with `EMBEDDED_WORKER=true` on free hosting.
- All state lives in Postgres: events, incidents, reports, proposals, audit log, enrichment
  cache, quotas, metrics counters, pg-boss queues, worker heartbeat.
- The worker's correlator holds a session advisory lock, so only one instance correlates at
  a time; queue jobs are deduplicated per incident or IP (`stately` policy).
