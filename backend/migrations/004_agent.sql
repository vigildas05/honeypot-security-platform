-- SOC agent bookkeeping.

-- What the incident looked like at its last analysis (severity|techniques|tags),
-- used to decide whether an update is "significant" enough to re-run the agent.
ALTER TABLE incidents ADD COLUMN analyzed_signature TEXT;

-- One row per LLM call (including retries and failures). Never stores the
-- prompt or reply: those contain attacker data and the canary.
CREATE TABLE llm_calls (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  incident_id BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
  model       TEXT,
  attempt     SMALLINT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('valid', 'invalid', 'canary_leak', 'error')),
  detail      TEXT,
  latency_ms  INTEGER,
  tokens_in   INTEGER NOT NULL DEFAULT 0,
  tokens_out  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_llm_calls_ts ON llm_calls (ts DESC);

-- Daily counters for agent/pipeline metrics, written by the worker and read by the API.
CREATE TABLE metric_counters (
  day   DATE NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC')::date,
  name  TEXT NOT NULL,
  value BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (day, name)
);
