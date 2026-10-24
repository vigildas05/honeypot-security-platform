-- Normalized event pipeline + SOC tables.
-- All attacker-controlled columns are TEXT and were already truncated/sanitized
-- at ingest; they must still be treated as untrusted everywhere downstream.

-- ---------------------------------------------------------------------------
-- Dashboard users (bcrypt hashes, role-based access)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE CHECK (char_length(username) BETWEEN 1 AND 64),
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin', 'demo')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Normalized sensor events
-- ---------------------------------------------------------------------------
CREATE TABLE events (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL,              -- time reported by the sensor
  received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),-- time the backend accepted it
  sensor_id     TEXT NOT NULL,                     -- bound to the ingest token, not client-chosen
  protocol      TEXT NOT NULL CHECK (protocol IN ('ssh', 'http')),
  event_type    TEXT NOT NULL CHECK (event_type IN ('connect', 'auth_attempt', 'command', 'request', 'session_closed')),
  src_ip        INET NOT NULL,
  src_port      INTEGER CHECK (src_port BETWEEN 0 AND 65535),
  session_id    TEXT,
  -- ssh
  username      TEXT,
  password      TEXT,
  auth_method   TEXT,
  auth_success  BOOLEAN,
  command       TEXT,
  -- http
  http_method   TEXT,
  http_path     TEXT,
  user_agent    TEXT,
  http_headers  JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- common
  country       TEXT,
  raw           TEXT,
  truncated     BOOLEAN NOT NULL DEFAULT FALSE,
  legacy_attack_id BIGINT UNIQUE                   -- set only for rows backfilled from `attacks`
);

CREATE INDEX idx_events_ts          ON events (ts DESC);
CREATE INDEX idx_events_src_ip_ts   ON events (src_ip, ts DESC);
CREATE INDEX idx_events_protocol_ts ON events (protocol, ts DESC);
CREATE INDEX idx_events_session     ON events (session_id) WHERE session_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Threat-intel enrichment cache (one row per ip/provider)
-- ---------------------------------------------------------------------------
CREATE TABLE ip_enrichment_cache (
  ip          INET NOT NULL,
  provider    TEXT NOT NULL,
  data        JSONB,
  error       TEXT,
  fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (ip, provider)
);

CREATE INDEX idx_enrichment_expires ON ip_enrichment_cache (expires_at);

-- ---------------------------------------------------------------------------
-- Incidents (deterministic correlation by src_ip + inactivity window)
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
  id                    BIGSERIAL PRIMARY KEY,
  src_ip                INET NOT NULL,
  status                TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  first_seen            TIMESTAMPTZ NOT NULL,
  last_seen             TIMESTAMPTZ NOT NULL,
  event_count           INTEGER NOT NULL DEFAULT 0,
  severity              TEXT NOT NULL DEFAULT 'low' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  severity_score        INTEGER NOT NULL DEFAULT 0,
  techniques            JSONB NOT NULL DEFAULT '[]'::jsonb,  -- rule-mapped ATT&CK techniques
  tags                  TEXT[] NOT NULL DEFAULT '{}',
  stats                 JSONB NOT NULL DEFAULT '{}'::jsonb,   -- aggregate counters used by rules/agent
  analyzed_event_count  INTEGER NOT NULL DEFAULT 0,          -- event_count at last agent run (debounce)
  last_analyzed_at      TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_src_ip_last_seen ON incidents (src_ip, last_seen DESC);
CREATE INDEX idx_incidents_last_seen        ON incidents (last_seen DESC);
CREATE INDEX idx_incidents_severity         ON incidents (severity);
CREATE INDEX idx_incidents_tags             ON incidents USING GIN (tags);
CREATE INDEX idx_incidents_techniques       ON incidents USING GIN (techniques jsonb_path_ops);

CREATE TABLE incident_events (
  incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  event_id    BIGINT NOT NULL UNIQUE REFERENCES events (id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, event_id)
);

-- ---------------------------------------------------------------------------
-- Agent reports (LLM or rule-only fallback; always labeled)
-- ---------------------------------------------------------------------------
CREATE TABLE agent_reports (
  id                BIGSERIAL PRIMARY KEY,
  incident_id       BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  source            TEXT NOT NULL CHECK (source IN ('llm', 'rules')),
  ai_generated      BOOLEAN NOT NULL,
  model             TEXT,
  prompt_version    TEXT,
  report            JSONB NOT NULL,
  validation_status TEXT NOT NULL CHECK (validation_status IN ('valid', 'retried_valid', 'fallback')),
  fallback_reason   TEXT,
  tokens_in         INTEGER,
  tokens_out        INTEGER,
  latency_ms        INTEGER,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (ai_generated = (source = 'llm'))
);

CREATE INDEX idx_agent_reports_incident ON agent_reports (incident_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Proposed response actions (human-in-the-loop)
-- pending -> approved | rejected ; approved -> active -> expired
-- ---------------------------------------------------------------------------
CREATE TABLE proposed_actions (
  id              BIGSERIAL PRIMARY KEY,
  incident_id     BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  report_id       BIGINT REFERENCES agent_reports (id) ON DELETE SET NULL,
  action_type     TEXT NOT NULL CHECK (action_type IN ('block_ip', 'watchlist', 'no_action')),
  target          INET,
  reason          TEXT NOT NULL,
  ttl_hours       INTEGER CHECK (ttl_hours > 0),
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected', 'active', 'expired')),
  proposed_by     TEXT NOT NULL CHECK (proposed_by IN ('llm', 'rules')),
  decided_by      TEXT,
  decided_at      TIMESTAMPTZ,
  decision_reason TEXT,
  activated_at    TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (action_type = 'no_action' OR target IS NOT NULL)
);

CREATE INDEX idx_proposed_actions_status ON proposed_actions (status, created_at DESC);
CREATE INDEX idx_proposed_actions_target ON proposed_actions (target, status);
CREATE INDEX idx_proposed_actions_incident ON proposed_actions (incident_id);

-- ---------------------------------------------------------------------------
-- Append-only audit log
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor       TEXT NOT NULL,           -- username, or 'system:<component>'
  actor_role  TEXT,
  action      TEXT NOT NULL,           -- e.g. action.approve, policy.violation, agent.canary_leak
  target_type TEXT,
  target_id   TEXT,
  details     JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id  TEXT
);

CREATE INDEX idx_audit_log_ts     ON audit_log (ts DESC);
CREATE INDEX idx_audit_log_action ON audit_log (action, ts DESC);

CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ---------------------------------------------------------------------------
-- Backfill legacy `attacks` rows into `events`.
-- Rows whose ip is not a valid INET are skipped rather than failing the migration.
-- (pg_input_is_valid is PG16+, so use an exception-safe helper for PG14/15 hosts.)
-- ---------------------------------------------------------------------------
CREATE FUNCTION pg_temp.safe_inet(value TEXT) RETURNS INET AS $$
BEGIN
  RETURN value::inet;
EXCEPTION WHEN others THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

INSERT INTO events (
  ts, received_at, sensor_id, protocol, event_type, src_ip,
  username, password, auth_method, auth_success,
  http_method, http_path, user_agent, http_headers, country, raw, legacy_attack_id
)
SELECT
  a.timestamp,
  a.timestamp,
  'legacy-' || lower(a.service),
  lower(a.protocol),
  CASE WHEN lower(a.protocol) = 'ssh' THEN 'auth_attempt' ELSE 'request' END,
  pg_temp.safe_inet(regexp_replace(a.ip, '^::ffff:', '')),
  left(a.username, 256),
  left(a.password, 256),
  CASE WHEN lower(a.protocol) = 'ssh' THEN left(a.metadata ->> 'authMethod', 32) END,
  CASE WHEN lower(a.protocol) = 'ssh' THEN FALSE END,
  left(a.method, 16),
  left(a.path, 2048),
  left(a.user_agent, 1024),
  '{}'::jsonb,
  a.country,
  NULL,
  a.id
FROM attacks a
WHERE lower(a.protocol) IN ('ssh', 'http')
  AND pg_temp.safe_inet(regexp_replace(a.ip, '^::ffff:', '')) IS NOT NULL;
