-- Daily call counters for external providers (threat intel now, LLM later).
-- Reserved atomically before each call so restarts or multiple workers can
-- never exceed a free-tier quota.
CREATE TABLE provider_usage (
  provider TEXT NOT NULL,
  day      DATE NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC')::date,
  calls    INTEGER NOT NULL DEFAULT 0,
  tokens   BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, day)
);
