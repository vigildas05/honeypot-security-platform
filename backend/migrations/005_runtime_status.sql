-- Heartbeat + non-secret runtime config published by background components
-- (e.g. which LLM model / intel providers the worker has, and its budgets),
-- so the API can show it without holding the worker's secrets.
CREATE TABLE runtime_status (
  component  TEXT PRIMARY KEY,
  data       JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
