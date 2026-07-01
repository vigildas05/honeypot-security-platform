CREATE TABLE IF NOT EXISTS attacks (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip TEXT NOT NULL,
  country TEXT,
  protocol TEXT NOT NULL,
  service TEXT NOT NULL,
  username TEXT,
  password TEXT,
  user_agent TEXT,
  method TEXT,
  path TEXT,
  headers JSONB DEFAULT '{}'::jsonb,
  metadata JSONB DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'captured',
  connection_duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks (ip);
CREATE INDEX IF NOT EXISTS idx_attacks_service ON attacks (service);
