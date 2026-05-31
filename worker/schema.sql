CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  encrypted_password TEXT NOT NULL,
  ip_hash TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_reset_at
ON rate_limits (reset_at);
