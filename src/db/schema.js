export const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    phone_encrypted TEXT,
    phone_key_version INTEGER NOT NULL DEFAULT 1,
    mfa_secret_encrypted TEXT,
    mfa_key_version INTEGER NOT NULL DEFAULT 1,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`,

  `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,

  `CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content_encrypted TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,

  `CREATE INDEX IF NOT EXISTS idx_notes_owner_id ON notes(owner_id)`,

  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  )`,

  `CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON password_reset_tokens(user_id)`,

  `CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warn', 'critical')),
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_user_id TEXT,
    ip_address TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`,

  `CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)`,

  `CREATE TABLE IF NOT EXISTS security_alerts (
    id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warn', 'critical')),
    summary TEXT NOT NULL,
    ip_address TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged')),
    created_at TEXT NOT NULL
  )`,
];

export async function runMigrations(db) {
  for (const statement of SCHEMA_STATEMENTS) {
    await db.exec(statement);
  }
}
