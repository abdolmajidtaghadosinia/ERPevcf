-- Schema (same tables as live/server.js) + the single admin user. No demo data.
CREATE TABLE IF NOT EXISTS companies (id TEXT PRIMARY KEY, name TEXT NOT NULL, sector TEXT, location TEXT, extra TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT, role TEXT NOT NULL, company_id TEXT, active INTEGER NOT NULL, extra TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY, company_id TEXT NOT NULL, assessor_id TEXT, status TEXT NOT NULL,
  submitted_at TEXT, finalized_at TEXT, updated_at TEXT,
  responses TEXT NOT NULL, evidence TEXT NOT NULL, reviews TEXT NOT NULL, rev_comments TEXT NOT NULL, snapshot TEXT, extra TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (sid_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, question_id TEXT NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL,
  stored_name TEXT NOT NULL, uploader TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS files_by_assessment ON files (assessment_id);
-- shared login lockout (Workers have no shared memory between requests)
CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL);

-- The only user. Its password is set from the ADMIN_PASSWORD secret on the first login (see README).
INSERT OR IGNORE INTO users (id, username, display_name, role, company_id, active, extra)
VALUES ('u-admin', 'admin', 'مدیر سامانه', 'ADMIN', NULL, 1, '{"title":"مدیر سامانه"}');
