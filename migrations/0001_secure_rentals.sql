CREATE TABLE rentals (
 id TEXT PRIMARY KEY,
 record TEXT NOT NULL,
 document_key TEXT NOT NULL UNIQUE,
 document_type TEXT NOT NULL,
 document_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active',
 created_at TEXT NOT NULL
);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE audit (id INTEGER PRIMARY KEY, rental_id TEXT, action TEXT NOT NULL, occurred_at TEXT NOT NULL);
CREATE TABLE login_attempts (client_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL, window_start INTEGER NOT NULL);
