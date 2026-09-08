-- ---------------------------------------------------------------------------
-- Vigil schema.
--
-- Three rules shape this file:
--
--   1. SSH private keys are never stored in plaintext. Every secret column is
--      suffixed _enc and holds an AES-256-GCM envelope produced by
--      server/crypto/secrets.mjs. The database alone cannot decrypt them.
--   2. Servers belong to a user, not to a tenant. Every query that touches a
--      server is scoped by user_id, and there is no path in the application
--      that reads a server row without one.
--   3. Findings and anomalies are derived - recomputed from the latest scan on
--      every read - so improving a rule never rewrites history. What IS a fact
--      is a scan, and someone's acknowledgement of a finding; those are stored.
--
-- Written to be idempotent: it runs on every boot.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          text NOT NULL,
  name           text NOT NULL,
  password_hash  text NOT NULL,
  disabled       boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_login_at  timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  ip          text,
  user_agent  text
);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Servers.
--
-- private_key_enc holds the SSH private key the app authenticates with. It is
-- sealed under a key that lives outside the database, decrypted into memory for
-- the length of one connection, and never written to disk - not to a temp file,
-- not to an agent socket. The application has no endpoint that returns it.
--
-- host_key_fp is trust-on-first-use: the server's host key fingerprint is
-- recorded on the first successful connection and every later connection is
-- refused if it changes. That is what turns "we ignore host keys" into a real
-- man-in-the-middle check, and it is why re-imaged hosts need an explicit reset.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name              text NOT NULL,
  host              text NOT NULL,
  port              integer NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
  username          text NOT NULL,
  private_key_enc   text NOT NULL,
  passphrase_enc    text,
  host_key_fp       text,
  tags              text[] NOT NULL DEFAULT '{}',
  status            text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'healthy', 'error', 'disabled')),
  last_error        text,
  last_scan_at      timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS servers_user_name_key ON servers (user_id, lower(name));
CREATE INDEX IF NOT EXISTS servers_user_idx ON servers (user_id);

-- ---------------------------------------------------------------------------
-- Scans.
--
-- One row per collection run. `facts` is the parsed output of the probe;
-- `findings` is what the rules made of it, stored alongside so a finding can
-- always be read back exactly as it was raised even after a rule changes.
--
-- `limited` names the checks that could not run at full fidelity - almost
-- always because the login has no sudo. An empty array means everything ran.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id    uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz,
  ok           boolean NOT NULL DEFAULT false,
  error        text,
  duration_ms  integer,
  facts        jsonb,
  findings     jsonb NOT NULL DEFAULT '[]'::jsonb,
  anomalies    jsonb NOT NULL DEFAULT '[]'::jsonb,
  limited      text[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS scans_server_time_idx ON scans (server_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scans_user_time_idx ON scans (user_id, started_at DESC);

-- ---------------------------------------------------------------------------
-- Acknowledgements.
--
-- Findings are recomputed on every scan, so silencing one means remembering the
-- acknowledgement rather than editing the finding.
--
-- value_at_ack is what makes this an acknowledgement rather than a mute: the
-- finding comes back if it gets materially worse than the state someone
-- accepted. A disk acknowledged at 82% full reappears at 91%.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding_acks (
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id     uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  finding_key   text NOT NULL,
  reason        text,
  value_at_ack  double precision,
  actor         text NOT NULL,
  acked_at      timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz,
  PRIMARY KEY (server_id, finding_key)
);

CREATE INDEX IF NOT EXISTS finding_acks_user_idx ON finding_acks (user_id);

-- Per-user preferences. Absent means "use the instance default", which is why
-- there is no row created at sign-up and every read falls back.
CREATE TABLE IF NOT EXISTS user_settings (
  user_id       uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  -- Minutes between automatic sweeps. 0 disables them, and scanning becomes
  -- something a person triggers.
  scan_minutes  integer NOT NULL DEFAULT 15 CHECK (scan_minutes >= 0 AND scan_minutes <= 1440),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Append-only. Nothing in the application ever updates or deletes a row here.
CREATE TABLE IF NOT EXISTS audit_log (
  id       bigserial PRIMARY KEY,
  user_id  uuid REFERENCES users(id) ON DELETE SET NULL,
  actor    text NOT NULL,
  event    text NOT NULL,
  detail   text NOT NULL,
  meta     jsonb,
  at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_user_time_idx ON audit_log (user_id, at DESC);
