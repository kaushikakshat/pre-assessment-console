"""initial schema, grants, seed

Revision ID: 0001
"""
import json

from alembic import op

revision = "0001"
down_revision = None

POLICY_V1 = {
    "no_match": "approval",
    "permitted_ports": [80, 443, 8080, 8443],
    "rules": [{"id": "R-01", "outcome": "allow", "match": "domain", "value": "testtarget",
               "internal": True, "dev_only": True, "note": "Local demo target (dev only)"}],
}

SEQS = {"user_display_seq": 0, "assessment_display_seq": 0, "job_display_seq": 0,
        "finding_display_seq": 0, "job_seq": 0}


def _disp(seq, prefix, width):
    return f"text NOT NULL UNIQUE DEFAULT '{prefix}' || lpad(nextval('{seq}')::text, {width}, '0')"


def upgrade():
    for s in SEQS:
        op.execute(f"CREATE SEQUENCE {s}")
    op.execute(f"""
CREATE TABLE users (
  id serial PRIMARY KEY,
  display_id {_disp('user_display_seq', 'U-', 3)},
  name text NOT NULL, email text NOT NULL UNIQUE, role text NOT NULL CHECK (role IN ('owner','admin')),
  team text, status text NOT NULL DEFAULT 'active', password_hash text NOT NULL, totp_secret text,
  mfa_enrolled boolean NOT NULL DEFAULT false, last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE sessions (
  id text PRIMARY KEY, user_id integer NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, revoked_at timestamptz);
CREATE INDEX ix_sessions_user_id ON sessions(user_id);
CREATE TABLE login_attempts (
  id serial PRIMARY KEY, email text NOT NULL, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_login_attempts_email ON login_attempts(email);
CREATE TABLE policy_versions (
  version text PRIMARY KEY, rules jsonb NOT NULL, published_at timestamptz NOT NULL DEFAULT now(),
  published_by text, status text NOT NULL DEFAULT 'active');
CREATE TABLE assessments (
  id serial PRIMARY KEY,
  display_id {_disp('assessment_display_seq', 'A-', 4)},
  owner_id integer NOT NULL REFERENCES users(id), name text NOT NULL, target text NOT NULL, env text NOT NULL,
  hosts text NOT NULL DEFAULT '', paths text NOT NULL DEFAULT '', ports text NOT NULL DEFAULT '',
  exclusions text NOT NULL DEFAULT '', notes text, status text NOT NULL DEFAULT 'draft',
  validation jsonb, policy_version text REFERENCES policy_versions(version), approval jsonb,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_assessments_owner_id ON assessments(owner_id);
CREATE TABLE jobs (
  id serial PRIMARY KEY,
  display_id {_disp('job_display_seq', 'JOB-', 6)},
  seq bigint NOT NULL UNIQUE DEFAULT nextval('job_seq'),
  assessment_id integer NOT NULL REFERENCES assessments(id), requested_by integer NOT NULL REFERENCES users(id),
  type text NOT NULL DEFAULT 'scan', profile text, priority text NOT NULL DEFAULT 'Normal',
  state text NOT NULL DEFAULT 'queued', submitted_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz, ended_at timestamptz, policy_version text REFERENCES policy_versions(version),
  idempotency_key text NOT NULL UNIQUE, lease_owner text, lease_expires_at timestamptz,
  attempt integer NOT NULL DEFAULT 0, note text, resume_of integer REFERENCES jobs(id), review text,
  cancel_requested boolean NOT NULL DEFAULT false);
CREATE INDEX ix_jobs_assessment_id ON jobs(assessment_id);
CREATE INDEX ix_jobs_state ON jobs(state);
CREATE TABLE module_runs (
  id serial PRIMARY KEY, job_id integer NOT NULL REFERENCES jobs(id), key text NOT NULL,
  state text NOT NULL DEFAULT 'queued', detail text, started_at timestamptz, ended_at timestamptz,
  tool_version text);
CREATE INDEX ix_module_runs_job_id ON module_runs(job_id);
CREATE TABLE findings (
  id serial PRIMARY KEY,
  display_id {_disp('finding_display_seq', 'F-', 4)},
  assessment_id integer NOT NULL REFERENCES assessments(id), job_id integer NOT NULL REFERENCES jobs(id),
  module text NOT NULL, severity text NOT NULL, confidence text NOT NULL, state text NOT NULL DEFAULT 'new',
  title text NOT NULL, asset text NOT NULL, location jsonb NOT NULL, description text NOT NULL,
  impact text NOT NULL, evidence text NOT NULL, reproduce text NOT NULL, remediation text NOT NULL,
  "references" jsonb NOT NULL DEFAULT '[]', fingerprint text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
  history jsonb NOT NULL DEFAULT '[]', comments jsonb NOT NULL DEFAULT '[]');
CREATE INDEX ix_findings_assessment_id ON findings(assessment_id);
CREATE INDEX ix_findings_fingerprint ON findings(fingerprint);
CREATE TABLE workers (
  id serial PRIMARY KEY, name text NOT NULL UNIQUE, enabled boolean NOT NULL DEFAULT true,
  last_heartbeat_at timestamptz, current_job_id integer REFERENCES jobs(id));
CREATE TABLE scheduler_config (
  id integer PRIMARY KEY CHECK (id = 1), concurrency_limit integer NOT NULL DEFAULT 1,
  aging_enabled boolean NOT NULL DEFAULT true, aging_minutes integer NOT NULL DEFAULT 15,
  queue_cap integer NOT NULL DEFAULT 50, per_user_quota integer NOT NULL DEFAULT 5,
  paused boolean NOT NULL DEFAULT false, emergency boolean NOT NULL DEFAULT false, reason text);
CREATE TABLE audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(),
  actor text NOT NULL, area text NOT NULL, action text NOT NULL, object text NOT NULL,
  outcome text NOT NULL, detail text NOT NULL, policy_version text);

INSERT INTO scheduler_config (id) VALUES (1);
""")
    op.get_bind().exec_driver_sql(
        "INSERT INTO policy_versions (version, rules, published_by) VALUES ('v1', %s::jsonb, 'system')",
        (json.dumps(POLICY_V1),))
    # app_user is created by db/init-app-role.sh; audit_events stays append-only for it.
    op.execute("""
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, login_attempts, policy_versions, assessments,
  jobs, module_runs, findings, workers, scheduler_config TO app_user;
GRANT SELECT, INSERT ON audit_events TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
""")


def downgrade():
    raise NotImplementedError("forward-only")
