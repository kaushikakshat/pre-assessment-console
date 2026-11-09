"""phase 3: login_setups, credentials, wordlists, reports; engine slots, retest and wordlist columns

Revision ID: 0008
"""
from alembic import op

revision = "0008"
down_revision = "0007"

PROFILE_LIMITS = ('{"pre": {"budget_min": 30, "request_cap": 5000, "rate_per_s": 10}, '
                  '"deep": {"budget_min": 180, "request_cap": 50000, "rate_per_s": 10}}')


def upgrade():
    op.execute("CREATE SEQUENCE credential_display_seq")
    op.execute("CREATE SEQUENCE report_display_seq")
    op.execute(f"""
CREATE TABLE login_setups (
  assessment_id integer PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
  style text NOT NULL CHECK (style IN ('single','two-step')),
  login_url text NOT NULL, username_field text NOT NULL, password_field text NOT NULL,
  code_field text, otp_url text, otp_field text, bypass_code_enc bytea,
  logged_in_indicator text NOT NULL, logged_out_indicator text,
  updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE credentials (
  id serial PRIMARY KEY,
  display_id text NOT NULL UNIQUE DEFAULT 'C-' || lpad(nextval('credential_display_seq')::text, 4, '0'),
  assessment_id integer NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  role_label text NOT NULL, username_enc bytea NOT NULL, password_enc bytea NOT NULL,
  last_test text CHECK (last_test IN ('ok','failed')), last_tested_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz);
CREATE INDEX ix_credentials_assessment_id ON credentials(assessment_id);
CREATE TABLE wordlists (
  key text PRIMARY KEY, category text NOT NULL CHECK (category IN ('discovery','fuzzing')),
  label text NOT NULL, lines integer NOT NULL, enabled boolean NOT NULL DEFAULT true);
CREATE TABLE reports (
  id serial PRIMARY KEY,
  display_id text NOT NULL UNIQUE DEFAULT 'R-' || lpad(nextval('report_display_seq')::text, 4, '0'),
  assessment_id integer NOT NULL REFERENCES assessments(id),
  job_id integer NOT NULL REFERENCES jobs(id),
  type text NOT NULL CHECK (type IN ('management','technical')),
  version integer NOT NULL,
  state text NOT NULL DEFAULT 'generating' CHECK (state IN ('generating','ready','failed')),
  model jsonb, pdf_path text, requested_by integer NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(), error text,
  UNIQUE (assessment_id, type, version));
CREATE INDEX ix_reports_job_id ON reports(job_id);

ALTER TABLE jobs ADD COLUMN wordlists jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN retest_of jsonb,
  ADD COLUMN credential_ids jsonb NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN credential_id integer;
ALTER TABLE module_runs ADD COLUMN untested integer NOT NULL DEFAULT 0;
ALTER TABLE scheduler_config
  ADD COLUMN engine_slots integer NOT NULL DEFAULT 1 CHECK (engine_slots BETWEEN 1 AND 3),
  ADD COLUMN profile_limits jsonb NOT NULL DEFAULT '{PROFILE_LIMITS}';
ALTER TABLE workers ADD COLUMN engine_ok boolean NOT NULL DEFAULT false;

GRANT SELECT, INSERT, UPDATE, DELETE ON login_setups, credentials, wordlists, reports TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
""")


def downgrade():
    raise NotImplementedError("forward-only")
