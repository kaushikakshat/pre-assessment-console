"""policy drafts: nullable published_at, draft metadata, one draft and one published row

Revision ID: 0013
"""
from alembic import op

revision = "0013"
down_revision = "0012"


def upgrade():
    op.execute("""
        ALTER TABLE policy_versions ALTER COLUMN published_at DROP NOT NULL, ALTER COLUMN published_at DROP DEFAULT,
          ADD COLUMN note text, ADD COLUMN created_by text, ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
          ADD COLUMN rev integer NOT NULL DEFAULT 0, ADD COLUMN dry_run jsonb, ADD COLUMN validation jsonb,
          ADD CONSTRAINT policy_status_ck CHECK (status IN ('draft','published','superseded'))""")
    op.execute("CREATE UNIQUE INDEX policy_one_draft ON policy_versions ((true)) WHERE status = 'draft'")
    op.execute("CREATE UNIQUE INDEX policy_one_published ON policy_versions ((true)) WHERE status = 'published'")
    op.execute("UPDATE policy_versions SET note = 'Initial policy' WHERE version = 'v1' AND note IS NULL")


def downgrade():
    raise NotImplementedError("forward-only")
