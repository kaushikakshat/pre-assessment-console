"""policy_versions.status uses 'published' for the version in force

Revision ID: 0004
"""
from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade():
    op.execute("""
ALTER TABLE policy_versions ALTER COLUMN status SET DEFAULT 'published';
UPDATE policy_versions SET status = 'published' WHERE status = 'active';
""")


def downgrade():
    raise NotImplementedError("forward-only")
