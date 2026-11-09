"""reports.claimed_at: when a worker started rendering (staleness clock)

Revision ID: 0011
"""
from alembic import op

revision = "0011"
down_revision = "0010"


def upgrade():
    op.execute("ALTER TABLE reports ADD COLUMN claimed_at timestamptz;")


def downgrade():
    raise NotImplementedError("forward-only")
