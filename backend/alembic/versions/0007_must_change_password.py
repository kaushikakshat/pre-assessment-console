"""users.must_change_password: forces a new password after an admin-issued temporary one

Revision ID: 0007
"""
from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade():
    op.execute("ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false")


def downgrade():
    raise NotImplementedError("forward-only")
