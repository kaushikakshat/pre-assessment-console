"""users.validating_until: DB lease limiting each user to one in-flight validation

Revision ID: 0005
"""
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade():
    op.execute("ALTER TABLE users ADD COLUMN validating_until timestamptz")


def downgrade():
    raise NotImplementedError("forward-only")
