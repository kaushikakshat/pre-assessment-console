"""login_attempts.ip for per-IP throttling

Revision ID: 0002
"""
from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade():
    op.execute("""
ALTER TABLE login_attempts ADD COLUMN ip text;
CREATE INDEX ix_login_attempts_ip ON login_attempts(ip);
""")


def downgrade():
    raise NotImplementedError("forward-only")
