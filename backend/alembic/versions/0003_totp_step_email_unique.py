"""last_totp_step (replay protection), case-insensitive unique email

Revision ID: 0003
"""
from alembic import op

revision = "0003"
down_revision = "0002"


def upgrade():
    op.execute("""
ALTER TABLE users ADD COLUMN last_totp_step bigint;
CREATE UNIQUE INDEX ux_users_email_lower ON users (lower(email));
""")


def downgrade():
    raise NotImplementedError("forward-only")
