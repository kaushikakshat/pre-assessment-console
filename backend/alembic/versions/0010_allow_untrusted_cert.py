"""assessments.allow_untrusted_cert: owner opt-in to scan test environments with self-signed or internal-CA certificates

Revision ID: 0010
"""
from alembic import op

revision = "0010"
down_revision = "0009"


def upgrade():
    op.execute("ALTER TABLE assessments ADD COLUMN allow_untrusted_cert boolean NOT NULL DEFAULT false;")


def downgrade():
    raise NotImplementedError("forward-only")
