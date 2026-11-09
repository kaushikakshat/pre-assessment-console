"""credentials.username_hint (plaintext hint; the API cannot decrypt) and findings.credential_id FK

Revision ID: 0009
"""
from alembic import op

revision = "0009"
down_revision = "0008"


def upgrade():
    op.execute("""
ALTER TABLE credentials ADD COLUMN username_hint text NOT NULL DEFAULT '';
UPDATE findings SET credential_id = NULL WHERE credential_id IS NOT NULL
  AND credential_id NOT IN (SELECT id FROM credentials);
ALTER TABLE findings ADD CONSTRAINT findings_credential_id_fkey
  FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL;
""")


def downgrade():
    raise NotImplementedError("forward-only")
