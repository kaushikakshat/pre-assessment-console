"""dev-only internal-target rule R-02 for the demo portal (ignored unless APP_ENV=dev)

Revision ID: 0012
"""
import json

from alembic import op

revision = "0012"
down_revision = "0011"

RULE = {"id": "R-02", "outcome": "allow", "match": "domain", "value": "testportal",
        "internal": True, "dev_only": True, "note": "Local demo portal (dev only)"}


def upgrade():
    # appended in place like R-01: the dev rule must not mint a new policy version label
    op.get_bind().exec_driver_sql(
        "UPDATE policy_versions SET rules = jsonb_set(rules, '{rules}', (rules->'rules') || %s::jsonb) WHERE version = 'v1'",
        (json.dumps([RULE]),))


def downgrade():
    raise NotImplementedError("forward-only")
