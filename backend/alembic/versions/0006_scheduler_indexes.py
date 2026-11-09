"""queue-order index and uniqueness backstops for module runs and finding fingerprints

Revision ID: 0006
"""
from alembic import op

revision = "0006"
down_revision = "0005"


def upgrade():
    op.execute("""
CREATE INDEX ix_jobs_state_seq ON jobs(state, seq);
CREATE UNIQUE INDEX ux_module_runs_job_key ON module_runs(job_id, key);
CREATE UNIQUE INDEX ux_findings_assessment_fingerprint ON findings(assessment_id, fingerprint);""")


def downgrade():
    raise NotImplementedError("forward-only")
