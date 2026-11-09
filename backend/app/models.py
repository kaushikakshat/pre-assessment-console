from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Identity, Integer, Sequence, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import DateTime

NOW = text("now()")
_ts = lambda **kw: mapped_column(DateTime(timezone=True), **kw)  # noqa: E731


def _display(seq, prefix, width):
    return text(f"'{prefix}' || lpad(nextval('{seq}')::text, {width}, '0')")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    display_id: Mapped[str] = mapped_column(Text, unique=True, server_default=_display("user_display_seq", "U-", 3))
    name: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(Text, unique=True)
    role: Mapped[str] = mapped_column(Text)  # owner | admin
    team: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="active")
    password_hash: Mapped[str] = mapped_column(Text)
    totp_secret: Mapped[str | None] = mapped_column(Text)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, server_default="false")
    last_totp_step: Mapped[int | None] = mapped_column(BigInteger)
    last_login_at: Mapped[datetime | None] = _ts()
    validating_until: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = _ts(server_default=NOW)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(Text, primary_key=True)  # sha256 of the cookie token
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = _ts(server_default=NOW)
    expires_at: Mapped[datetime] = _ts()
    revoked_at: Mapped[datetime | None] = _ts()


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(Text, index=True)
    ip: Mapped[str | None] = mapped_column(Text, index=True)
    at: Mapped[datetime] = _ts(server_default=NOW)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    version: Mapped[str] = mapped_column(Text, primary_key=True)
    rules: Mapped[dict] = mapped_column(JSONB)
    published_at: Mapped[datetime] = _ts(server_default=NOW)
    published_by: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="published")


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    display_id: Mapped[str] = mapped_column(Text, unique=True, server_default=_display("assessment_display_seq", "A-", 4))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    env: Mapped[str] = mapped_column(Text)
    hosts: Mapped[str] = mapped_column(Text, server_default="")
    paths: Mapped[str] = mapped_column(Text, server_default="")
    ports: Mapped[str] = mapped_column(Text, server_default="")
    exclusions: Mapped[str] = mapped_column(Text, server_default="")
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="draft")
    validation: Mapped[dict | None] = mapped_column(JSONB)
    policy_version: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.version"))
    approval: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = _ts(server_default=NOW)
    updated_at: Mapped[datetime] = _ts(server_default=NOW)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    display_id: Mapped[str] = mapped_column(Text, unique=True, server_default=_display("job_display_seq", "JOB-", 6))
    seq: Mapped[int] = mapped_column(BigInteger, Sequence("job_seq"), unique=True, server_default=text("nextval('job_seq')"))
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    type: Mapped[str] = mapped_column(Text, server_default="scan")
    profile: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(Text, server_default="Normal")
    state: Mapped[str] = mapped_column(Text, server_default="queued", index=True)
    submitted_at: Mapped[datetime] = _ts(server_default=NOW)
    started_at: Mapped[datetime | None] = _ts()
    ended_at: Mapped[datetime | None] = _ts()
    policy_version: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.version"))
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    lease_owner: Mapped[str | None] = mapped_column(Text)
    lease_expires_at: Mapped[datetime | None] = _ts()
    attempt: Mapped[int] = mapped_column(Integer, server_default="0")
    note: Mapped[str | None] = mapped_column(Text)
    resume_of: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"))
    review: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, server_default="false")


class ModuleRun(Base):
    __tablename__ = "module_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    key: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, server_default="queued")
    detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = _ts()
    ended_at: Mapped[datetime | None] = _ts()
    tool_version: Mapped[str | None] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    display_id: Mapped[str] = mapped_column(Text, unique=True, server_default=_display("finding_display_seq", "F-", 4))
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    module: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, server_default="new")
    title: Mapped[str] = mapped_column(Text)
    asset: Mapped[str] = mapped_column(Text)
    location: Mapped[dict] = mapped_column(JSONB)
    description: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)  # redacted before insert
    reproduce: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONB, server_default="[]")
    fingerprint: Mapped[str] = mapped_column(Text, index=True)
    first_seen_at: Mapped[datetime] = _ts(server_default=NOW)
    last_seen_at: Mapped[datetime] = _ts(server_default=NOW)
    history: Mapped[list] = mapped_column(JSONB, server_default="[]")
    comments: Mapped[list] = mapped_column(JSONB, server_default="[]")


class Worker(Base):
    __tablename__ = "workers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    last_heartbeat_at: Mapped[datetime | None] = _ts()
    current_job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"))


class SchedulerConfig(Base):
    __tablename__ = "scheduler_config"
    id: Mapped[int] = mapped_column(primary_key=True)  # always 1
    concurrency_limit: Mapped[int] = mapped_column(Integer, server_default="1")
    aging_enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    aging_minutes: Mapped[int] = mapped_column(Integer, server_default="15")
    queue_cap: Mapped[int] = mapped_column(Integer, server_default="50")
    per_user_quota: Mapped[int] = mapped_column(Integer, server_default="5")
    paused: Mapped[bool] = mapped_column(Boolean, server_default="false")
    emergency: Mapped[bool] = mapped_column(Boolean, server_default="false")
    reason: Mapped[str | None] = mapped_column(Text)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = _ts(server_default=NOW)
    actor: Mapped[str] = mapped_column(Text)
    area: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    object: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str | None] = mapped_column(Text)
