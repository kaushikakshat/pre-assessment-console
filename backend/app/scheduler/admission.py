"""Global concurrency gate. Every admission takes the scheduler_config row lock, so the running-job count can
never exceed the limit across processes; nothing is counted in memory."""
from dataclasses import dataclass

from sqlalchemy import exists, func, select, text, update

from app.core.audit import record
from app.models import Job, ModuleRun, SchedulerConfig, Worker

CEILING = 3
LEASE_SECONDS = 60
HEALTHY_SECONDS = 30
ACTIVE = ("running", "cancelling")
ENGINE_MODULES = {"crawl", "dast", "api"}  # these go through the shared ZAP engine
# Effective priority: rank (High 0, Normal 1, Low 2) minus one per elapsed aging period, floor 0; ties by seq.
ORDER = text("""GREATEST((CASE priority WHEN 'High' THEN 0 WHEN 'Normal' THEN 1 ELSE 2 END)
  - (CASE WHEN :aging THEN floor(extract(epoch FROM now() - submitted_at) / 60 / GREATEST(:mins, 1))::int ELSE 0 END), 0), seq""")


@dataclass
class Capacity:
    active: int
    limit: int
    effective_limit: int
    queued: int
    healthy_workers: int
    ceiling: int
    blocked_reason: str | None


def healthy_workers(db) -> int:
    return db.scalar(select(func.count()).select_from(Worker).where(
        Worker.enabled, Worker.last_heartbeat_at > func.now() - text(f"interval '{HEALTHY_SECONDS} seconds'")))


def uses_engine(module_keys) -> bool:
    return bool(ENGINE_MODULES & set(module_keys))


def engine_healthy(db) -> bool:
    return bool(db.scalar(select(func.count()).select_from(Worker).where(
        Worker.enabled, Worker.engine_ok,
        Worker.last_heartbeat_at > func.now() - text(f"interval '{HEALTHY_SECONDS} seconds'"))))


def _count(db, *states):
    return db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(states)))


def _cfg(db, lock=False):
    q = select(SchedulerConfig).where(SchedulerConfig.id == 1).execution_options(populate_existing=True)
    return db.scalar(q.with_for_update() if lock else q)


def capacity(db) -> Capacity:
    cfg, healthy = _cfg(db), healthy_workers(db)
    return Capacity(_count(db, *ACTIVE), cfg.concurrency_limit, min(cfg.concurrency_limit, healthy), _count(db, "queued"),
                    healthy, CEILING, "emergency" if cfg.emergency else "paused" if cfg.paused else None)


def claim_next(db, worker_id: str) -> Job | None:
    """worker_id is the worker's registered name. One transaction; returns the job now running, or None."""
    cfg = _cfg(db, lock=True)  # serialises all admissions
    worker = db.scalar(select(Worker).where(Worker.name == worker_id))
    if cfg.paused or cfg.emergency or not worker or not worker.enabled \
            or _count(db, *ACTIVE) >= min(cfg.concurrency_limit, healthy_workers(db)):
        db.rollback()
        return None
    params = {"aging": cfg.aging_enabled, "mins": cfg.aging_minutes}
    q = select(Job).where(Job.state == "queued")
    on_engine = exists().where(ModuleRun.job_id == Job.id, ModuleRun.key.in_(ENGINE_MODULES))
    if db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(ACTIVE), on_engine)) >= cfg.engine_slots:
        q = q.where(~on_engine)  # slots full: a Quick Scan behind an engine job may still start
    job = db.scalar(q.order_by(ORDER.bindparams(**params))
                    .limit(1).with_for_update(skip_locked=True))
    if not job:
        db.rollback()
        return None
    job.state, job.started_at, job.lease_owner = "running", func.now(), worker_id
    job.lease_expires_at = func.now() + text(f"interval '{LEASE_SECONDS} seconds'")
    job.attempt += 1
    worker.current_job_id = job.id
    record(db, "scheduler", "job", "dispatched", job.display_id, "success", "Job dispatched to a worker")
    db.commit()
    return job


def heartbeat(db, worker_id: str, job_id: int | None = None, engine_ok: bool | None = None) -> bool:
    """Returns False when the caller no longer holds the job's lease (it was reaped or reassigned)."""
    vals = {"last_heartbeat_at": func.now(), **({} if engine_ok is None else {"engine_ok": engine_ok})}
    db.execute(update(Worker).where(Worker.name == worker_id).values(**vals))
    held = True
    if job_id is not None:
        held = db.execute(update(Job).where(Job.id == job_id, Job.lease_owner == worker_id, Job.state.in_(ACTIVE))
                          .values(lease_expires_at=func.now() + text(f"interval '{LEASE_SECONDS} seconds'"))
                          ).rowcount == 1
    db.commit()
    return held


def reap_expired(db) -> int:
    """Jobs whose worker stopped heartbeating become 'interrupted' for admin review; never 'completed'."""
    jobs = db.scalars(select(Job).where(Job.state.in_(ACTIVE), Job.lease_expires_at < func.now())
                      .with_for_update(skip_locked=True)).all()
    for j in jobs:
        j.state, j.ended_at = "interrupted", func.now()
        db.execute(update(ModuleRun).where(ModuleRun.job_id == j.id, ModuleRun.state.in_(("queued", "running")))
                   .values(state="interrupted", ended_at=func.now()))
        db.execute(update(Worker).where(Worker.current_job_id == j.id).values(current_job_id=None))
        record(db, "scheduler", "job", "interrupted", j.display_id, "failure",
               "Worker stopped responding; partial results preserved")
    db.commit()
    return len(jobs)


def queued_order(db) -> list[int]:
    cfg = _cfg(db)
    return list(db.scalars(select(Job.id).where(Job.state == "queued")
                           .order_by(ORDER.bindparams(aging=cfg.aging_enabled, mins=cfg.aging_minutes))))


def queue_position(db, job: Job) -> int | None:
    if job.state != "queued":
        return None
    ids = queued_order(db)
    return ids.index(job.id) + 1 if job.id in ids else None


def wait_estimate(position: int | None) -> dict | None:
    """Naive, Quick Scan only: 5-15 minutes per job ahead (including this one)."""
    return None if position is None else {"lo_min": position * 5, "hi_min": position * 15}
