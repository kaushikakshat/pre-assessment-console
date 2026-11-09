"""Scan worker: registers, heartbeats, reaps expired leases, claims one job at a time through the DB gate and
runs its modules sequentially in a thread while the main thread keeps the lease alive."""
import hashlib
import logging
import os
import signal
import socket
import threading
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.audit import record
from app.core.startup import validate_env
from app.db import SessionLocal
from app.models import Assessment, Finding, Job, ModuleRun, PolicyVersion, Worker
from app.scheduler.admission import ACTIVE, claim_next, heartbeat, reap_expired
from app.targets import ipguard
from app.targets.safe_http import BlockedAddress, RequestCapExceeded, SafeClient, ScopeError
from app.targets.validate import _internal, first_rule, parse_target
from app.worker.modules import MODULES, TIMEOUTS
from app.worker.modules.base import Blocked, Ctx
from app.worker.redact import redact

log = logging.getLogger("worker")
REQUEST_CAP, DEFAULT_TIMEOUT, LOOP_SECONDS, HEARTBEAT_SECONDS, MAX_MISSES = 50, 120, 2, 10, 3


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def final_state(states) -> str:
    if all(s == "completed" for s in states):
        return "completed"
    return "completed-warnings" if any(s in ("completed", "completed-warnings") for s in states) else "failed"


def store_findings(db, job, assessment, module, drafts):
    """Dedupe by sha256(module|title|asset): a repeat only refreshes last_seen_at and the job reference."""
    db.execute(select(func.pg_advisory_xact_lock(assessment.id)))
    for d in drafts:
        for f in ("title", "asset", "description", "impact", "reproduce", "remediation"):
            setattr(d, f, redact(getattr(d, f)))  # header values reach these fields too
        fp = hashlib.sha256(f"{module}|{d.title}|{d.asset}".encode()).hexdigest()
        old = db.scalar(select(Finding).where(Finding.assessment_id == assessment.id, Finding.fingerprint == fp))
        if old:
            old.last_seen_at, old.job_id = func.now(), job.id
            old.history = [*old.history, {"at": _now(), "by": "System", "text": f"Seen again in {job.display_id}"}]
        else:
            db.add(Finding(assessment_id=assessment.id, job_id=job.id, module=module, severity=d.severity,
                           confidence=d.confidence, title=d.title, asset=d.asset, location=d.location,
                           description=d.description, impact=d.impact, evidence=redact(d.evidence), reproduce=d.reproduce,
                           remediation=d.remediation, references=d.references, fingerprint=fp,
                           history=[{"at": _now(), "by": "System", "text": f"Found in {job.display_id}"}]))
    db.flush()


def _internal_allowance(a, policy, resolver):
    """Re-derive the private-address allowance the validation used (same rule engine, same policy version)."""
    try:
        host = parse_target(a.target).host
        addrs = ipguard.resolve(host, resolver)
        return _internal(first_rule(policy, host, addrs, a.env), os.environ.get("APP_ENV", "prod"), addrs)
    except (ValueError, OSError):
        return False


def execute_module(key, ctx_args, timeout):
    """-> (state, detail, findings, tool_version). Never raises; every failure is plain and never 'completed'."""
    client = SafeClient({ctx_args["host"]}, ctx_args["internal_hosts"], max_requests=REQUEST_CAP,
                        resolver=ctx_args["resolver"])
    ctx = Ctx(**{k: v for k, v in ctx_args.items() if k != "internal_hosts"}, client=client,
              deadline=time.monotonic() + timeout)
    try:
        r = MODULES[key](ctx)
        return r.state, r.detail, r.findings, r.tool_version
    except Blocked:
        return "inconclusive", "Target rate-limited or blocked the requests", [], None
    except (TimeoutError, RequestCapExceeded):
        return "inconclusive", "The check ran out of time or request budget before it finished.", [], None
    except (httpx.HTTPError, OSError, BlockedAddress, ScopeError):
        return "failed", "Could not connect to the target.", [], None
    except Exception:
        log.exception("module %s crashed", key)
        return "failed", "The check could not be completed.", [], None
    finally:
        client.close()


def _gate(db, job_id, worker):
    """None to continue, else 'lost' | 'cancelled' | 'blocked'. Read fresh before every module."""
    row = db.execute(select(Job.state, Job.cancel_requested, Job.lease_owner, Assessment.status)
                     .join(Assessment, Assessment.id == Job.assessment_id).where(Job.id == job_id)).one()
    db.rollback()
    if row.lease_owner != worker or row.state not in ACTIVE:
        return "lost"
    if row.cancel_requested or row.state == "cancelling":
        return "cancelled"
    return "blocked" if row.status != "active" else None


def _end(db, job, worker, state, module_state, detail):
    ok = db.execute(update(Job).where(Job.id == job.id, Job.lease_owner == worker, Job.state.in_(ACTIVE))
                    .values(state=state, ended_at=func.now(), lease_expires_at=None)).rowcount
    if ok:
        if module_state:
            db.execute(update(ModuleRun).where(ModuleRun.job_id == job.id, ModuleRun.state == "queued")
                       .values(state=module_state, detail=detail, ended_at=func.now()))
        db.execute(update(Worker).where(Worker.name == worker).values(current_job_id=None))
        record(db, "system", "job", state, job.display_id, "failure" if state in ("failed", "blocked") else "success",
               detail or f"Job {state}")
    db.commit()


def run_job(job_id, worker, halt, resolver=socket.getaddrinfo):
    """halt: set on SIGTERM or lost lease; the job is then left for the lease to expire (never marked done)."""
    with SessionLocal() as db:
        job, a = db.get(Job, job_id), None
        a = db.get(Assessment, job.assessment_id)
        pv = db.get(PolicyVersion, job.policy_version or a.policy_version) if (job.policy_version or a.policy_version) else None
        policy = {**pv.rules, "version": pv.version} if pv else {}
        p = parse_target(a.target)
        args = {"url": a.target, "scheme": p.scheme, "host": p.host, "port": p.effective_port,
                "permitted_ports": {p.effective_port, *(int(x) for x in a.ports.replace(",", " ").split() if x.isdigit())},
                "resolver": resolver}
        internal = _internal_allowance(a, policy, resolver)
        args["internal"] = internal
        args["internal_hosts"] = {} if internal is False else {p.host: internal}
        keys = list(db.scalars(select(ModuleRun.key).where(ModuleRun.job_id == job_id).order_by(ModuleRun.id)))
        states = []
        for key in keys:
            if halt.is_set():
                return
            why = _gate(db, job_id, worker)
            if why == "lost":
                return
            if why:
                return _end(db, job, worker, why, why, "Cancelled before it started" if why == "cancelled"
                            else "The assessment is no longer approved for scanning")
            if key not in MODULES:
                state, detail, found, tool = "unavailable", "Not available in this release", [], None
            else:
                db.execute(update(ModuleRun).where(ModuleRun.job_id == job_id, ModuleRun.key == key,
                                                   ModuleRun.state == "queued").values(state="running", started_at=func.now()))
                db.commit()
                state, detail, found, tool = execute_module(key, args, TIMEOUTS.get(key, DEFAULT_TIMEOUT))
            if halt.is_set():
                return
            # Guarded on state='running' (or queued for unavailable): a reaped job's module is no longer ours to write.
            done = db.execute(update(ModuleRun).where(ModuleRun.job_id == job_id, ModuleRun.key == key,
                                                      ModuleRun.state.in_(("running", "queued")))
                              .values(state=state, detail=detail, tool_version=tool, ended_at=func.now(),
                                      started_at=func.coalesce(ModuleRun.started_at, func.now()))).rowcount
            if not done:
                db.rollback()
                return
            store_findings(db, job, a, key, found)
            db.commit()
            states.append(state)
        why = _gate(db, job_id, worker)
        if why == "lost":
            return
        if why:
            return _end(db, job, worker, why, why, None)
        _end(db, job, worker, final_state(states), None, "")


def register(db, name):
    db.execute(insert(Worker).values(name=name, last_heartbeat_at=func.now())
               .on_conflict_do_update(index_elements=["name"], set_={"last_heartbeat_at": func.now()}))
    record(db, "system", "worker", "registered", "worker", "success", "Worker registered")
    db.commit()


def _safe_run(*a):
    try:
        run_job(*a)
    except Exception:
        log.exception("job crashed; its lease will expire and an admin will review it")


def run_with_lease(job_id, name, stop):
    """Keeps the lease alive while the module thread runs. Returns only once that thread has ended (or the
    process is stopping), so a worker never claims more work while a module is still sending traffic."""
    halt = threading.Event()  # per job: set on SIGTERM, a lost lease, or too many missed heartbeats
    t = threading.Thread(target=_safe_run, args=(job_id, name, halt), daemon=True)
    t.start()
    last, misses = time.monotonic(), 0
    while t.is_alive() and not halt.is_set():
        t.join(min(1, HEARTBEAT_SECONDS))
        if stop.is_set():
            halt.set()
            return
        if time.monotonic() - last >= HEARTBEAT_SECONDS and t.is_alive():
            last = time.monotonic()
            try:
                with SessionLocal() as db:
                    misses = 0 if heartbeat(db, name, job_id) else MAX_MISSES
            except Exception:
                misses += 1
                log.exception("heartbeat failed")
            if misses >= MAX_MISSES:  # 3 x 10s is under the 60s lease: stop before the job can be reaped under us
                halt.set()
    while t.is_alive():  # halted: wait for the module to wind down; keep the worker itself marked healthy
        t.join(min(1, HEARTBEAT_SECONDS))
        if stop.is_set():
            return
        if time.monotonic() - last >= HEARTBEAT_SECONDS:
            last = time.monotonic()
            try:
                with SessionLocal() as db:
                    heartbeat(db, name)
            except Exception:
                log.exception("heartbeat failed")


def main():
    validate_env()
    name, stop = socket.gethostname(), threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    with SessionLocal() as db:
        register(db, name)
    log.info("worker started")
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                heartbeat(db, name)
                reap_expired(db)
                job = None if stop.is_set() else claim_next(db, name)
                job_id = job.id if job else None
            if job_id:
                run_with_lease(job_id, name, stop)  # SIGTERM sets stop: thread abandons, the lease expires
                continue
        except Exception:
            log.exception("worker loop error")
        stop.wait(LOOP_SECONDS)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
