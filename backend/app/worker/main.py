"""Scan worker: registers, heartbeats, reaps expired leases, claims one job at a time through the DB gate and
runs its modules sequentially in a thread while the main thread keeps the lease alive."""
import contextlib
import hashlib
import logging
import os
import signal
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.audit import record
from app.core import crypto
from app.core.startup import validate_env
from app.engine import stages
from app.engine.zap import EngineDown, EngineError
from app.db import SessionLocal
from app.models import Assessment, Credential, Finding, Job, LoginSetup, ModuleRun, PolicyVersion, SchedulerConfig, Worker
from app.scheduler.admission import ACTIVE, ENGINE_MODULES, claim_next, heartbeat, reap_expired
from app.targets import ipguard
from app.targets.safe_http import BlockedAddress, RequestCapExceeded, SafeClient, ScopeError
from app.targets.validate import _internal, first_rule, parse_target
from app.worker.modules import MODULES, TIMEOUTS, wordlists
from app.worker.modules.base import Blocked, Ctx
from app.worker.redact import redact

log = logging.getLogger("worker")
REQUEST_CAPS = {"access": 500, "cval": 200}  # replays are many small requests; every other module keeps 50
REQUEST_CAP, DEFAULT_TIMEOUT, LOOP_SECONDS, HEARTBEAT_SECONDS, MAX_MISSES = 50, 120, 2, 10, 3


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def final_state(states) -> str:
    if all(s == "completed" for s in states):
        return "completed"
    return "completed-warnings" if any(s in ("completed", "completed-warnings") for s in states) else "failed"


def fingerprint(module, d):
    return hashlib.sha256(f"{module}|{d.fingerprint_key or f'{d.title}|{d.asset}'}".encode()).hexdigest()


def confirm_findings(db, job, assessment, confirmed):
    """cval: drafts already stored (their text was redacted in place) whose re-check reproduced."""
    for module, d in confirmed:
        f = db.scalar(select(Finding).where(Finding.assessment_id == assessment.id, Finding.fingerprint == fingerprint(module, d)))
        if f and f.confidence != "confirmed":
            f.confidence = "confirmed"
            f.history = [*f.history, {"at": _now(), "by": "System", "text": "Confirmed by control validation"}]
    db.flush()


def load_accounts(db, a, run_ctx):
    """Sealed blobs only: the auth module opens them into locals. Plaintext never enters run_ctx."""
    setup = db.get(LoginSetup, a.id)
    creds = db.execute(select(Credential.display_id, Credential.role_label, Credential.username_enc, Credential.password_enc)
                       .where(Credential.assessment_id == a.id, Credential.deleted_at.is_(None)).order_by(Credential.id)).all()
    if setup and creds:
        run_ctx["accounts"] = [(c.display_id, c.role_label, bytes(c.username_enc), bytes(c.password_enc)) for c in creds]
        run_ctx["login"] = {k: getattr(setup, k) for k in ("style", "login_url", "username_field", "password_field",
                            "logged_in_indicator", "code_field", "otp_url", "otp_field", "logged_out_indicator", "bypass_code_enc")}


def store_findings(db, job, assessment, module, drafts):
    """Dedupe by sha256(module|title|asset): a repeat only refreshes last_seen_at and the job reference."""
    db.execute(select(func.pg_advisory_xact_lock(assessment.id)))
    for d in drafts:
        for f in ("title", "asset", "description", "impact", "reproduce", "remediation"):
            setattr(d, f, redact(getattr(d, f)))  # header values reach these fields too
        cred = db.scalar(select(Credential.id).where(Credential.display_id == d.credential_id)) if d.credential_id else None
        fp = fingerprint(module, d)
        old = db.scalar(select(Finding).where(Finding.assessment_id == assessment.id, Finding.fingerprint == fp))
        if old:
            old.last_seen_at, old.job_id = func.now(), job.id
            old.history = [*old.history, {"at": _now(), "by": "System", "text": f"Seen again in {job.display_id}"}]
        else:
            db.add(Finding(assessment_id=assessment.id, job_id=job.id, module=module, severity=d.severity,
                           confidence=d.confidence, title=d.title, asset=d.asset, location=d.location,
                           description=d.description, impact=d.impact, evidence=redact(d.evidence), reproduce=d.reproduce,
                           remediation=d.remediation, references=d.references, fingerprint=fp, credential_id=cred,
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


ENGINE_DOWN = "The scanning engine is not running."


UNTRUSTED_CERT = "The site's certificate is not trusted. Tick 'Allow untrusted certificate' on the assessment to scan test environments."


def _cert_failure(e) -> bool:
    while e is not None:
        if isinstance(e, ssl.SSLCertVerificationError):
            return True
        e = e.__cause__ or e.__context__
    return False


def execute_module(key, ctx_args, timeout, stage_deadline=None, run_ctx=None):
    """-> (state, detail, findings, tool_version, untested). Never raises; every failure is plain and never 'completed'.
    stage_deadline (absolute monotonic) caps the module's own timeout; run_ctx is shared across the job's modules."""
    rc = run_ctx if run_ctx is not None else {}
    wl = bool(rc.get("wordlists")) and key in ("exposed", "dast")  # wordlist modules may use the profile's request cap
    client = SafeClient({ctx_args["host"]}, ctx_args["internal_hosts"],
                        max_requests=rc.get("request_cap", REQUEST_CAP) if wl else REQUEST_CAPS.get(key, REQUEST_CAP),
                        resolver=ctx_args["resolver"], verify=ctx_args.get("verify", True))
    deadline = time.monotonic() + timeout
    ctx = Ctx(**{k: v for k, v in ctx_args.items() if k not in ("internal_hosts", "verify")}, client=client,
              deadline=min(deadline, stage_deadline) if stage_deadline else deadline,
              run_ctx=run_ctx if run_ctx is not None else {})
    try:
        r = MODULES[key](ctx)
        return r.state, r.detail, r.findings, r.tool_version, r.untested
    except EngineDown:
        return "unavailable", ENGINE_DOWN, [], None, 0
    except EngineError as e:
        return "failed", str(e), [], None, 0
    except Blocked:
        return "inconclusive", "Target rate-limited or blocked the requests", [], None, 0
    except (TimeoutError, RequestCapExceeded):
        return "inconclusive", "The check ran out of time or request budget before it finished.", [], None, 0
    except (httpx.HTTPError, OSError, BlockedAddress, ScopeError) as e:
        if _cert_failure(e):
            return "failed", UNTRUSTED_CERT, [], None, 0
        return "failed", "Could not connect to the target.", [], None, 0
    except Exception:
        log.exception("module %s crashed", key)
        return "failed", "The check could not be completed.", [], None, 0
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
    with SessionLocal() as db, contextlib.ExitStack() as stack:  # stack closes the engine session on every exit
        job, a = db.get(Job, job_id), None
        a = db.get(Assessment, job.assessment_id)
        pv = db.get(PolicyVersion, job.policy_version or a.policy_version) if (job.policy_version or a.policy_version) else None
        policy = {**pv.rules, "version": pv.version} if pv else {}
        p = parse_target(a.target)
        args = {"url": a.target, "scheme": p.scheme, "host": p.host, "port": p.effective_port,
                "permitted_ports": {p.effective_port, *(int(x) for x in a.ports.replace(",", " ").split() if x.isdigit())},
                "resolver": resolver, "verify": not a.allow_untrusted_cert}
        internal = _internal_allowance(a, policy, resolver)
        args["internal"] = internal
        args["internal_hosts"] = {} if internal is False else {p.host: internal}
        keys = list(db.scalars(select(ModuleRun.key).where(ModuleRun.job_id == job_id).order_by(ModuleRun.id)))
        states, run_ctx, engine_down = [], {"profile": job.profile, "notes": a.notes or "", "wordlists": list(job.wordlists or [])}, False
        if "auth" in keys:
            load_accounts(db, a, run_ctx)
        limits = db.scalar(select(SchedulerConfig.profile_limits).where(SchedulerConfig.id == 1)) or {}
        run_ctx["request_cap"] = limits.get(job.profile, {}).get("request_cap", REQUEST_CAP)
        run_ctx["rate_per_s"] = limits.get(job.profile, {}).get("rate_per_s", 10)
        budget_s = limits.get(job.profile, {}).get("budget_min", {"pre": 30, "deep": 180}.get(job.profile)) if job.profile else None
        budget = stages.Budget(budget_s * 60, keys) if budget_s else None
        scope = {"hosts": {p.host}, "ports": args["permitted_ports"],
                 "internal": {h: None if n is None else [str(x) for x in n] for h, n in args["internal_hosts"].items()}}
        for key in keys:
            if halt.is_set():
                return
            why = _gate(db, job_id, worker)
            if why == "lost":
                return
            if why:
                return _end(db, job, worker, why, why, "Cancelled before it started" if why == "cancelled"
                            else "The assessment is no longer approved for scanning")
            if key in ENGINE_MODULES and key in MODULES and not engine_down and "session" not in run_ctx:
                try:
                    s = stack.enter_context(stages.EngineSession(job, a, scope, ttl_s=(budget_s * 60 if budget_s else 3600) + 120))
                    run_ctx.update(session=s, zap=s.zap, exclude=s.exclude)
                except (EngineDown, EngineError):
                    engine_down = True
            if key not in MODULES:
                state, detail, found, tool, untested = "unavailable", "Not available in this release", [], None, 0
            elif key in ENGINE_MODULES and engine_down:
                state, detail, found, tool, untested = "unavailable", ENGINE_DOWN, [], None, 0
            else:
                db.execute(update(ModuleRun).where(ModuleRun.job_id == job_id, ModuleRun.key == key,
                                                   ModuleRun.state == "queued").values(state="running", started_at=func.now()))
                db.commit()
                timeout, sd = TIMEOUTS.get(key, DEFAULT_TIMEOUT), None
                if key == "exposed" and run_ctx["wordlists"] and budget_s:
                    timeout = budget_s * 60 * stages.SPLIT["crawl"]  # discovery lists need more than the default 120 s
                sd = budget.start(key) if budget and key in stages.MODULE_STAGE else None
                if sd:
                    timeout = max(0.0, sd - time.monotonic())  # staged modules run to their share of the stage
                state, detail, found, tool, untested = execute_module(key, args, timeout, sd, run_ctx)
            if budget and key in stages.MODULE_STAGE:
                budget.end(key)  # unused time flows to the next module or stage
            if halt.is_set():
                return
            # Guarded on state='running' (or queued for unavailable): a reaped job's module is no longer ours to write.
            done = db.execute(update(ModuleRun).where(ModuleRun.job_id == job_id, ModuleRun.key == key,
                                                      ModuleRun.state.in_(("running", "queued")))
                              .values(state=state, detail=detail, tool_version=tool, untested=untested, ended_at=func.now(),
                                      started_at=func.coalesce(ModuleRun.started_at, func.now()))).rowcount
            if not done:
                db.rollback()
                return
            store_findings(db, job, a, key, found)
            if key == "exposed":  # cval re-checks these; access records its own suspects
                run_ctx.setdefault("suspects", []).extend({"module": key, "draft": d, "method": "GET", "url": d.location["url"],
                                                           "owner": None, "who": None, "form": None}
                                                          for d in found if d.confidence == "suspected")
            if key == "cval":
                confirm_findings(db, job, a, run_ctx.get("confirmed", []))
            db.commit()
            states.append(state)
        why = _gate(db, job_id, worker)
        if why == "lost":
            return
        if why:
            return _end(db, job, worker, why, why, None)
        _end(db, job, worker, final_state(states), None, "")


def engine_ok() -> bool:
    """The engine answers and the egress guard is reachable; either one down means Deep/Pre cannot run safely."""
    url, ctl = os.environ.get("ENGINE_URL"), os.environ.get("EGRESS_CONTROL")
    if not url or not ctl:
        return False
    try:
        with httpx.Client(timeout=2) as c:
            return (c.get(f"{url}/JSON/core/view/version/", params={"apikey": os.environ.get("ZAP_API_KEY", "")}).status_code == 200
                    and c.get(f"{ctl}/stats", headers={"X-Egress-Token": os.environ.get("EGRESS_TOKEN", "")}).status_code == 200)
    except httpx.HTTPError:
        return False


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
                    misses = 0 if heartbeat(db, name, job_id, engine_ok=engine_ok()) else MAX_MISSES
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
                    heartbeat(db, name, engine_ok=engine_ok())
            except Exception:
                log.exception("heartbeat failed")


def main():
    validate_env("worker")
    crypto.enable_decryption()
    name, stop = socket.gethostname(), threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    with SessionLocal() as db:
        register(db, name)
        try:
            wordlists.seed(db)
        except Exception:
            log.exception("wordlist seeding failed")
            db.rollback()
    log.info("worker started")
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                heartbeat(db, name, engine_ok=engine_ok())
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
