import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api import assessments as asm
from app.api.jobs import apply_cancel, capacity_shape, shape as job_shape
from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, AuditEvent, Job, ModuleRun, SchedulerConfig, User, Wordlist, Worker
from app.scheduler import admission

router = APIRouter(prefix="/admin", dependencies=[Depends(sec.require_admin)])
AUDIT_CAP = 500
LIVE = ("queued", "scheduled", "running", "cancelling")


def reason_of(s: str) -> str:
    s = s.strip()
    if not s:
        raise HTTPException(422, {"fields": {"reason": "Enter a reason."}})
    return s


def audit_shape(e: AuditEvent) -> dict:
    return {"id": str(e.id), "at": e.at, "actor": e.actor, "area": e.area, "action": e.action, "object": e.object,
            "outcome": e.outcome, "detail": e.detail, "policy_version": e.policy_version}


def recent_audit(db, *where, limit=10):
    return [audit_shape(e) for e in db.scalars(select(AuditEvent).where(*where).order_by(AuditEvent.id.desc()).limit(limit))]


def worker_shape(db, w: Worker) -> dict:
    fresh = w.last_heartbeat_at and datetime.now(timezone.utc) - w.last_heartbeat_at < timedelta(seconds=admission.HEALTHY_SECONDS)
    cur = db.scalar(select(Job.display_id).where(Job.id == w.current_job_id)) if w.current_job_id else None
    return {"id": str(w.id), "name": w.name, "status": ("healthy" if fresh else "heartbeat-lost") if w.enabled else "standby",
            "enabled": w.enabled, "last_seen_at": w.last_heartbeat_at, "current_job": cur}


def workers(db):
    return [worker_shape(db, w) for w in db.scalars(select(Worker).order_by(Worker.id))]


def admin_job(db, j: Job) -> dict:
    a = db.get(Assessment, j.assessment_id)
    return {**job_shape(db, j), "owner": db.get(User, a.owner_id).name, "target": a.target}


def pending_assessments(db):
    return db.scalars(select(Assessment).where(Assessment.status == "awaiting-approval",
                                               Assessment.approval["state"].astext == "pending").order_by(Assessment.updated_at))


# ---- overview ----
@router.get("/overview")
def overview(db=Depends(get_db)):
    running = db.scalars(select(Job).where(Job.state.in_(admission.ACTIVE)).order_by(Job.seq)).all()
    return {"capacity": capacity_shape(db), "workers": workers(db),
            "approvals_pending": len(pending_assessments(db).all()),
            "interrupted_unreviewed": db.scalar(select(func.count()).select_from(Job).where(
                Job.state == "interrupted", Job.review.is_(None))),
            "running": [admin_job(db, j) for j in running], "recent_audit": recent_audit(db)}


# ---- assessments & approvals ----
@router.get("/assessments")
def all_assessments(db=Depends(get_db)):
    return [{**asm.summary(db, a), "owner": {"id": o.display_id, "name": o.name}}
            for a, o in db.execute(select(Assessment, User).join(User, User.id == Assessment.owner_id).order_by(Assessment.id.desc()))]


@router.get("/approvals")
def approvals(admin=Depends(sec.require_admin), db=Depends(get_db)):
    return [{"assessment": asm.shape(db, a, admin), "requested_at": a.updated_at, "own": a.owner_id == admin.id}
            for a in pending_assessments(db)]


class DecisionIn(BaseModel):
    decision: Literal["approve", "refuse"]
    note: str = Field("", max_length=1000)


@router.post("/approvals/{aid}")
def decide(aid: str, body: DecisionIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    note = body.note.strip()
    if not note:
        raise HTTPException(422, {"fields": {"note": "Enter a note."}})
    a = db.scalar(select(Assessment).where(Assessment.display_id == aid).with_for_update())
    if not a:
        raise HTTPException(404, "Not found.")
    if a.status != "awaiting-approval" or (a.approval or {}).get("state") != "pending":
        raise HTTPException(409, "This assessment is not waiting for approval.")
    approve, own = body.decision == "approve", a.owner_id == admin.id
    if approve and any(c.get("result") == "fail" for c in (a.validation or {}).get("checks", [])):
        raise HTTPException(409, "A failed safety check cannot be approved.")  # safety invariants are never overridden
    a.status = "active" if approve else "blocked"
    a.approval = {"state": "approved" if approve else "refused", "note": note, "by": admin.name,
                  "at": datetime.now(timezone.utc).isoformat(), "self": own}
    a.updated_at = func.now()
    action = "self-approval" if approve and own else body.decision
    record(db, admin.email, "approval", action, a.display_id, "success",
           f"{note}" + (" (self-approval: the approver owns this assessment)" if own else ""), a.policy_version)
    db.commit()
    db.refresh(a)
    return asm.shape(db, a, admin)


# ---- jobs ----
@router.get("/jobs")
def jobs(filter: Literal["active", "interrupted", "all"] = "active", db=Depends(get_db)):
    q = select(Job).order_by(Job.id.desc()).limit(500)
    if filter != "all":
        q = q.where(Job.state.in_(LIVE if filter == "active" else ("interrupted",)))
    return [admin_job(db, j) for j in db.scalars(q)]


def locked_job(db, jid: str) -> Job:
    j = db.scalar(select(Job).where(Job.display_id == jid).with_for_update())
    if not j:
        raise HTTPException(404, "Not found.")
    return j


class ReasonIn(BaseModel):
    reason: str = Field("", max_length=1000)


@router.post("/jobs/{jid}/cancel")
def cancel(jid: str, body: ReasonIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    j = locked_job(db, jid)
    apply_cancel(db, j, admin.email, f". Reason: {reason}")
    return admin_job(db, j)


class PriorityIn(ReasonIn):
    priority: Literal["High", "Normal", "Low"]


@router.post("/jobs/{jid}/priority")
def priority(jid: str, body: PriorityIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    j = locked_job(db, jid)
    if j.state != "queued":
        raise HTTPException(409, "Priority can only be changed while a scan is queued.")
    old, j.priority = j.priority, body.priority
    record(db, admin.email, "job", "priority", j.display_id, "success", f"{old} -> {body.priority}. Reason: {reason}")
    db.commit()
    return admin_job(db, j)


class ReviewIn(ReasonIn):
    outcome: Literal["resume", "rerun-advised", "closed"]


@router.post("/jobs/{jid}/review")
def review(jid: str, body: ReviewIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    j = locked_job(db, jid)
    if j.state != "interrupted" or j.review is not None:
        raise HTTPException(409, "Only an interrupted scan that has not been reviewed can be reviewed.")
    detail = f"{body.outcome}. Reason: {reason}"
    if body.outcome == "resume":
        a = db.scalar(select(Assessment).where(Assessment.id == j.assessment_id).with_for_update())
        if a.status != "active":
            raise HTTPException(409, "This assessment is no longer active, so the scan cannot be resumed.")
        if db.scalar(select(Job.id).where(Job.assessment_id == a.id, Job.state.in_(LIVE)).limit(1)):
            raise HTTPException(409, "This assessment already has a queued or running scan.")
        keys = db.scalars(select(ModuleRun.key).where(ModuleRun.job_id == j.id, ModuleRun.state.in_(("interrupted", "queued")))
                          .order_by(ModuleRun.id)).all()
        new = Job(assessment_id=a.id, requested_by=admin.id, profile=j.profile, priority=j.priority,
                  policy_version=a.policy_version, resume_of=j.id, idempotency_key=f"resume:{j.id}")
        db.add(new)
        db.flush()
        db.refresh(new)
        db.add_all(ModuleRun(job_id=new.id, key=k) for k in ["reach", *(k for k in keys if k != "reach")])
        detail += f" Resumed as {new.display_id}"
    j.review = {"resume": "resumed"}.get(body.outcome, body.outcome)
    record(db, admin.email, "job", "review", j.display_id, "success", detail)
    db.commit()
    db.refresh(j)
    return admin_job(db, j)


# ---- capacity & workers ----
def capacity_response(db) -> dict:
    c = admission._cfg(db)
    return {"config": {"limit": c.concurrency_limit, "aging_enabled": c.aging_enabled, "aging_minutes": c.aging_minutes,
                       "queue_cap": c.queue_cap, "per_user_quota": c.per_user_quota, "paused": c.paused,
                       "engine_slots": c.engine_slots, "profile_limits": c.profile_limits},
            "capacity": capacity_shape(db), "workers": workers(db),
            "history": recent_audit(db, AuditEvent.area.in_(("capacity", "worker")), limit=20)}


@router.get("/capacity")
def get_capacity(db=Depends(get_db)):
    return capacity_response(db)


class ProfileLimit(BaseModel):
    budget_min: int = Field(ge=5, le=600)
    request_cap: int = Field(ge=100, le=200000)
    rate_per_s: int = Field(ge=1, le=50)


class CapacityIn(ReasonIn):
    limit: int = Field(ge=1, le=admission.CEILING)
    aging_enabled: bool
    aging_minutes: int = Field(ge=1, le=1440)
    queue_cap: int = Field(ge=1, le=10000)
    per_user_quota: int = Field(ge=1, le=1000)
    engine_slots: int | None = Field(None, ge=1, le=3)
    profile_limits: dict[Literal["pre", "deep"], ProfileLimit] | None = None


@router.put("/capacity")
def put_capacity(body: CapacityIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    cfg = admission._cfg(db, lock=True)  # same lock as every admission: no claim races the change
    if body.limit > cfg.concurrency_limit and body.limit > (n := admission.healthy_workers(db)):
        raise HTTPException(422, f"Only {n} healthy {'worker is' if n == 1 else 'workers are'} available. "
                                 f"Enable or provision more workers before raising the limit to {body.limit}.")
    if body.engine_slots is not None and body.engine_slots > 1:  # one ZAP and one egress scope cannot isolate two jobs
        raise HTTPException(422, "Only one scanning engine is provisioned.")
    new = {"concurrency_limit": body.limit, "aging_enabled": body.aging_enabled, "aging_minutes": body.aging_minutes,
           "queue_cap": body.queue_cap, "per_user_quota": body.per_user_quota}
    if body.engine_slots is not None:
        new["engine_slots"] = body.engine_slots
    if body.profile_limits is not None:  # partial: unnamed profiles keep their limits
        new["profile_limits"] = {**cfg.profile_limits, **{k: v.model_dump() for k, v in body.profile_limits.items()}}
    changes = ", ".join(f"{k} {getattr(cfg, k)} -> {v}" for k, v in new.items() if getattr(cfg, k) != v) or "no change"
    for k, v in new.items():
        setattr(cfg, k, v)
    record(db, admin.email, "capacity", "update", "scheduler", "success", f"{changes}. Reason: {reason}")
    db.commit()
    return capacity_response(db)


def wordlist_shape(w: Wordlist) -> dict:
    return {"key": w.key, "category": w.category, "label": w.label, "lines": w.lines, "enabled": w.enabled}


@router.get("/wordlists")
def get_wordlists(db=Depends(get_db)):
    return [wordlist_shape(w) for w in db.scalars(select(Wordlist).order_by(Wordlist.key))]


class WordlistIn(ReasonIn):
    key: str
    enabled: bool


@router.put("/wordlists")
def put_wordlist(body: WordlistIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    w = db.get(Wordlist, body.key)
    if not w:
        raise HTTPException(404, "Not found.")
    w.enabled = body.enabled
    record(db, admin.email, "capacity", "update", "wordlist", "success",
           f"{w.key} {'enabled' if body.enabled else 'disabled'}. Reason: {reason}")
    db.commit()
    return wordlist_shape(w)


class WorkerIn(ReasonIn):
    action: Literal["enable", "drain"]


@router.post("/workers/{wid}")
def worker_action(wid: int, body: WorkerIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = reason_of(body.reason)
    w = db.scalar(select(Worker).where(Worker.id == wid).with_for_update())
    if not w:
        raise HTTPException(404, "Not found.")
    enable = body.action == "enable"
    if w.enabled == enable:
        raise HTTPException(409, f"This worker is already {'enabled' if enable else 'drained'}.")
    w.enabled = enable  # a drained worker finishes its current job and claims nothing new
    record(db, admin.email, "worker", body.action, w.name, "success", f"Reason: {reason}")
    db.commit()
    return workers(db)


# ---- audit ----
def audit_query(q, area, actor, outcome):
    sel = select(AuditEvent).order_by(AuditEvent.id.desc())
    if q:
        sel = sel.where(AuditEvent.action.icontains(q, autoescape=True) | AuditEvent.object.icontains(q, autoescape=True)
                        | AuditEvent.detail.icontains(q, autoescape=True))
    if area:
        sel = sel.where(AuditEvent.area == area)
    if actor:
        sel = sel.where(AuditEvent.actor.icontains(actor, autoescape=True))
    if outcome:
        sel = sel.where(AuditEvent.outcome == outcome)
    return sel


@router.get("/audit")
def audit(response: Response, q: str = "", area: str = "", actor: str = "", outcome: str = "", db=Depends(get_db)):
    sel = audit_query(q, area, actor, outcome)
    total = db.scalar(select(func.count()).select_from(sel.order_by(None).subquery()))
    response.headers["X-Total-Count"] = str(total)
    if total > AUDIT_CAP:
        response.headers["X-Truncated"] = "true"
    return [audit_shape(e) for e in db.scalars(sel.limit(AUDIT_CAP))]


def _cell(v) -> str:
    s = str(v if v is not None else "")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula injection


@router.get("/audit.csv")
def audit_csv(q: str = "", area: str = "", actor: str = "", outcome: str = "",
              admin=Depends(sec.require_admin), db=Depends(get_db)):
    rows = db.scalars(audit_query(q, area, actor, outcome)).all()  # no cap: the export is complete (shortcut: buffered in memory, stream if the log outgrows it)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "at", "actor", "area", "action", "object", "outcome", "detail", "policy_version"])
    for e in rows:
        w.writerow([_cell(v) for v in (e.id, e.at.isoformat(), e.actor, e.area, e.action, e.object, e.outcome, e.detail, e.policy_version)])
    filt = ", ".join(f"{k}={v}" for k, v in (("q", q), ("area", area), ("actor", actor), ("outcome", outcome)) if v)
    record(db, admin.email, "auth", "audit export", "audit_events", "success", f"Exported {len(rows)} events" + (f" ({filt})" if filt else ""))
    db.commit()
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit.csv"'})
