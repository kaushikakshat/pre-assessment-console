from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.api.catalog import MODULES, QUICK
from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, Job, ModuleRun, SchedulerConfig, User
from app.scheduler import admission

router = APIRouter()
ACTIVE = ("queued", "validating", "scheduled", "running", "cancelling")
FINISHED = ("completed", "completed-warnings", "failed", "cancelled", "blocked", "interrupted")
NAMES = {k: n for k, n, _ in MODULES}
BLOCKED = {"emergency": "An administrator used Emergency stop. New scans are blocked until it is lifted.",
           "paused": "An administrator has paused new scans. Submissions are not accepted until scanning resumes."}


class JobIn(BaseModel):
    assessment_id: str = ""
    profile: str | None = None
    modules: list[str] | None = None
    authorized: bool = False
    idempotency_key: str = ""


def shape(db, j: Job, queue=True) -> dict:
    a, u = db.get(Assessment, j.assessment_id), db.get(User, j.requested_by)
    runs = db.scalars(select(ModuleRun).where(ModuleRun.job_id == j.id).order_by(ModuleRun.id)).all()
    pos = admission.queue_position(db, j) if queue else None
    return {"id": j.display_id, "seq": j.seq, "assessment_id": a.display_id, "assessment_name": a.name, "type": j.type,
            "profile": j.profile, "priority": j.priority, "state": j.state, "submitted_at": j.submitted_at,
            "started_at": j.started_at, "ended_at": j.ended_at, "policy_version": j.policy_version,
            "requested_by": u.name, "note": j.note,
            "resume_of": db.scalar(select(Job.display_id).where(Job.id == j.resume_of)) if j.resume_of else None,
            "review": j.review,
            "modules": [{"key": r.key, "name": NAMES.get(r.key, r.key), "state": r.state, "detail": r.detail,
                         "started_at": r.started_at, "ended_at": r.ended_at} for r in runs],
            "queue_position": pos, "wait_estimate": admission.wait_estimate(pos)}


def capacity_shape(db) -> dict:
    return asdict(admission.capacity(db))


def get_job_or_404(db, display_id, user, action, lock=False) -> Job:
    q = select(Job).where(Job.display_id == display_id)
    j = db.scalar(q.with_for_update() if lock else q)
    a = db.get(Assessment, j.assessment_id) if j else None
    if not j or not sec.can(sec.perm_for(user, a), action):
        raise HTTPException(404, "Not found.")
    return j


def _choose_modules(body: JobIn, env: str) -> list[str]:
    err = lambda m: HTTPException(422, {"fields": {"modules": m}})  # noqa: E731
    if body.modules is not None:
        picked = list(dict.fromkeys(body.modules))
        if not picked or any(k not in NAMES for k in picked):
            raise err("Choose at least one valid module.")
    elif body.profile == "quick":
        picked = list(QUICK)
    elif body.profile:
        raise err("That scan profile is not available in this release.")
    else:
        raise err("Choose a scan profile or at least one module.")
    picked = ["reach", *(k for k in picked if k != "reach")]
    if env == "Production" and not set(picked) <= set(QUICK):
        raise HTTPException(422, "Production targets can only be scanned with Quick Scan.")
    return picked


@router.post("/jobs", status_code=202)
def submit(body: JobIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, body.assessment_id, user, "scan")
    if body.authorized is not True:
        raise HTTPException(422, {"fields": {"authorized": "Confirm you are authorized to test this target."}})
    key = body.idempotency_key.strip()
    if not 1 <= len(key) <= 120:
        raise HTTPException(422, {"fields": {"idempotency_key": "Enter a valid value."}})
    modules = _choose_modules(body, a.env)
    scoped = f"{user.id}:{key}"
    prior = db.scalar(select(Job).where(Job.idempotency_key == scoped))
    if prior:
        if prior.assessment_id != a.id:
            raise HTTPException(409, "That submission key was already used for another scan.")
        return shape(db, prior)
    if a.status != "active":
        raise HTTPException(409, "This assessment is not ready to scan. Validate the target and wait for approval first.")
    cfg = db.scalar(select(SchedulerConfig).where(SchedulerConfig.id == 1).with_for_update()
                    .execution_options(populate_existing=True))  # serialises quota and cap checks
    if cfg.emergency or cfg.paused:
        raise HTTPException(503, BLOCKED["emergency" if cfg.emergency else "paused"])
    count = lambda *where: db.scalar(select(func.count()).select_from(Job).where(*where))  # noqa: E731
    if count(Job.state == "queued") >= cfg.queue_cap:
        raise HTTPException(429, "The scan queue is full. Try again later.")
    if count(Job.requested_by == user.id, Job.state.in_(ACTIVE)) >= cfg.per_user_quota:
        raise HTTPException(429, f"You already have {cfg.per_user_quota} active scans. Wait for one to finish or cancel it.")
    j = Job(assessment_id=a.id, requested_by=user.id, profile=body.profile if body.modules is None else None,
            policy_version=a.policy_version, idempotency_key=scoped)
    db.add(j)
    try:
        db.flush()
    except IntegrityError:  # same key raced in from another request
        db.rollback()
        return shape(db, db.scalar(select(Job).where(Job.idempotency_key == scoped)))
    db.refresh(j)
    db.add_all(ModuleRun(job_id=j.id, key=k) for k in modules)
    record(db, user.email, "job", "submit", j.display_id, "success", f"Scan submitted for {a.display_id}", a.policy_version)
    db.commit()
    return shape(db, j)


@router.get("/jobs/{jid}")
def get_one(jid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    return shape(db, get_job_or_404(db, jid, user, "view"))


def apply_cancel(db, j: Job, actor: str, extra: str = ""):
    """Caller holds the job row lock. queued -> cancelled; running -> cancelling; finished -> 409."""
    if j.state == "queued":
        j.state, j.ended_at, j.cancel_requested = "cancelled", func.now(), True
        db.execute(update(ModuleRun).where(ModuleRun.job_id == j.id, ModuleRun.state == "queued")
                   .values(state="skipped", detail="Cancelled before it started"))
    elif j.state == "running":
        j.state, j.cancel_requested = "cancelling", True
    elif j.state != "cancelling":
        raise HTTPException(409, "This scan has already finished.")
    record(db, actor, "job", "cancel", j.display_id, "success", f"Cancel requested; job is now {j.state}{extra}")
    db.commit()
    db.refresh(j)


@router.post("/jobs/{jid}/cancel")
def cancel(jid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    j = get_job_or_404(db, jid, user, "cancel_own_job", lock=True)  # row lock: a concurrent claim either wins or is skipped
    apply_cancel(db, j, user.email)
    return shape(db, j)


@router.get("/assessments/{aid}/jobs")
def for_assessment(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "view")
    return [shape(db, j) for j in db.scalars(select(Job).where(Job.assessment_id == a.id).order_by(Job.id.desc()))]


@router.get("/queue")
def queue(user=Depends(sec.current_user), db=Depends(get_db)):
    mine = db.scalars(select(Job).where(Job.requested_by == user.id, Job.state.in_(ACTIVE)).order_by(Job.seq)).all()
    running = db.scalars(select(Job).where(Job.state.in_(("running", "cancelling"))).order_by(Job.seq)).all()
    queued = {j.id: j for j in db.scalars(select(Job).where(Job.state == "queued"))}
    slots = [*running, *(queued[i] for i in admission.queued_order(db) if i in queued)]
    recent = db.scalars(select(Job).where(Job.requested_by == user.id, Job.state.in_(FINISHED))
                        .order_by(Job.ended_at.desc().nulls_last(), Job.id.desc()).limit(10))
    return {"capacity": capacity_shape(db), "mine": [shape(db, j) for j in mine],
            "platform": [{"position": i, "mine": j.requested_by == user.id, "state": j.state,
                          "job_id": j.display_id if j.requested_by == user.id else None}
                         for i, j in enumerate(slots, 1)],
            "recent": [shape(db, j, queue=False) for j in recent]}
