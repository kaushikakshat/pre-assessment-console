import os
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy import update as sql_update

from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, AuditEvent, Finding, Job, PolicyVersion, User
from app.targets import ipguard
from app.targets.policy import ENVS
from app.targets.validate import parse_ports, parse_target, validate_target

router = APIRouter(prefix="/assessments")
ACTIVE_JOB = ("queued", "validating", "scheduled", "running", "cancelling")
NEEDS_ACTION = ("new", "open", "under-review", "reopened")
STATUS = {"allowed": "active", "approval": "awaiting-approval", "blocked": "blocked"}


class In(BaseModel):
    name: str = ""
    target: str = ""
    env: str = ""
    hosts: str = ""
    paths: str = ""
    ports: str = ""
    exclusions: str = ""
    notes: str | None = None
    allow_untrusted_cert: bool | None = None  # owner opt-in; None keeps the stored value


def clean(b: In) -> dict:
    """Validate and apply defaults; raises 422 with per-field messages."""
    err, name, p = {}, b.name.strip(), None
    if not 1 <= len(name) <= 120:
        err["name"] = "Enter a name of 1 to 120 characters."
    try:
        p = parse_target(b.target)
    except ValueError as e:
        err["target"] = str(e)
    if b.env not in ENVS:
        err["env"] = "Choose an environment."
    for f in ("hosts", "paths", "exclusions", "notes"):
        if len(getattr(b, f) or "") > 4000:
            err[f] = "Too long."
    for h in re.split(r"[,\s]+", b.hosts.strip()):
        try:
            if h:
                ipguard.normalize_host(h)
                if not re.fullmatch(r"[^\s/@?#]+", h):
                    raise ValueError
        except (UnicodeError, ValueError):
            err["hosts"] = "Enter hostnames or IP addresses separated by commas."
            break
    ports = b.ports.strip() or (("443" if p.scheme == "https" else "80") if p else "")
    if ports:
        try:
            parse_ports(ports)
        except ValueError as e:
            err["ports"] = str(e)
    if err:
        raise HTTPException(422, {"fields": err})
    return {"name": name, "target": p.normalized, "env": b.env, "hosts": b.hosts.strip() or p.host,
            "paths": b.paths.strip() or "/*", "ports": ports, "exclusions": b.exclusions.strip(),
            "notes": (b.notes or "").strip() or None}


def shape(db, a: Assessment, user: User) -> dict:
    job = db.scalar(select(Job.display_id).where(Job.assessment_id == a.id, Job.state.in_(ACTIVE_JOB))
                    .order_by(Job.id.desc()))
    owner = db.get(User, a.owner_id)
    return {"id": a.display_id, "name": a.name, "owner": {"id": owner.display_id, "name": owner.name},
            "target": a.target, "env": a.env, "hosts": a.hosts, "paths": a.paths, "ports": a.ports,
            "exclusions": a.exclusions, "notes": a.notes, "status": a.status, "validation": a.validation,
            "approval": a.approval, "allow_untrusted_cert": a.allow_untrusted_cert, "active_job_id": job, "created_at": a.created_at, "updated_at": a.updated_at,
            "access": sec.perm_for(user, a)}


def summary(db, a: Assessment) -> dict:
    last = db.execute(select(Job.display_id, Job.state, Job.submitted_at).where(Job.assessment_id == a.id)
                      .order_by(Job.id.desc()).limit(1)).first()
    n = db.scalar(select(func.count()).select_from(Finding).where(Finding.assessment_id == a.id,
                                                                   Finding.state.in_(NEEDS_ACTION)))
    return {"id": a.display_id, "name": a.name, "target": a.target, "env": a.env, "status": a.status,
            "validation_outcome": (a.validation or {}).get("outcome"),
            "last_job": {"id": last[0], "state": last[1], "submitted_at": last[2]} if last else None,
            "open_findings": n, "created_at": a.created_at}


@router.get("")
def list_mine(user=Depends(sec.current_user), db=Depends(get_db)):
    q = select(Assessment).where(Assessment.owner_id == user.id).order_by(Assessment.id.desc())
    return [summary(db, a) for a in db.scalars(q)]


@router.post("", status_code=201)
def create(body: In, user=Depends(sec.current_user), db=Depends(get_db)):
    a = Assessment(owner_id=user.id, allow_untrusted_cert=body.allow_untrusted_cert is True, **clean(body))
    db.add(a)
    db.flush()
    db.refresh(a)
    record(db, user.email, "assessment", "create", a.display_id, "success", "Assessment created")
    if a.allow_untrusted_cert:
        record(db, user.email, "assessment", "update", a.display_id, "success", "allow untrusted certificate: on")
    out = shape(db, a, user)
    db.commit()
    return out


@router.get("/{aid}")
def get_one(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    return shape(db, sec.get_assessment_or_404(db, aid, user, "view"), user)


@router.patch("/{aid}")
def update(aid: str, body: In, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "edit")
    if db.scalar(select(Job.id).where(Job.assessment_id == a.id, Job.state.in_(ACTIVE_JOB)).limit(1)):
        raise HTTPException(409, "This assessment has a scan queued or running. Wait for it to finish before editing.")
    for k, v in clean(body).items():
        setattr(a, k, v)
    if body.allow_untrusted_cert is not None and body.allow_untrusted_cert != a.allow_untrusted_cert:
        a.allow_untrusted_cert = body.allow_untrusted_cert
        record(db, user.email, "assessment", "update", a.display_id, "success",
               f"allow untrusted certificate: {'on' if a.allow_untrusted_cert else 'off'}")
    a.validation = a.approval = a.policy_version = None
    a.status, a.updated_at = "draft", func.now()
    record(db, user.email, "assessment", "update", a.display_id, "success", "Assessment edited; validation cleared")
    db.flush()
    db.refresh(a)
    out = shape(db, a, user)
    db.commit()
    return out


VALIDATES_PER_MIN = 10


@router.post("/{aid}/validate")
def validate(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "edit")
    pv = db.scalar(select(PolicyVersion).where(PolicyVersion.status == "published")
                   .order_by(PolicyVersion.published_at.desc()).limit(1))
    if not pv:
        raise HTTPException(503, "Target validation is unavailable. Try again later.")
    recent = db.scalar(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.actor == user.email, AuditEvent.area == "validation",
        AuditEvent.at > datetime.now(timezone.utc) - timedelta(minutes=1)))
    if recent >= VALIDATES_PER_MIN:
        raise HTTPException(429, "Too many validations. Wait a minute before trying again.")
    # Atomic lease: one in-flight validation per user across all API processes; expires if a process dies.
    got = db.execute(sql_update(User).where(User.id == user.id, (User.validating_until.is_(None)) | (User.validating_until < func.now()))
                     .values(validating_until=func.now() + text("interval '20 seconds'")))
    db.commit()
    if got.rowcount == 0:
        raise HTTPException(409, "A validation is already running for you.")
    try:
        snap = (a.target, a.env, a.ports, a.hosts)
        policy = {**pv.rules, "version": pv.version}
        result = validate_target(*snap[:3], policy, hosts=snap[3], app_env=os.environ.get("APP_ENV", "prod"),
                                 verify=not a.allow_untrusted_cert)
    finally:
        db.execute(sql_update(User).where(User.id == user.id).values(validating_until=None))
        db.commit()
    # populate_existing: the identity map still holds the pre-validation object (expire_on_commit=False)
    a = db.scalar(select(Assessment).where(Assessment.id == a.id).with_for_update()
                  .execution_options(populate_existing=True))
    if a is None:
        raise HTTPException(404, "Not found.")
    if (a.target, a.env, a.ports, a.hosts) != snap:
        raise HTTPException(409, "The assessment changed while it was being validated. Validate again.")
    a.validation, a.policy_version = result, pv.version
    a.status = STATUS[result["outcome"]]
    a.approval = {"state": "pending", "note": None, "by": None, "at": None, "self": False} \
        if result["outcome"] == "approval" else None
    a.updated_at = func.now()
    record(db, user.email, "validation", "validate", a.display_id,
           "blocked" if result["outcome"] == "blocked" else "success", f"Validation outcome: {result['outcome']}",
           pv.version)
    db.commit()
    return result


@router.get("/{aid}/activity")
def activity(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "activity")
    objs = [a.display_id,
            *db.scalars(select(Job.display_id).where(Job.assessment_id == a.id)),
            *db.scalars(select(Finding.display_id).where(Finding.assessment_id == a.id))]
    rows = db.scalars(select(AuditEvent).where(AuditEvent.object.in_(objs)).order_by(AuditEvent.id.desc()).limit(200))
    return [{"id": str(e.id), "at": e.at, "actor": e.actor, "area": e.area, "action": e.action, "object": e.object,
             "outcome": e.outcome, "detail": e.detail, "policy_version": e.policy_version} for e in rows]
