from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import case, select

from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, Finding, Job

router = APIRouter()
SEV = ["critical", "high", "medium", "low", "info"]
# action: (resulting state, label, allowed from, reason required) - DESIGN_SYSTEM §7.6
ACTIONS = {
    "acknowledge": ("open", "Open", {"new"}, False),
    "under-review": ("under-review", "Under review", {"new", "open", "reopened"}, False),
    "false-positive": ("false-positive", "False positive", {"new", "open", "under-review", "reopened"}, True),
    "accept-risk": ("accepted-risk", "Accepted risk", {"open", "under-review", "reopened"}, True),
    "reopen": ("reopened", "Reopened", {"false-positive", "accepted-risk", "resolved"}, True),
}
STATE_LABEL = {"new": "new", "open": "open", "under-review": "under review", "false-positive": "a false positive",
               "resolved": "resolved", "reopened": "reopened", "not-retested": "not retested", "accepted-risk": "an accepted risk"}


class StateIn(BaseModel):
    action: str
    reason: str | None = None


class CommentIn(BaseModel):
    text: str


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short(db, f: Finding) -> dict:
    return {"id": f.display_id, "assessment_id": db.scalar(select(Assessment.display_id).where(Assessment.id == f.assessment_id)),
            "job_id": db.scalar(select(Job.display_id).where(Job.id == f.job_id)), "severity": f.severity,
            "confidence": f.confidence, "state": f.state, "module": f.module, "title": f.title, "asset": f.asset,
            "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at}


def detail(db, f: Finding) -> dict:
    return {**short(db, f), "location": f.location, "description": f.description, "impact": f.impact,
            "evidence": f.evidence, "reproduce": f.reproduce, "remediation": f.remediation, "references": f.references,
            "policy_version": db.scalar(select(Job.policy_version).where(Job.id == f.job_id)),
            "history": f.history, "comments": f.comments}


def get_finding_or_404(db, fid, user, action, lock=False) -> Finding:
    q = select(Finding).where(Finding.display_id == fid)
    f = db.scalar(q.with_for_update() if lock else q)
    a = db.get(Assessment, f.assessment_id) if f else None
    if not f or not sec.can(sec.perm_for(user, a), action):
        raise HTTPException(404, "Not found.")
    return f


@router.get("/assessments/{aid}/findings")
def for_assessment(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "view")
    rank = case(*[(Finding.severity == s, i) for i, s in enumerate(SEV)], else_=len(SEV))
    q = select(Finding).where(Finding.assessment_id == a.id).order_by(rank, Finding.confidence, Finding.id)  # 'confirmed' < 'suspected'
    return [short(db, f) for f in db.scalars(q)]


@router.get("/findings/{fid}")
def get_one(fid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    return detail(db, get_finding_or_404(db, fid, user, "view"))


@router.post("/findings/{fid}/state")
def change_state(fid: str, body: StateIn, user=Depends(sec.current_user), db=Depends(get_db)):
    f = get_finding_or_404(db, fid, user, "change_finding_state", lock=True)
    if body.action not in ACTIONS:
        raise HTTPException(422, {"fields": {"action": "Choose a valid action."}})
    new, label, allowed, needs_reason = ACTIONS[body.action]
    reason = (body.reason or "").strip()
    if needs_reason and not reason:
        raise HTTPException(422, {"fields": {"reason": "Enter a reason."}})
    if len(reason) > 1000:
        raise HTTPException(422, {"fields": {"reason": "Use 1000 characters or fewer."}})
    if f.state not in allowed:
        raise HTTPException(409, f"This change is not available for a finding that is {STATE_LABEL[f.state]}.")
    old, f.state = f.state, new
    line = f"{label} — {reason} · {user.name}" if reason else f"{label} · {user.name}"
    f.history = [*f.history, {"at": _now(), "by": user.name, "text": line}]
    record(db, user.email, "finding", body.action, f.display_id, "success", f"State changed from {old} to {new}")
    db.commit()
    return detail(db, f)


@router.post("/findings/{fid}/comments")
def comment(fid: str, body: CommentIn, user=Depends(sec.current_user), db=Depends(get_db)):
    f = get_finding_or_404(db, fid, user, "comment", lock=True)
    text = body.text.strip()
    if not 1 <= len(text) <= 2000:
        raise HTTPException(422, {"fields": {"text": "Enter a comment of 1 to 2000 characters."}})
    f.comments = [*f.comments, {"at": _now(), "by": user.name, "text": text}]
    record(db, user.email, "finding", "comment", f.display_id, "success", "Comment added")
    db.commit()
    return detail(db, f)
