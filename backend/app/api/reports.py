import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.jobs import FINISHED
from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, Job, Report, User

router = APIRouter()
REPORTS_DIR = lambda: Path(os.environ.get("REPORTS_DIR", "/data/reports"))  # noqa: E731
SLUG = {"management": "management-summary", "technical": "technical-report"}
FAILED = "Report generation failed — your assessment results are unchanged"


class ReportIn(BaseModel):
    type: str = ""
    job_id: str = ""


def shape(db, r: Report, model=False) -> dict:
    out = {"id": r.display_id, "assessment_id": db.scalar(select(Assessment.display_id).where(Assessment.id == r.assessment_id)),
           "job_id": db.scalar(select(Job.display_id).where(Job.id == r.job_id)), "type": r.type, "version": r.version,
           "state": r.state, "created_at": r.created_at, "requested_by": db.get(User, r.requested_by).name}
    if r.error:
        out["error"] = r.error
    return {**out, "model": r.model} if model else out


def get_report_or_404(db, rid, user, lock=False) -> Report:
    r = db.scalar(select(Report).where(Report.display_id == rid))
    a = db.get(Assessment, r.assessment_id) if r else None
    if not r or not sec.can(sec.perm_for(user, a), "view"):
        raise HTTPException(404, "Not found.")
    if lock:
        db.refresh(r, with_for_update=True)
    return r


@router.post("/assessments/{aid}/reports", status_code=202)
def create(aid: str, body: ReportIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "generate_report")
    if body.type not in SLUG:
        raise HTTPException(422, {"fields": {"type": "Choose a report type."}})
    job = db.scalar(select(Job).where(Job.display_id == body.job_id, Job.assessment_id == a.id))
    if not job or job.state not in FINISHED:
        raise HTTPException(422, {"fields": {"job_id": "Choose a finished scan of this assessment."}})
    db.execute(select(func.pg_advisory_xact_lock(a.id)))  # two requests must not pick the same version
    v = db.scalar(select(func.coalesce(func.max(Report.version), 0)).where(Report.assessment_id == a.id, Report.type == body.type)) + 1
    r = Report(assessment_id=a.id, job_id=job.id, type=body.type, version=v, requested_by=user.id)
    db.add(r)
    db.flush()
    record(db, user.email, "assessment", "report-requested", r.display_id, "success", f"{SLUG[body.type]} v{v} requested")
    db.commit()
    return shape(db, r)


@router.get("/assessments/{aid}/reports")
def listing(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "view")
    return [shape(db, r) for r in db.scalars(select(Report).where(Report.assessment_id == a.id).order_by(Report.id.desc()))]


@router.get("/reports/{rid}")
def one(rid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    return shape(db, get_report_or_404(db, rid, user), model=True)


@router.get("/reports/{rid}/pdf")
def pdf(rid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    r = get_report_or_404(db, rid, user)
    if r.state != "ready" or not r.pdf_path or not Path(r.pdf_path).is_file():
        raise HTTPException(409, "This report is not ready to download.")
    name = re.sub(r"[^A-Za-z0-9]+", "-", db.get(Assessment, r.assessment_id).name).strip("-") or "Assessment"
    record(db, user.email, "assessment", "report-downloaded", r.display_id, "success", "PDF downloaded")
    db.commit()
    return FileResponse(r.pdf_path, media_type="application/pdf", filename=f"{r.display_id}-v{r.version}-{SLUG[r.type]}-{name}.pdf")


@router.post("/reports/{rid}/retry", status_code=202)
def retry(rid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    r = get_report_or_404(db, rid, user, lock=True)
    if not sec.can(sec.perm_for(user, db.get(Assessment, r.assessment_id)), "generate_report"):
        raise HTTPException(404, "Not found.")
    if r.state != "failed":
        raise HTTPException(409, "Only a failed report can be retried.")
    r.state, r.error, r.claimed_at = "generating", None, None  # unclaimed again: the worker picks it up
    record(db, user.email, "assessment", "report-retried", r.display_id, "success", "Report generation retried")
    db.commit()
    db.refresh(r)
    return shape(db, r)
