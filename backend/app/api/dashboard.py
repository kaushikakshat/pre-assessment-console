from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from app.api.assessments import NEEDS_ACTION, summary
from app.api.jobs import ACTIVE, capacity_shape, shape
from app.core import security as sec
from app.db import get_db
from app.models import Assessment, Finding, Job

router = APIRouter()


@router.get("/dashboard")
def dashboard(user=Depends(sec.current_user), db=Depends(get_db)):
    mine = Assessment.owner_id == user.id
    n = lambda q: db.scalar(q)  # noqa: E731
    active = select(Job).join(Assessment, Assessment.id == Job.assessment_id).where(mine, Job.state.in_(ACTIVE))
    latest = db.scalar(active.order_by(Job.id.desc()).limit(1))
    recent = db.scalars(select(Assessment).where(mine).order_by(Assessment.id.desc()).limit(5))
    return {"counts": {
                "assessments": n(select(func.count()).select_from(Assessment).where(mine)),
                "open_findings": n(select(func.count()).select_from(Finding).join(Assessment, Assessment.id == Finding.assessment_id)
                                   .where(mine, Finding.state.in_(NEEDS_ACTION))),
                "active_jobs": n(select(func.count()).select_from(active.subquery()))},
            "active_job": shape(db, latest) if latest else None,
            "recent": [summary(db, a) for a in recent], "capacity": capacity_shape(db)}
