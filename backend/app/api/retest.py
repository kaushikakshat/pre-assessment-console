from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.api.jobs import JobIn, _choose_modules, enqueue
from app.core import security as sec
from app.db import get_db
from app.models import Credential, Finding
from app.scheduler.admission import ENGINE_MODULES

router = APIRouter()


class RetestIn(BaseModel):
    finding_ids: list[str] = []
    authorized: bool = False
    idempotency_key: str = ""


@router.post("/assessments/{aid}/retest", status_code=202)
def retest(aid: str, body: RetestIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = sec.get_assessment_or_404(db, aid, user, "retest")
    err = lambda field, m: HTTPException(422, {"fields": {field: m}})  # noqa: E731
    if body.authorized is not True:
        raise err("authorized", "Confirm you are authorized to test this target.")
    key = body.idempotency_key.strip()
    if not 1 <= len(key) <= 120:
        raise err("idempotency_key", "Enter a valid value.")
    ids = list(dict.fromkeys(body.finding_ids))
    found = db.scalars(select(Finding).where(Finding.assessment_id == a.id, Finding.display_id.in_(ids))).all()
    if not ids or len(found) != len(ids):
        raise err("finding_ids", "Choose findings from this assessment.")
    if any(f.state in ("false-positive", "accepted-risk") for f in found):
        raise err("finding_ids", "False positives and accepted risks cannot be retested. Reopen them first.")
    creds = sorted(db.scalars(select(Credential.display_id).where(
        Credential.id.in_([f.credential_id for f in found if f.credential_id]), Credential.deleted_at.is_(None))))
    mods = {f.module for f in found}
    if mods & ENGINE_MODULES:
        mods.add("crawl")
    if creds:
        mods.add("auth")  # a removed account is not re-added; the worker marks its findings Not retested
    body_jobs = JobIn(modules=sorted(mods), credential_ids=creds)
    return enqueue(db, user, a, key, _choose_modules(body_jobs, a.env), body_jobs, what="Retest", type="retest", retest_of=ids)
