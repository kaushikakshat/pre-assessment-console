from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.api.catalog import QUICK
from app.api.jobs import JobIn, _choose_modules, enqueue
from app.core import security as sec
from app.db import get_db
from app.models import Credential, Finding, Job, SchedulerConfig, Wordlist
from app.worker.modules import wordlists as wl
from app.scheduler.admission import ENGINE_MODULES

router = APIRouter()
WORDLIST_MODULES = {"exposed", "dast"}  # the modules that use a job's wordlists


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
    prod = a.env == "Production"
    kept = [f for f in found if not prod or f.module in QUICK]  # the rest become Not retested in the worker
    if not kept:
        raise err("finding_ids", "These findings need checks that Production targets do not allow.")
    creds = sorted(db.scalars(select(Credential.display_id).where(
        Credential.id.in_([f.credential_id for f in kept if f.credential_id]), Credential.deleted_at.is_(None))))
    mods = {f.module for f in kept}
    if mods & ENGINE_MODULES:
        mods.add("crawl")
    if creds:
        mods.add("auth")  # a removed account is not re-added; the worker marks its findings Not retested
    # Inherit the profile (limits, budget) and wordlists of the jobs that last observed the findings, so deep or
    # wordlist-only findings can reappear. Production is Quick only, so it inherits nothing.
    origin = [] if prod else db.scalars(select(Job).where(Job.id.in_({f.job_id for f in kept}))).all()
    profile = next((p for p in ("deep", "pre") if any(j.profile == p for j in origin)), None)
    lists = sorted({w for f in kept if f.module in WORDLIST_MODULES for j in origin if j.id == f.job_id for w in j.wordlists or []})
    # Unavailable or over-cap lists are dropped, never refused; the worker marks the findings that depended on them Not retested.
    live = {w.key: w.lines for w in db.scalars(select(Wordlist).where(Wordlist.key.in_(lists), Wordlist.enabled))}
    lists = sorted(live) if profile else []
    cap = (db.scalar(select(SchedulerConfig.profile_limits).where(SchedulerConfig.id == 1)) or {}).get(profile, {}).get("request_cap", 0)
    while lists and wl.estimate(db, lists) > cap:
        lists.remove(max(lists, key=live.get))
    body_jobs = JobIn(modules=["reach", *sorted(mods)], credential_ids=creds, profile=profile, wordlists=lists)
    return enqueue(db, user, a, key, _choose_modules(body_jobs, a.env), body_jobs, what="Retest",
                   type="retest", retest_of=ids, profile=profile)
