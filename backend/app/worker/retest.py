"""Finding reconciliation at the end of a retest job (DESIGN_SYSTEM §7.7). Evidence rows are never touched."""
from datetime import datetime, timezone

from sqlalchemy import func, select

from app.core.audit import record
from app.models import Credential, Finding, ModuleRun
from app.scheduler.admission import ENGINE_MODULES

def _set(db, f, state, text):
    old, f.state = f.state, state
    f.history = [*f.history, {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "by": "System", "text": text}]
    record(db, "system", "finding", "retest", f.display_id, "success", f"State changed from {old} to {state}; {text}")


def need(f) -> set:
    """Modules that must complete before absence means fixed."""
    return {f.module} | ({"crawl"} if f.module in ENGINE_MODULES else set()) | ({"auth"} if f.credential_id else set())


def reconcile(db, job, excluded=()) -> None:
    """excluded: display ids of accounts that could not sign in during this job."""
    db.execute(select(func.pg_advisory_xact_lock(job.assessment_id)))  # same lock store_findings takes
    targets = set(job.retest_of or [])
    runs = dict(db.execute(select(ModuleRun.key, ModuleRun.state).where(ModuleRun.job_id == job.id)).all())
    live = set(db.scalars(select(Credential.id).where(Credential.assessment_id == job.assessment_id, Credential.deleted_at.is_(None))))
    cred_name = dict(db.execute(select(Credential.id, Credential.display_id)).all())
    for f in db.scalars(select(Finding).where(Finding.assessment_id == job.assessment_id).with_for_update()):
        seen, target = f.job_id == job.id, f.display_id in targets  # store_findings re-points a finding at the job that observed it
        if seen:
            if target:
                _set(db, f, "reopened" if f.state == "resolved" else f.state, f"Still present in {job.display_id}")
            continue
        if f.module not in runs or f.state in ("false-positive", "accepted-risk"):
            continue
        if not target:
            if f.state not in ("resolved", "not-retested"):
                _set(db, f, "not-retested", f"Not observed in {job.display_id}, which did not target it")
            continue
        why = next((f"the {k} check did not complete in {job.display_id}" for k in sorted(need(f))
                    if runs.get(k) not in (("completed", "completed-warnings") if k == "auth" else ("completed",))), None)
        if f.credential_id and f.credential_id not in live:
            why = "the account it was found with was removed"
        elif f.credential_id and cred_name.get(f.credential_id) in excluded:
            why = "the account it was found with could not sign in"
        if f.state == "resolved":
            continue  # a fixed finding is neither re-resolved nor downgraded by a retest that could not verify it
        if why:
            _set(db, f, "not-retested", f"Not retested: {why}")
        else:
            _set(db, f, "resolved", f"Fixed in {job.display_id}")
