"""Finding reconciliation at the end of a retest job (DESIGN_SYSTEM §7.7). Evidence rows are never touched."""
from datetime import datetime, timezone

from sqlalchemy import func, select

from app.core.audit import record
from app.models import Credential, Finding, Job, ModuleRun, Wordlist
from app.scheduler.admission import ENGINE_MODULES

def _line(f, text):
    f.history = [*f.history, {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "by": "System", "text": text}]


def _set(db, f, state, text):
    old, f.state = f.state, state
    _line(f, text)
    record(db, "system", "finding", "retest", f.display_id, "success", f"State changed from {old} to {state}; {text}")


def need(f) -> set:
    """Modules that must complete before absence means fixed."""
    return {f.module} | ({"crawl"} if f.module in ENGINE_MODULES else set()) | ({"auth"} if f.credential_id else set())


def reconcile(db, job, excluded=(), seen=()) -> None:
    """excluded: display ids of accounts that could not sign in. seen: fingerprints this job stored."""
    db.execute(select(func.pg_advisory_xact_lock(job.assessment_id)))  # same lock store_findings takes
    targets = set(job.retest_of or [])
    runs = dict(db.execute(select(ModuleRun.key, ModuleRun.state).where(ModuleRun.job_id == job.id)).all())
    creds = {c.id: (c.display_id, c.deleted_at) for c in db.execute(
        select(Credential.id, Credential.display_id, Credential.deleted_at).where(Credential.assessment_id == job.assessment_id))}
    for f in db.scalars(select(Finding).where(Finding.assessment_id == job.assessment_id).with_for_update()):
        target = f.display_id in targets
        if f.fingerprint in seen:
            if target:
                _set(db, f, "reopened" if f.state == "resolved" else f.state, f"Still present in {job.display_id}")
            continue
        if f.state in ("false-positive", "accepted-risk"):
            continue
        if not target:
            if f.module in runs and f.state not in ("resolved", "not-retested"):
                _set(db, f, "not-retested", f"Not observed in {job.display_id}, which did not target it")
            continue
        cred = creds.get(f.credential_id)
        origin = db.get(Job, f.job_id) if f.module in ("exposed", "dast") else None  # unobserved, so still its originating job
        lost = [w for w in (origin.wordlists if origin else None) or [] if w not in (job.wordlists or [])]
        if lost:
            usable = set(db.scalars(select(Wordlist.key).where(Wordlist.key.in_(lost), Wordlist.enabled)))
            why = ("the wordlist used originally is no longer available" if len(usable) < len(lost)
                   else "the original wordlist selection exceeds the current request limit")
        elif f.module not in runs:
            why = f"the {f.module} check could not run in this retest"
        elif f.module == "access":  # the owner account is not recorded, so absence cannot prove a fix
            why = "Cross-account findings need both accounts"
        elif f.credential_id and (cred is None or cred[1] is not None):
            why = "the account it was found with was removed"
        elif f.credential_id and cred[0] in excluded:
            why = "the account it was found with could not sign in"
        else:
            why = next((f"the {k} check did not complete in {job.display_id}" for k in sorted(need(f))
                        if runs.get(k) not in (("completed", "completed-warnings") if k == "auth" else ("completed",))), None)
        if f.state == "resolved":  # a fixed finding is neither re-resolved nor downgraded
            if why:
                _line(f, f"Retest in {job.display_id} could not verify: {why}")
        elif why:
            _set(db, f, "not-retested", f"Not retested: {why}")
        else:
            _set(db, f, "resolved", f"Fixed in {job.display_id}")
