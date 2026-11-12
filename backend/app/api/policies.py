import ipaddress
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.jobs import apply_cancel
from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, Job, PolicyVersion, User
from app.targets import ipguard
from app.targets.policy import INVARIANTS, RANK, canonical, check_policy, content_hash, evaluate_outcome, schema_errors
from app.targets.validate import parse_target

router = APIRouter(prefix="/admin/policies", dependencies=[Depends(sec.require_admin)])
MAX_RULES = 500
STALE = "Someone else changed this draft. Reload to see their changes."


class SaveIn(BaseModel):
    document: dict
    note: str = Field(max_length=500)
    rev: int


class ImportIn(BaseModel):
    text: str = Field(max_length=262144)
    rev: int


class PublishIn(BaseModel):
    rev: int


class RollbackIn(BaseModel):
    reason: str = Field(max_length=500)


def published(db, lock=False) -> PolicyVersion:
    q = select(PolicyVersion).where(PolicyVersion.status == "published").order_by(PolicyVersion.published_at.desc()).limit(1)
    pv = db.scalar(q.with_for_update() if lock else q)
    if not pv:
        raise HTTPException(503, "Target validation is unavailable. Try again later.")
    return pv


def next_label(db) -> str:
    nums = [int(v[1:]) for v in db.scalars(select(PolicyVersion.version)) if v[1:].isdigit()]
    return f"v{max(nums, default=0) + 1}"


def version_shape(db, pv: PolicyVersion) -> dict:
    used = db.scalar(select(func.count()).select_from(Assessment).where(Assessment.policy_version == pv.version))
    return {"version": pv.version, "status": pv.status, "document": pv.rules, "note": pv.note,
            "published_at": pv.published_at, "published_by": pv.published_by, "rules": len(pv.rules.get("rules", [])),
            "used_by": used}


def draft_shape(pv: PolicyVersion) -> dict:
    h = content_hash(pv.rules)
    val = pv.validation if pv.validation and pv.validation.get("hash") == h else None
    dry = pv.dry_run if pv.dry_run and pv.dry_run.get("hash") == h else None
    checks = val["checks"] if val else None
    stage = "draft"
    if val and not any(c["result"] == "fail" for c in checks):
        stage = "dry-run" if dry else "validated"
    return {"version": pv.version, "status": pv.status, "document": pv.rules, "note": pv.note, "rev": pv.rev,
            "created_by": pv.created_by, "created_at": pv.created_at, "stage": stage, "checks": checks,
            "dry_run": {k: v for k, v in dry.items() if k != "hash"} if dry else None}


def locked_draft(db) -> PolicyVersion:
    pv = db.scalar(select(PolicyVersion).where(PolicyVersion.status == "draft").with_for_update())
    if not pv:
        raise HTTPException(404, "No draft is open.")
    return pv


def invalid(errors):
    return JSONResponse({"detail": "The policy has errors.", "errors": errors}, status_code=422)


def replace(db, admin, doc, rev, action, note=None):
    """Swap the draft document under the row lock; returns a 422 response instead of the draft on bad input."""
    pv = locked_draft(db)
    if pv.rev != rev:
        raise HTTPException(409, STALE)
    errs = schema_errors(doc)
    if not errs and len(doc["rules"]) > MAX_RULES:
        errs = [f"A policy can have at most {MAX_RULES} rules"]
    if errs:
        return invalid(errs)
    pv.rules, pv.rev, pv.validation, pv.dry_run = canonical(doc), pv.rev + 1, None, None
    if note is not None:
        pv.note = note
    record(db, admin.email, "policy", action, pv.version, "success", f"rev {pv.rev}, {len(doc['rules'])} rules")
    db.commit()
    return draft_shape(pv)


@router.get("")
def overview(db=Depends(get_db)):
    d = db.scalar(select(PolicyVersion).where(PolicyVersion.status == "draft"))
    return {"published": version_shape(db, published(db)), "draft": draft_shape(d) if d else None,
            "invariants": INVARIANTS}


@router.post("/draft", status_code=201)
def start(admin=Depends(sec.require_admin), db=Depends(get_db)):
    pv = PolicyVersion(version=next_label(db), rules=json.loads(json.dumps(published(db).rules)), status="draft",
                       note="", created_by=admin.email)
    db.add(pv)
    try:
        db.flush()
    except IntegrityError:  # policy_one_draft (or a racing label)
        db.rollback()
        raise HTTPException(409, "A draft is already open.")
    record(db, admin.email, "policy", "draft-start", pv.version, "success", "Started from the published policy")
    db.commit()
    return draft_shape(pv)


@router.put("/draft")
def save(body: SaveIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    return replace(db, admin, body.document, body.rev, "draft-save", body.note)


@router.post("/draft/import")
def import_doc(body: ImportIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    try:
        doc = json.loads(body.text)
    except (ValueError, RecursionError):
        return invalid(["The text is not valid JSON"])
    return replace(db, admin, doc, body.rev, "draft-import")


@router.delete("/draft", status_code=204)
def discard(admin=Depends(sec.require_admin), db=Depends(get_db)):
    pv = locked_draft(db)
    db.delete(pv)
    record(db, admin.email, "policy", "draft-discard", pv.version, "success", "Draft discarded")
    db.commit()
    return Response(status_code=204)


@router.post("/draft/validate")
def validate(admin=Depends(sec.require_admin), db=Depends(get_db)):
    pv = locked_draft(db)
    checks = check_policy(pv.rules)
    pv.validation = {"hash": content_hash(pv.rules), "checks": checks}
    record(db, admin.email, "policy", "draft-validate", pv.version, "success",
           f"{sum(c['result'] == 'fail' for c in checks)} failing checks")
    db.commit()
    return draft_shape(pv)


# ORM-assigned None is stored as JSON null (not SQL NULL), so test the JSON type
VALIDATED = func.jsonb_typeof(Assessment.validation) == "object"


def _host(target):
    try:
        return parse_target(target).host
    except ValueError:
        return None


def _lookup(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return [host.strip("[]")]
    except ValueError:
        pass
    try:
        return ipguard.resolve(host, timeout=3)
    except OSError:
        return None


def resolve_hosts(db, hosts=None) -> dict:
    """host -> addresses (None when unresolvable). Defaults to every validated assessment's host; call outside row locks."""
    if hosts is None:
        hosts = [a.target for a in db.scalars(select(Assessment).where(VALIDATED))]
        hosts = [_host(t) for t in hosts]
    hosts = sorted({h for h in hosts if h})
    with ThreadPoolExecutor(max_workers=8) as ex:
        return dict(zip(hosts, ex.map(_lookup, hosts)))


def outcomes(db, published_doc, draft_doc, app_env, resolved=None) -> list[dict]:
    """Re-evaluate every validated assessment under both documents; DNS only, never any HTTP.
    `resolved` is a pre-resolved host map; hosts missing from it are resolved here."""
    rows = db.execute(select(Assessment, User.name).join(User, User.id == Assessment.owner_id)
                      .where(VALIDATED).order_by(Assessment.id)).all()
    addrs = dict(resolved or {})
    addrs.update(resolve_hosts(db, [_host(a.target) for a, _ in rows if _host(a.target) not in addrs]))
    out = []
    for a, owner in rows:
        ad = addrs.get(_host(a.target))
        pub = evaluate_outcome(a.target, a.env, a.ports, published_doc, ad, app_env)
        new = evaluate_outcome(a.target, a.env, a.ports, draft_doc, ad, app_env)
        stored = a.validation["outcome"]
        out.append({"assessment": a.display_id, "name": a.name, "target": a.target, "env": a.env, "owner": owner,
                    "stored": stored, "published": pub, "draft": new, "changed": pub != new or new == "unresolved",
                    "reset": new in RANK and RANK[new] > RANK[stored]})
    return out


def apply_publish(db, new_doc, label, actor, note, draft=None) -> dict:
    """One transaction: supersede, publish, reset stricter assessments, cancel their queued scans.
    Lock order: draft row, assessments by id, published row, then jobs by id. validate locks an assessment and then
    reads the published row FOR SHARE, so the published row must come after the assessments. DNS runs before any lock."""
    resolved = resolve_hosts(db)
    if draft is not None:
        db.execute(select(PolicyVersion).where(PolicyVersion.version == draft.version).with_for_update()
                   .execution_options(populate_existing=True))
    locked = {a.display_id: a for a in db.scalars(
        select(Assessment).where(VALIDATED).order_by(Assessment.id).with_for_update()
        .execution_options(populate_existing=True))}
    old = published(db, lock=True)
    rows = outcomes(db, old.rules, new_doc, os.environ.get("APP_ENV", "prod"), resolved)
    if any(r["reset"] and r["assessment"] not in locked for r in rows):
        db.rollback()
        raise HTTPException(409, "A target was validated while publishing. Publish again.")
    old.status = "superseded"
    db.flush()  # free the 'published' slot before the new row takes it
    if draft is None:
        db.add(PolicyVersion(version=label, rules=json.loads(json.dumps(new_doc)), status="published", created_by=actor,
                             published_at=datetime.now(timezone.utc), published_by=actor, note=note))
    else:
        draft.status, draft.published_at, draft.published_by = "published", datetime.now(timezone.utc), actor
        draft.validation = draft.dry_run = None
    action = "rollback" if draft is None else "publish"
    db.flush()
    cancelled = 0
    resets = [r for r in rows if r["reset"]]
    for r in resets:
        a = locked[r["assessment"]]
        a.validation = a.approval = a.policy_version = None
        a.status, a.updated_at = "draft", func.now()
        for j in db.scalars(select(Job).where(Job.assessment_id == a.id, Job.state == "queued").order_by(Job.id)
                            .with_for_update()):
            apply_cancel(db, j, actor, f". Reason: target policy {label} made this target stricter", commit=False)
            cancelled += 1
        record(db, actor, "validation", "policy-reset", a.display_id, "success",
               f"Policy {label}: outcome now {r['draft']}; validate again", label)
    changed = sum(r["changed"] for r in rows)
    record(db, actor, "policy", action, label, "success",
           f"{changed} targets change, {len(resets)} need re-validation, {cancelled} queued scans cancelled", label)
    db.commit()
    return {"version": label, "changed": changed, "reset": len(resets), "jobs_cancelled": cancelled}


@router.post("/draft/dry-run")
def dry_run(admin=Depends(sec.require_admin), db=Depends(get_db)):
    pv = locked_draft(db)
    if draft_shape(pv)["stage"] == "draft":
        raise HTTPException(409, "Validate the draft first.")
    rows = outcomes(db, published(db).rules, pv.rules, os.environ.get("APP_ENV", "prod"))
    pv.dry_run = {"hash": content_hash(pv.rules), "at": datetime.now(timezone.utc).isoformat(), "rows": rows,
                  "changed": sum(r["changed"] for r in rows), "resets": sum(r["reset"] for r in rows)}
    record(db, admin.email, "policy", "dry-run", pv.version, "success",
           f"{pv.dry_run['changed']} targets change, {pv.dry_run['resets']} would need re-validation")
    db.commit()
    return draft_shape(pv)


@router.post("/draft/publish")
def publish(body: PublishIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    pv = locked_draft(db)
    if pv.rev != body.rev:
        raise HTTPException(409, STALE)
    if draft_shape(pv)["stage"] != "dry-run":
        raise HTTPException(409, "Run a dry run of the current draft first.")
    return apply_publish(db, pv.rules, pv.version, admin.email, pv.note, draft=pv)


@router.get("/versions")
def versions(db=Depends(get_db)):
    pvs = db.scalars(select(PolicyVersion).where(PolicyVersion.status != "draft")
                     .order_by(PolicyVersion.published_at.desc().nulls_last(), PolicyVersion.created_at.desc()))
    return [{k: v for k, v in version_shape(db, pv).items() if k != "document"} for pv in pvs]


@router.get("/versions/{v}")
def version(v: str, db=Depends(get_db)):
    pv = db.get(PolicyVersion, v)
    if not pv or pv.status == "draft":
        raise HTTPException(404, "Not found.")
    return version_shape(db, pv)


@router.post("/versions/{v}/rollback")
def rollback(v: str, body: RollbackIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(422, "Give a reason for the rollback.")
    cur = published(db)  # unlocked: apply_publish takes the published row lock after the assessments
    if db.scalar(select(PolicyVersion.version).where(PolicyVersion.status == "draft")):
        raise HTTPException(409, "Discard or publish the open draft first.")
    pv = db.get(PolicyVersion, v)
    if not pv:
        raise HTTPException(404, "Not found.")
    if pv.version == cur.version:
        raise HTTPException(409, "This version is already in force.")
    if fails := [c["detail"] for c in check_policy(pv.rules) if c["result"] == "fail"]:
        return invalid(fails)
    return apply_publish(db, pv.rules, next_label(db), admin.email, f"Rollback to {v}: {reason}")
