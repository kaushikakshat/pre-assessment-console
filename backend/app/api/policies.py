import json

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Assessment, PolicyVersion
from app.targets.policy import INVARIANTS, check_policy, content_hash, schema_errors

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


def published(db) -> PolicyVersion:
    pv = db.scalar(select(PolicyVersion).where(PolicyVersion.status == "published")
                   .order_by(PolicyVersion.published_at.desc()).limit(1))
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


def replace(db, admin, doc, rev, note=None):
    """Swap the draft document under the row lock; returns a 422 response instead of the draft on bad input."""
    pv = locked_draft(db)
    if pv.rev != rev:
        raise HTTPException(409, STALE)
    errs = schema_errors(doc)
    if not errs and len(doc["rules"]) > MAX_RULES:
        errs = [f"A policy can have at most {MAX_RULES} rules"]
    if errs:
        return invalid(errs)
    pv.rules, pv.rev, pv.validation, pv.dry_run = doc, pv.rev + 1, None, None
    if note is not None:
        pv.note = note
    record(db, admin.email, "policy", "draft-save", pv.version, "success", f"rev {pv.rev}, {len(doc['rules'])} rules")
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
    return replace(db, admin, body.document, body.rev, body.note)


@router.post("/draft/import")
def import_doc(body: ImportIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    try:
        doc = json.loads(body.text)
    except ValueError:
        return invalid(["The text is not valid JSON"])
    return replace(db, admin, doc, body.rev)


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
