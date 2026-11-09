import secrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import Session, User

router = APIRouter(prefix="/admin/users")
Role = Literal["owner", "admin"]


class CreateIn(BaseModel):
    name: str = Field(max_length=120)
    email: str = Field(max_length=254)
    role: Role
    team: str | None = Field(None, max_length=120)


class ActionIn(BaseModel):
    action: Literal["change-role", "deactivate", "reactivate", "reset-mfa", "revoke-sessions"]
    role: Role | None = None
    reason: str = Field(max_length=1000)


def shape(db, u: User):
    n = db.scalar(select(func.count()).select_from(Session).where(
        Session.user_id == u.id, Session.revoked_at.is_(None), Session.expires_at > func.now()))
    return {"id": u.display_id, "name": u.name, "email": u.email, "role": u.role, "team": u.team,
            "status": u.status, "mfa": "enrolled" if u.mfa_enrolled else "pending",
            "last_login_at": u.last_login_at, "sessions": n}


@router.get("")
def list_users(admin=Depends(sec.require_admin), db=Depends(get_db)):
    return [shape(db, u) for u in db.scalars(select(User).order_by(User.id))]


@router.post("", status_code=201)
def create_user(body: CreateIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    email = body.email.strip().lower()
    if not body.name.strip() or "@" not in email:
        raise HTTPException(422, {"fields": {"name" if not body.name.strip() else "email": "Enter a valid value."}})
    if db.scalar(select(User).where(func.lower(User.email) == email)):
        raise HTTPException(409, "A user with that email already exists.")
    temp = secrets.token_urlsafe(12)
    u = User(name=body.name.strip(), email=email, role=body.role, team=body.team, status="active",
             password_hash=sec.hash_password(temp), must_change_password=True)
    db.add(u)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A user with that email already exists.")
    db.refresh(u)  # load server-side display_id
    record(db, admin.email, "users", "create", u.display_id, "success", f"Created {body.role} account")
    out = {"user": shape(db, u), "temporary_password": temp}
    db.commit()
    return out


@router.post("/{user_id}/actions")
def user_action(user_id: str, body: ActionIn, admin=Depends(sec.require_admin), db=Depends(get_db)):
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(422, {"fields": {"reason": "Enter a reason."}})
    u = db.scalar(select(User).where(User.display_id == user_id))
    if not u:
        raise HTTPException(404, "Not found.")
    a = body.action
    if u.id == admin.id and (a == "deactivate" or (a == "change-role" and body.role != "admin")):
        raise HTTPException(409, "You cannot deactivate or demote your own account.")
    if a == "change-role":
        if not body.role:
            raise HTTPException(422, {"fields": {"role": "Choose a role."}})
        u.role = body.role
    elif a == "deactivate":
        u.status = "deactivated"
        sec.revoke_sessions(db, u.id)
    elif a == "reactivate":
        u.status = "active"
    elif a == "reset-mfa":
        u.totp_secret, u.mfa_enrolled, u.last_totp_step = None, False, None
        sec.revoke_sessions(db, u.id)
    else:
        sec.revoke_sessions(db, u.id)
    record(db, admin.email, "users", a, u.display_id, "success",
           f"{reason}" + (f" (role: {body.role})" if a == "change-role" else ""))
    db.commit()
    return shape(db, u)
