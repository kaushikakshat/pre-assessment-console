import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update, delete
from sqlalchemy.sql import func as sf

from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.models import LoginAttempt, Session, User

router = APIRouter(prefix="/auth")
ISSUER = "Pre-Assessment Console"


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class PasswordIn(BaseModel):  # lengths checked in the handler so errors keep the documented shapes
    current_password: str
    new_password: str


class MfaIn(BaseModel):
    code: str = Field(max_length=12)


def me(u: User):
    return {"id": u.display_id, "name": u.name, "email": u.email, "role": u.role, "team": u.team,
            "must_change_password": u.must_change_password}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db=Depends(get_db)):
    email, ip = body.email.strip().lower(), sec.client_ip(request)
    sec.check_throttle(db, email, ip)
    user = db.scalar(select(User).where(func.lower(User.email) == email))
    if not sec.verify_password(user, body.password):
        sec.record_failure(db, email, ip)
        record(db, email, "auth", "login", email, "failure", "Incorrect email or password")
        db.commit()
        raise HTTPException(401, "The email or password is incorrect.")
    if user.status != "active":
        record(db, user.email, "auth", "login", user.display_id, "blocked", "Deactivated account")
        db.commit()
        raise HTTPException(403, "This account cannot sign in. Contact your platform administrator.")
    sec.set_cookie(response, "pa_pending", sec.make_pending(user.id), http_only=True, max_age=sec.PENDING_TTL)
    if user.mfa_enrolled:
        return {"next": "mfa"}
    user.totp_secret = user.totp_secret or pyotp.random_base32()
    db.commit()
    return {"next": "enrol", "secret": user.totp_secret,
            "otpauth_uri": pyotp.TOTP(user.totp_secret).provisioning_uri(user.email, issuer_name=ISSUER)}


@router.post("/mfa")
def mfa(body: MfaIn, request: Request, response: Response, db=Depends(get_db)):
    uid = sec.read_pending(request.cookies.get("pa_pending"))
    user = db.get(User, uid) if uid else None
    if not user or user.status != "active" or not user.totp_secret:
        raise HTTPException(401, "That code is not valid. Try again.")
    ip = sec.client_ip(request)
    sec.check_throttle(db, user.email.lower(), ip)  # pending cookie must not allow unlimited code guessing
    db.refresh(user)  # re-read last_totp_step now that the per-email lock is held
    if not sec.verify_totp(user, body.code.strip()):
        sec.record_failure(db, user.email.lower(), ip)
        record(db, user.email, "auth", "mfa", user.display_id, "failure", "Invalid code")
        db.commit()
        raise HTTPException(401, "That code is not valid. Try again.")
    if not user.mfa_enrolled:
        user.mfa_enrolled = True
        record(db, user.email, "auth", "mfa-enrol", user.display_id, "success", "Authenticator enrolled")
    user.last_login_at = sf.now()
    sec.create_session(db, user, response)
    record(db, user.email, "auth", "login", user.display_id, "success", "Signed in")
    db.commit()
    response.delete_cookie("pa_pending", path="/")
    return me(user)


@router.post("/logout", status_code=204)
def logout(request: Request, db=Depends(get_db)):
    resp = Response(status_code=204)
    try:
        sess = sec.current_session(request, db)
        user = db.get(User, sess.user_id)
        sess.revoked_at = sf.now()
        record(db, user.email, "auth", "logout", user.display_id, "success", "Signed out")
        db.commit()
    except HTTPException:
        pass
    resp.delete_cookie("pa_session", path="/")
    resp.delete_cookie("pa_csrf", path="/")
    return resp


@router.post("/password")
def change_password(body: PasswordIn, request: Request, user=Depends(sec.signed_in_user),
                    sess=Depends(sec.current_session), db=Depends(get_db)):
    email = user.email.lower()
    sec.check_throttle(db, email, sec.client_ip(request))  # same per-email lock/limit as login
    if len(body.current_password) > 256 or not sec.verify_password(user, body.current_password):  # bound argon2 input
        sec.record_failure(db, email, sec.client_ip(request))
        record(db, user.email, "auth", "password-change", user.display_id, "failure", "Incorrect current password")
        db.commit()
        raise HTTPException(400, "Your current password is incorrect.")
    if len(body.new_password) < 12:
        raise HTTPException(422, {"fields": {"new_password": "Use at least 12 characters."}})
    if len(body.new_password) > 256:
        raise HTTPException(422, {"fields": {"new_password": "Use at most 256 characters."}})
    if body.new_password == body.current_password:
        raise HTTPException(422, {"fields": {"new_password": "Choose a password you have not just used."}})
    user.password_hash = sec.hash_password(body.new_password)
    user.must_change_password = False
    db.execute(update(Session).where(Session.user_id == user.id, Session.id != sess.id,
                                     Session.revoked_at.is_(None)).values(revoked_at=sf.now()))
    db.execute(delete(LoginAttempt).where(LoginAttempt.email == email))
    record(db, user.email, "auth", "password-change", user.display_id, "success", "Password changed")
    db.commit()
    return me(user)


@router.get("/me")
def get_me(user=Depends(sec.signed_in_user)):
    return me(user)


@router.get("/csrf", status_code=204)
def csrf(response: Response):
    sec.set_csrf(response)
