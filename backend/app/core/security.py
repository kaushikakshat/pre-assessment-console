import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import func, select, update

from app.db import get_db
from app.models import Assessment, LoginAttempt, Session, User

SESSION_LIFETIME = timedelta(hours=12)  # TBD OD-19: absolute lifetime pending decision
PENDING_TTL = 300
THROTTLE_WINDOW = timedelta(minutes=5)
MAX_FAILURES_PER_EMAIL = 5
MAX_FAILURES_PER_IP = 20  # looser than per-email so a shared NAT is not locked out by one user
THROTTLE_MSG = "Too many attempts. Wait 5 minutes before trying again."

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(pw: str) -> str:
    return _hasher.hash(pw)


def verify_password(user: User | None, pw: str) -> bool:
    """Always performs one argon2 verify so unknown emails take the same time."""
    try:
        return _hasher.verify(user.password_hash if user else _DUMMY_HASH, pw) and user is not None
    except VerificationError:
        return False


def _secure() -> bool:
    return os.environ.get("COOKIE_SECURE", "false").lower() == "true"


def set_cookie(resp: Response, name: str, value: str, *, http_only: bool, max_age: int):
    resp.set_cookie(name, value, httponly=http_only, samesite="strict", secure=_secure(), max_age=max_age, path="/")


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---- throttling ----
def check_throttle(db, email: str, ip: str | None):
    since = datetime.now(timezone.utc) - THROTTLE_WINDOW
    by_email = db.scalar(select(func.count()).select_from(LoginAttempt)
                         .where(LoginAttempt.email == email, LoginAttempt.at > since))
    by_ip = db.scalar(select(func.count()).select_from(LoginAttempt)
                      .where(LoginAttempt.ip == ip, LoginAttempt.at > since)) if ip else 0
    if by_email >= MAX_FAILURES_PER_EMAIL or by_ip >= MAX_FAILURES_PER_IP:
        raise HTTPException(429, THROTTLE_MSG)


def record_failure(db, email: str, ip: str | None):
    db.add(LoginAttempt(email=email, ip=ip))
    db.flush()


# ---- pending-login cookie (password verified, MFA outstanding) ----
def _sign(msg: str) -> str:
    return hmac.new(os.environ["SECRET_KEY"].encode(), msg.encode(), hashlib.sha256).hexdigest()


def make_pending(user_id: int) -> str:
    msg = f"{user_id}.{int(time.time()) + PENDING_TTL}"
    return f"{msg}.{_sign(msg)}"


def read_pending(token: str | None) -> int | None:
    try:
        uid, exp, sig = token.rsplit(".", 2)
        if hmac.compare_digest(sig, _sign(f"{uid}.{exp}")) and int(exp) > time.time():
            return int(uid)
    except (AttributeError, ValueError):
        pass
    return None


# ---- sessions ----
def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user: User, resp: Response):
    token = secrets.token_urlsafe(32)
    db.add(Session(id=_digest(token), user_id=user.id, expires_at=datetime.now(timezone.utc) + SESSION_LIFETIME))
    ttl = int(SESSION_LIFETIME.total_seconds())
    set_cookie(resp, "pa_session", token, http_only=True, max_age=ttl)
    set_csrf(resp)


def set_csrf(resp: Response):
    set_cookie(resp, "pa_csrf", secrets.token_urlsafe(32), http_only=False, max_age=int(SESSION_LIFETIME.total_seconds()))


def revoke_sessions(db, user_id: int):
    db.execute(update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
               .values(revoked_at=func.now()))


def current_session(request: Request, db=Depends(get_db)) -> Session:
    token = request.cookies.get("pa_session")
    sess = db.get(Session, _digest(token)) if token else None
    if not sess or sess.revoked_at or sess.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(401, "Sign in to continue.")
    return sess


def current_user(sess=Depends(current_session), db=Depends(get_db)) -> User:
    user = db.get(User, sess.user_id)
    if not user or user.status != "active":
        raise HTTPException(401, "Sign in to continue.")
    return user


def require_admin(user=Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "The admin console is limited to Platform Administrators.")
    return user


# ---- RBAC (DESIGN_SYSTEM §11.2) ----
_ALL = {"view", "generate_report", "change_finding_state", "comment", "retest", "scan",
        "cancel_own_job", "share", "activity"}
_CAPS = {"owner": _ALL, "admin": {"view", "generate_report", "activity"}}


def perm_for(user: User, assessment: Assessment) -> str | None:
    if assessment.owner_id == user.id:
        return "owner"
    return "admin" if user.role == "admin" else None


def can(level: str | None, action: str) -> bool:
    return action in _CAPS.get(level, ())


def get_assessment_or_404(db, display_id: str, user: User, action: str) -> Assessment:
    a = db.scalar(select(Assessment).where(Assessment.display_id == display_id))
    if not a or not can(perm_for(user, a), action):
        raise HTTPException(404, "Not found.")
    return a
