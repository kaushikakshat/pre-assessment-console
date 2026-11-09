import itertools
from types import SimpleNamespace

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.security import can, hash_password, perm_for
from app.db import SessionLocal, engine
from app.main import app
from app.models import Session, User

PW = "correct horse battery"
_n = itertools.count()


@pytest.fixture(autouse=True)
def clean():
    with engine.begin() as c:
        c.execute(text("DELETE FROM login_attempts"))
    yield


def make_user(role="owner", status="active", enrolled=False):
    email = f"u{next(_n)}@example.test"
    with SessionLocal() as db, db.begin():
        u = User(name="T", email=email, role=role, status=status, password_hash=hash_password(PW),
                 mfa_enrolled=enrolled)
        db.add(u)
    return email


def signin(email, pw=PW):
    """Full login -> mfa; returns an authenticated client with CSRF header preset."""
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"] if r.json()["next"] == "enrol" else _secret(email)
    r = c.post("/api/auth/mfa", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = c.cookies["pa_csrf"]
    return c


def _secret(email):
    with SessionLocal() as db:
        return db.query(User).filter_by(email=email).one().totp_secret


def test_login_mfa_me_flow():
    email = make_user()
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.json()["next"] == "enrol"
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/") and "Pre-Assessment" in r.json()["otpauth_uri"]
    assert c.get("/api/auth/me").status_code == 401  # pending is not a session
    r = c.post("/api/auth/mfa", json={"code": "000000"})
    assert r.status_code == 401
    r = c.post("/api/auth/mfa", json={"code": pyotp.TOTP(_secret(email)).now()})
    assert r.status_code == 200 and r.json()["email"] == email
    assert c.get("/api/auth/me").json()["role"] == "owner"
    assert r.headers["cache-control"] == "no-store" and r.headers["x-frame-options"] == "DENY"
    # second sign-in now asks for mfa only
    assert TestClient(app).post("/api/auth/login", json={"email": email, "password": PW}).json() == {"next": "mfa"}
    with SessionLocal() as db:
        assert db.query(Session).count() >= 1 and len(db.query(Session).first().id) == 64  # sha256 hex only


def test_wrong_password_and_unknown_email_same_401():
    email = make_user()
    c = TestClient(app)
    for e in (email, "nobody@example.test"):
        r = c.post("/api/auth/login", json={"email": e, "password": "nope"})
        assert (r.status_code, r.json()["detail"]) == (401, "The email or password is incorrect.")


def test_throttle_after_five_failures():
    email = make_user()
    c = TestClient(app)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"email": email, "password": "x"}).status_code == 401
    r = c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 429 and r.json()["detail"] == "Too many attempts. Wait 5 minutes before trying again."


def test_deactivated_403_only_with_correct_password():
    email = make_user(status="deactivated")
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"email": email, "password": "x"}).status_code == 401
    r = c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 403 and "cannot sign in" in r.json()["detail"]


def test_csrf_required_on_mutations():
    c = signin(make_user())
    r = c.post("/api/auth/logout", headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403 and r.json()["detail"] == "Your session expired. Reload the page and try again."
    assert c.post("/api/auth/logout").status_code == 204
    assert c.get("/api/auth/me").status_code == 401


def test_non_admin_forbidden_on_admin_users():
    c = signin(make_user("owner"))
    r = c.get("/api/admin/users")
    assert r.status_code == 403 and "limited to Platform Administrators" in r.json()["detail"]
    assert TestClient(app).get("/api/admin/users").status_code == 401


def test_admin_creates_user_and_actions():
    admin_email = make_user("admin")
    c = signin(admin_email)
    r = c.post("/api/admin/users", json={"name": "New", "email": "New.Person@example.test", "role": "owner", "team": "Web"})
    assert r.status_code == 201
    temp, uid = r.json()["temporary_password"], r.json()["user"]["id"]
    assert r.json()["user"]["mfa"] == "pending"
    assert c.post("/api/admin/users", json={"name": "N", "email": "new.person@example.test", "role": "owner"}).status_code == 409
    n = signin("new.person@example.test", temp)  # temp password works
    assert n.get("/api/auth/me").status_code == 200
    users = {u["id"]: u for u in c.get("/api/admin/users").json()}
    assert users[uid]["sessions"] == 1
    # reason required
    assert c.post(f"/api/admin/users/{uid}/actions", json={"action": "deactivate", "reason": " "}).status_code == 422
    assert c.post(f"/api/admin/users/{uid}/actions", json={"action": "deactivate"}).status_code == 422
    r = c.post(f"/api/admin/users/{uid}/actions", json={"action": "deactivate", "reason": "left team"})
    assert r.json()["status"] == "deactivated" and r.json()["sessions"] == 0
    assert n.get("/api/auth/me").status_code == 401  # revoked session
    r = c.post(f"/api/admin/users/{uid}/actions", json={"action": "reset-mfa", "reason": "lost phone"})
    assert r.json()["mfa"] == "pending"


def test_cannot_deactivate_or_demote_self():
    email = make_user("admin")
    c = signin(email)
    me_id = next(u["id"] for u in c.get("/api/admin/users").json() if u["email"] == email)
    for body in ({"action": "deactivate"}, {"action": "change-role", "role": "owner"}):
        r = c.post(f"/api/admin/users/{me_id}/actions", json={**body, "reason": "test"})
        assert r.status_code == 409


def test_revoke_sessions_action():
    admin = signin(make_user("admin"))
    victim_email = make_user()
    victim = signin(victim_email)
    uid = next(u["id"] for u in admin.get("/api/admin/users").json() if u["email"] == victim_email)
    admin.post(f"/api/admin/users/{uid}/actions", json={"action": "revoke-sessions", "reason": "audit"})
    assert victim.get("/api/auth/me").status_code == 401


def test_perm_for_and_can_matrix():
    owner, admin, other = (SimpleNamespace(id=1, role="owner"), SimpleNamespace(id=2, role="admin"),
                           SimpleNamespace(id=3, role="owner"))
    a = SimpleNamespace(owner_id=1)
    assert (perm_for(owner, a), perm_for(admin, a), perm_for(other, a)) == ("owner", "admin", None)
    assert perm_for(admin, SimpleNamespace(owner_id=2)) == "owner"  # admin's own assessment
    every = {"view", "generate_report", "change_finding_state", "comment", "retest", "scan",
             "cancel_own_job", "share", "activity"}
    assert all(can("owner", x) for x in every)
    assert {x for x in every if can("admin", x)} == {"view", "generate_report", "activity"}
    assert not any(can(None, x) for x in every)
