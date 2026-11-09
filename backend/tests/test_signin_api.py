import pytest
from sqlalchemy import select

from app.api import signin
from app.db import SessionLocal
from app.models import Assessment, AuditEvent, Credential
from app.targets.safe_http import SafeClient
from stub_portal import CODE, serve
from test_auth import make_user, signin as sign_in

allow_all = lambda ip, allow_private: None  # noqa: E731
PW, USER = "Secret!pw", "alice"


@pytest.fixture
def env(monkeypatch):
    srv, h = serve()
    monkeypatch.setattr(signin, "make_client", lambda db, a, hosts: SafeClient(
        hosts, max_requests=10, guard=allow_all, resolver=lambda host, port, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))]))
    o1, o2, adm = (sign_in(make_user(r)) for r in ("owner", "owner", "admin"))
    aid = o1.post("/api/assessments", json={"name": "P", "target": "http://portal.test", "env": "Staging"}).json()["id"]
    yield o1, o2, adm, aid, f"http://portal.test:{srv.server_port}", srv
    srv.shutdown()


def setup_body(base, **kw):
    return {"style": "single", "login_url": base + "/login", "username_field": "u", "password_field": "p",
            "code_field": "code", "logged_in_indicator": "Sign out", **kw}


def validate(aid, outcome="allowed"):
    with SessionLocal() as db, db.begin():
        db.execute(Assessment.__table__.update().where(Assessment.display_id == aid).values(validation={"outcome": outcome}))


def test_accounts_never_return_password(env):
    o1, _, _, aid, base, _ = env
    validate(aid)
    r = o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, bypass_code=CODE))
    assert r.status_code == 200 and r.json()["bypass_code_set"] is True and CODE not in r.text
    r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "Admin", "username": USER, "password": PW,
                                                          "test": True, "authorized": True, "bypass_code": CODE})
    assert r.status_code == 201, r.text
    assert r.json()["test_result"] == "Signed in" and r.json()["last_test"] == "ok" and r.json()["username_hint"] == "al•••"
    r2 = o1.get(f"/api/assessments/{aid}/signin")
    assert r2.json()["setup"]["bypass_code_set"] and len(r2.json()["accounts"]) == 1
    for txt in (r.text, r2.text):
        assert PW not in txt and USER not in txt.replace("al•••", "") and CODE not in txt
    cid = r.json()["id"]
    r = o1.put(f"/api/assessments/{aid}/accounts/{cid}", json={"username": USER, "password": "other-pw-9"})
    assert r.status_code == 200 and r.json()["test_result"] is None
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.object == aid)).all()
        assert rows and all(PW not in e.detail and USER not in e.detail and CODE not in e.detail for e in rows)
        c = db.scalar(select(Credential))
        assert PW.encode() not in c.password_enc
    assert o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, bypass_code="")).json()["bypass_code_set"] is False
    assert o1.delete(f"/api/assessments/{aid}/accounts/{cid}").status_code == 204
    assert o1.get(f"/api/assessments/{aid}/signin").json()["accounts"] == []
    with SessionLocal() as db:
        c = db.scalar(select(Credential).where(Credential.display_id == cid))
        assert c.deleted_at and c.password_enc == b"" and c.username_enc == b""


def test_failed_test_login_is_recorded(env):
    o1, _, _, aid, base, _ = env
    validate(aid)
    o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base))
    r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "U", "username": USER, "password": "bad",
                                                          "test": True, "authorized": True})
    assert r.json()["test_result"] == "The login page did not show the signed-in marker" and r.json()["last_test"] == "failed"


def test_login_url_out_of_scope_422(env):
    o1, _, _, aid, base, _ = env
    r = o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, login_url="http://evil.test/login"))
    assert r.status_code == 422 and r.json()["detail"]["fields"] == {"login_url": "The login page must be on an in-scope host."}


def test_test_login_requires_authorized_and_allowed(env):
    o1, _, _, aid, base, _ = env
    o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base))
    b = {"role_label": "A", "username": USER, "password": PW, "test": True, "authorized": False}
    assert o1.post(f"/api/assessments/{aid}/accounts", json=b).status_code == 422
    assert o1.post(f"/api/assessments/{aid}/accounts", json={**b, "authorized": True}).status_code == 409  # unvalidated
    validate(aid, "blocked")
    assert o1.post(f"/api/assessments/{aid}/accounts", json={**b, "authorized": True}).status_code == 409
    validate(aid, "allowed")
    assert o1.post(f"/api/assessments/{aid}/accounts", json={**b, "authorized": True}).status_code == 201
    # saving without a test needs neither
    assert o1.post(f"/api/assessments/{aid}/accounts", json={**b, "test": False}).status_code == 201


def test_max_accounts(env):
    o1, _, _, aid, _, _ = env
    b = {"role_label": "A", "username": USER, "password": PW}
    for _ in range(10):
        assert o1.post(f"/api/assessments/{aid}/accounts", json=b).status_code == 201
    assert o1.post(f"/api/assessments/{aid}/accounts", json=b).status_code == 409


def test_other_owner_404(env):
    o1, o2, _, aid, base, _ = env
    for c in (lambda: o2.get(f"/api/assessments/{aid}/signin"), lambda: o2.put(f"/api/assessments/{aid}/signin", json=setup_body(base)),
              lambda: o2.post(f"/api/assessments/{aid}/accounts", json={})):
        assert c().status_code == 404


def test_admin_view_cannot_mutate(env):
    o1, _, adm, aid, base, _ = env
    cid = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW}).json()["id"]
    assert adm.get(f"/api/assessments/{aid}/signin").status_code == 404
    assert adm.put(f"/api/assessments/{aid}/signin", json=setup_body(base)).status_code == 404
    assert adm.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW}).status_code == 404
    assert adm.put(f"/api/assessments/{aid}/accounts/{cid}", json={"username": USER, "password": PW}).status_code == 404
    assert adm.delete(f"/api/assessments/{aid}/accounts/{cid}").status_code == 404
