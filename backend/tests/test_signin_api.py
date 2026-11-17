from datetime import timedelta

import pytest
from sqlalchemy import select

from app.api import signin
from app.db import SessionLocal
from app.models import Assessment, AuditEvent, Credential, SchedulerConfig
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
    aid = o1.post("/api/assessments", json={"name": "P", "target": "http://portal.test", "env": "Staging",
                                                  "ports": str(srv.server_port)}).json()["id"]
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


def test_signin_only_on_target_host_and_only_it_is_resolved(env, monkeypatch):
    o1, _, _, aid, base, _ = env
    validate(aid)
    with SessionLocal() as db, db.begin():
        db.execute(Assessment.__table__.update().where(Assessment.display_id == aid).values(hosts="portal.test, other.test"))
    other = base.replace("portal", "other")
    r = o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, login_url=other + "/login"))
    assert r.status_code == 422 and r.json()["detail"]["fields"] == {"login_url": "The sign-in page must be on the target host."}
    assert o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base)).status_code == 200
    seen = []
    orig = signin.make_client
    monkeypatch.setattr(signin, "make_client", lambda db, a, hosts: seen.append(hosts) or orig(db, a, hosts))
    r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW,
                                                          "test": True, "authorized": True})
    assert r.status_code == 201 and seen == [{"portal.test"}]


def test_login_url_out_of_scope_422(env):
    o1, _, _, aid, base, _ = env
    r = o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, login_url="http://evil.test/login"))
    assert r.status_code == 422 and r.json()["detail"]["fields"] == {"login_url": "The sign-in page must be on the target host."}


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


def test_empty_url_indicator_and_port_and_exclusion_rejected(env):
    o1, _, _, aid, base, _ = env
    f = lambda **kw: o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, **kw))  # noqa: E731
    assert "logged_in_indicator" in f(logged_in_indicator="url:").json()["detail"]["fields"]
    assert "login_url" in f(login_url="http://portal.test:9/login").json()["detail"]["fields"]
    o1.patch(f"/api/assessments/{aid}", json={"name": "P", "target": "http://portal.test", "env": "Staging",
                                              "ports": str(base.rsplit(":", 1)[1]), "exclusions": "/login*"})
    assert "login_url" in f().json()["detail"]["fields"]


def test_rate_limit_and_locked_account(env, monkeypatch):
    o1, _, _, aid, base, _ = env
    validate(aid)
    o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base))
    b = {"role_label": "L", "username": "locked", "password": PW, "test": True, "authorized": True}
    r = o1.post(f"/api/assessments/{aid}/accounts", json=b)
    assert r.json()["test_result"] == "Account appears locked"
    r2 = o1.post(f"/api/assessments/{aid}/accounts", json=b)
    assert r2.status_code == 429 and r2.json()["detail"] == "Wait before testing sign-in again."
    monkeypatch.setattr(signin, "TEST_GAP", timedelta(0))
    r3 = o1.put(f"/api/assessments/{aid}/accounts/{r.json()['id']}", json={**b, "username": "locked"})
    assert r3.status_code == 409 and "appears locked" in r3.json()["detail"]
    # replacing without a test clears the lock
    cid = r.json()["id"]
    assert o1.put(f"/api/assessments/{aid}/accounts/{cid}", json={**b, "test": False, "username": USER}).status_code == 200
    r4 = o1.put(f"/api/assessments/{aid}/accounts/{cid}", json={**b, "username": USER})
    assert r4.status_code == 200 and r4.json()["test_result"] == "Signed in"


def test_paused_refuses_test(env):
    o1, _, _, aid, base, _ = env
    validate(aid)
    o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base))
    with SessionLocal() as db, db.begin():
        db.execute(SchedulerConfig.__table__.update().values(paused=True))
    try:
        r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW,
                                                              "test": True, "authorized": True})
        assert r.status_code == 503
    finally:
        with SessionLocal() as db, db.begin():
            db.execute(SchedulerConfig.__table__.update().values(paused=False))


def test_bad_types_never_echoed_and_short_hint(env):
    o1, _, _, aid, base, _ = env
    for bad in (123, {"x": 1}, "p" * 500):
        for k in ("password", "bypass_code"):
            r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW, k: bad})
            assert r.status_code == 422
            assert str(bad) not in r.text
    r = o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": "abcd", "password": PW})
    assert r.json()["username_hint"] == "•••"


def test_no_secrets_in_logs(env, caplog):
    import logging
    o1, _, _, aid, base, _ = env
    validate(aid)
    caplog.set_level(logging.DEBUG)
    o1.put(f"/api/assessments/{aid}/signin", json=setup_body(base, bypass_code=CODE))
    o1.post(f"/api/assessments/{aid}/accounts", json={"role_label": "A", "username": USER, "password": PW,
                                                      "test": True, "authorized": True, "bypass_code": CODE})
    assert PW not in caplog.text and CODE not in caplog.text and USER not in caplog.text
