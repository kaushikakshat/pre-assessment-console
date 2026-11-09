import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app.main import app


def test_health():
    r = TestClient(app).get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_app_role_audit_is_append_only(app_conn):
    app_conn.execute(text("INSERT INTO audit_events (actor, area, action, object, outcome, detail) "
                          "VALUES ('t','auth','x','o','success','d')"))
    assert app_conn.execute(text("SELECT count(*) FROM audit_events")).scalar() >= 1
    app_conn.commit()
    for sql in ("UPDATE audit_events SET detail = 'x'", "DELETE FROM audit_events"):
        with pytest.raises(ProgrammingError, match="permission denied"):
            app_conn.execute(text(sql))
        app_conn.rollback()


def test_seed_and_display_ids(app_conn):
    cfg = app_conn.execute(text("SELECT concurrency_limit, queue_cap FROM scheduler_config WHERE id=1")).one()
    assert tuple(cfg) == (1, 50)
    rules = app_conn.execute(text("SELECT rules FROM policy_versions WHERE version='v1'")).scalar()
    assert rules["permitted_ports"] == [80, 443, 8080, 8443] and rules["no_match"] == "approval"
    uid = app_conn.execute(text("INSERT INTO users (name,email,role,password_hash) "
                                "VALUES ('a','a@x','owner','h') RETURNING display_id")).scalar()
    assert uid.startswith("U-") and len(uid) == 5
