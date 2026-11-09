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


def test_phase3_tables_exist(app_conn):
    for t in ("login_setups", "credentials", "wordlists", "reports"):
        assert app_conn.execute(text(f"SELECT count(*) FROM {t}")).scalar() >= 0
    cfg = app_conn.execute(text("SELECT engine_slots, profile_limits FROM scheduler_config WHERE id=1")).one()
    assert cfg[0] == 1 and cfg[1]["deep"]["budget_min"] == 180 and cfg[1]["pre"]["request_cap"] == 5000
    app_conn.execute(text("SELECT engine_ok FROM workers LIMIT 1"))
    for sql in ("UPDATE audit_events SET detail = 'x'", "DELETE FROM audit_events"):
        with pytest.raises(ProgrammingError, match="permission denied"):
            app_conn.execute(text(sql))
        app_conn.rollback()


def test_engine_slots_check_rejects_4(app_conn):
    with pytest.raises(Exception, match="check"):
        app_conn.execute(text("UPDATE scheduler_config SET engine_slots = 4 WHERE id=1"))
    app_conn.rollback()


def test_credentials_cascade_on_assessment_delete(app_conn):
    uid = app_conn.execute(text("INSERT INTO users (name,email,role,password_hash) "
                                "VALUES ('c','c@x','owner','h') RETURNING id")).scalar()
    aid = app_conn.execute(text("INSERT INTO assessments (owner_id,name,target,env) "
                                "VALUES (:u,'n','t','e') RETURNING id"), {"u": uid}).scalar()
    cid = app_conn.execute(text("INSERT INTO credentials (assessment_id,role_label,username_enc,password_enc) "
                                "VALUES (:a,'admin','\\x01','\\x02') RETURNING display_id"), {"a": aid}).scalar()
    assert cid.startswith("C-") and len(cid) == 6
    app_conn.execute(text("DELETE FROM assessments WHERE id=:a"), {"a": aid})
    assert app_conn.execute(text("SELECT count(*) FROM credentials WHERE assessment_id=:a"), {"a": aid}).scalar() == 0
