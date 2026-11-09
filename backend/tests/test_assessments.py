import pytest
from sqlalchemy import select

from app.api import assessments as api
from app.db import SessionLocal
from app.models import AuditEvent
from app.targets.validate import validate_target
from test_auth import make_user, signin

BODY = {"name": "Portal", "target": "https://App.Example.com", "env": "Staging", "notes": ""}


def fake_net(monkeypatch, table):
    real = validate_target

    def r(host, port, **kw):
        return [(2, 1, 6, "", (ip, 0)) for ip in table[host]]
    monkeypatch.setattr(api, "validate_target", lambda *a, **k: real(*a, resolver=r, fetch_redirect=lambda u: (200, None), **k))


@pytest.fixture
def users():
    o1, o2, adm = (signin(make_user(r)) for r in ("owner", "owner", "admin"))
    return o1, o2, adm


def test_create_defaults_and_field_errors(users):
    o1, *_ = users
    r = o1.post("/api/assessments", json=BODY)
    assert r.status_code == 201, r.text
    a = r.json()
    assert (a["status"], a["target"], a["hosts"], a["paths"], a["ports"], a["access"]) == (
        "draft", "https://app.example.com/", "app.example.com", "/*", "443", "owner")
    assert a["id"].startswith("A-") and a["validation"] is None and a["active_job_id"] is None
    assert o1.post("/api/assessments", json={**BODY, "target": "http://x.example.com"}).json()["ports"] == "80"
    r = o1.post("/api/assessments", json={"name": "", "target": "http://2130706433", "env": "Prod"})
    assert r.status_code == 422
    assert set(r.json()["detail"]["fields"]) == {"name", "target", "env"}
    assert r.json()["detail"]["fields"]["target"] == "Use a hostname or a standard IP address."


def test_access_control(users):
    o1, o2, adm = users
    aid = o1.post("/api/assessments", json=BODY).json()["id"]
    assert o2.get(f"/api/assessments/{aid}").status_code == 404
    assert o2.patch(f"/api/assessments/{aid}", json=BODY).status_code == 404
    assert o2.post(f"/api/assessments/{aid}/validate").status_code == 404
    assert o2.get(f"/api/assessments/{aid}/activity").status_code == 404
    assert adm.get(f"/api/assessments/{aid}").json()["access"] == "admin"
    assert adm.get(f"/api/assessments/{aid}/activity").status_code == 200
    assert adm.patch(f"/api/assessments/{aid}", json=BODY).status_code == 404
    assert adm.post(f"/api/assessments/{aid}/validate").status_code == 404
    assert aid not in [x["id"] for x in o2.get("/api/assessments").json()]
    assert aid not in [x["id"] for x in adm.get("/api/assessments").json()]
    assert aid in [x["id"] for x in o1.get("/api/assessments").json()]


def test_validate_persists_audits_and_patch_clears(users, monkeypatch):
    o1, *_ = users
    monkeypatch.setenv("APP_ENV", "dev")
    fake_net(monkeypatch, {"testtarget": ["10.0.0.5"], "evil.example.com": ["127.0.0.1"]})
    aid = o1.post("/api/assessments", json={**BODY, "target": "http://testtarget"}).json()["id"]
    v = o1.post(f"/api/assessments/{aid}/validate").json()
    assert v["outcome"] == "allowed" and v["policy_version"] == "v1"
    a = o1.get(f"/api/assessments/{aid}").json()
    assert a["status"] == "active" and a["validation"]["outcome"] == "allowed"
    a = o1.patch(f"/api/assessments/{aid}", json={**BODY, "target": "http://testtarget", "name": "Renamed"}).json()
    assert a["status"] == "draft" and a["validation"] is None and a["approval"] is None

    bid = o1.post("/api/assessments", json={**BODY, "target": "https://evil.example.com"}).json()["id"]
    assert o1.post(f"/api/assessments/{bid}/validate").json()["outcome"] == "blocked"
    assert o1.get(f"/api/assessments/{bid}").json()["status"] == "blocked"
    with SessionLocal() as db:
        ev = db.scalars(select(AuditEvent).where(AuditEvent.object == bid, AuditEvent.area == "validation")).one()
    assert (ev.outcome, ev.policy_version) == ("blocked", "v1")
    acts = o1.get(f"/api/assessments/{bid}/activity").json()
    assert {e["action"] for e in acts} == {"create", "validate"}


def test_unknown_target_needs_approval(users, monkeypatch):
    o1, *_ = users
    fake_net(monkeypatch, {"new.example.com": ["93.184.216.34"]})
    aid = o1.post("/api/assessments", json={**BODY, "target": "https://new.example.com"}).json()["id"]
    assert o1.post(f"/api/assessments/{aid}/validate").json()["outcome"] == "approval"
    a = o1.get(f"/api/assessments/{aid}").json()
    assert a["status"] == "awaiting-approval" and a["approval"]["state"] == "pending"


def test_catalog(users):
    c = users[0].get("/api/catalog").json()
    assert [(p["key"], p["available"]) for p in c["profiles"]] == [("quick", True), ("pre", False), ("deep", False)]
    assert c["profiles"][0]["modules"] == ["reach", "ports", "tls", "headers", "exposed", "finger"]
    assert {m["key"] for m in c["modules"] if m["available"]} == set(c["profiles"][0]["modules"])
    assert len(c["modules"]) == 14
