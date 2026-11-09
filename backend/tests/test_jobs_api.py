import pytest
from sqlalchemy import text

from app.db import SessionLocal, engine
from app.models import Finding, Job
from test_auth import make_user, signin
from test_scheduler import add_job, cfg, make_assessment, sched, workers  # noqa: F401  (sched is a fixture)


@pytest.fixture
def world(sched):  # noqa: F811
    email = make_user()
    aid, uid = make_assessment(owner_email=email)
    with SessionLocal() as db:
        disp = db.execute(text("SELECT display_id FROM assessments WHERE id=:i"), {"i": aid}).scalar()
    return signin(email), disp, aid, uid


def body(a, **kw):
    return {"assessment_id": a, "profile": "quick", "modules": None, "authorized": True, "idempotency_key": "k1", **kw}


def test_submit_validation_and_access(world):
    c, a, aid, uid = world
    r = c.post("/api/jobs", json=body(a, authorized=False))
    assert r.status_code == 422 and "authorized" in r.json()["detail"]["fields"]
    assert c.post("/api/jobs", json=body(a, profile=None)).status_code == 422
    assert c.post("/api/jobs", json=body(a, profile="deep")).status_code == 422
    assert c.post("/api/jobs", json=body(a, modules=["nope"], profile=None)).status_code == 422
    other, adm = signin(make_user()), signin(make_user("admin"))
    assert other.post("/api/jobs", json=body(a)).status_code == 404
    assert adm.post("/api/jobs", json=body(a)).status_code == 404  # admins read, never scan
    r = c.post("/api/jobs", json=body(a, modules=["headers"], profile=None))
    assert r.status_code == 202, r.text
    j = r.json()
    assert [m["key"] for m in j["modules"]] == ["reach", "headers"]  # reach always first
    assert j["state"] == "queued" and j["queue_position"] == 1 and j["wait_estimate"] == {"lo_min": 5, "hi_min": 15}
    assert j["id"].startswith("JOB-") and j["requested_by"] == "T"
    assert other.get(f"/api/jobs/{j['id']}").status_code == 404
    assert adm.get(f"/api/jobs/{j['id']}").status_code == 200
    assert [x["id"] for x in c.get(f"/api/assessments/{a}/jobs").json()] == [j["id"]]


def test_not_active_and_production_rules(world):
    c, a, aid, uid = world
    with engine.begin() as cn:
        cn.execute(text("UPDATE assessments SET status='awaiting-approval' WHERE id=:i"), {"i": aid})
    assert c.post("/api/jobs", json=body(a)).status_code == 409
    with engine.begin() as cn:
        cn.execute(text("UPDATE assessments SET status='active', env='Production' WHERE id=:i"), {"i": aid})
    r = c.post("/api/jobs", json=body(a, profile=None, modules=["reach", "crawl"]))
    assert r.status_code == 422 and r.json()["detail"] == "Production targets can only be scanned with Quick Scan."
    assert c.post("/api/jobs", json=body(a)).status_code == 202


def test_idempotency_quota_cap_and_blocking(world):
    c, a, aid, uid = world
    first = c.post("/api/jobs", json=body(a)).json()
    again = c.post("/api/jobs", json=body(a))
    assert again.status_code == 202 and again.json()["id"] == first["id"]
    with SessionLocal() as db:
        assert db.query(Job).filter_by(assessment_id=aid).count() == 1
    cfg(per_user_quota=2)
    assert c.post("/api/jobs", json=body(a, idempotency_key="k2")).status_code == 202
    r = c.post("/api/jobs", json=body(a, idempotency_key="k3"))
    assert r.status_code == 429 and "2 active scans" in r.json()["detail"]
    cfg(per_user_quota=5, queue_cap=2)
    assert c.post("/api/jobs", json=body(a, idempotency_key="k3")).status_code == 429
    cfg(queue_cap=50, paused=True)
    r = c.post("/api/jobs", json=body(a, idempotency_key="k4"))
    assert r.status_code == 503 and r.json()["detail"] == (
        "An administrator has paused new scans. Submissions are not accepted until scanning resumes.")
    cfg(emergency=True)
    assert c.post("/api/jobs", json=body(a, idempotency_key="k4")).json()["detail"] == (
        "An administrator used Emergency stop. New scans are blocked until it is lifted.")
    assert c.post("/api/jobs", json=body(a)).status_code == 202  # existing key still returns its job


def test_cancel_queue_dashboard(world):
    c, a, aid, uid = world
    j = c.post("/api/jobs", json=body(a)).json()
    other = signin(make_user())
    assert other.post(f"/api/jobs/{j['id']}/cancel").status_code == 404
    q = c.get("/api/queue").json()
    assert q["capacity"]["blocked_reason"] is None and q["capacity"]["ceiling"] == 3 and q["capacity"]["queued"] == 1
    assert [x["id"] for x in q["mine"]] == [j["id"]]
    assert q["platform"] == [{"position": 1, "mine": True, "state": "queued", "job_id": j["id"]}]
    oq = other.get("/api/queue").json()
    assert oq["mine"] == [] and oq["platform"] == [{"position": 1, "mine": False, "state": "queued", "job_id": None}]
    d = c.get("/api/dashboard").json()
    assert d["counts"] == {"assessments": 1, "open_findings": 0, "active_jobs": 1} and d["active_job"]["id"] == j["id"]
    r = c.post(f"/api/jobs/{j['id']}/cancel")
    assert r.status_code == 200 and r.json()["state"] == "cancelled"
    assert {m["state"] for m in r.json()["modules"]} == {"skipped"}
    assert c.post(f"/api/jobs/{j['id']}/cancel").status_code == 409
    assert c.get("/api/queue").json()["recent"][0]["id"] == j["id"]
    # running job -> cancelling
    rid = add_job(aid, uid, state="running")
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET lease_owner='x', lease_expires_at = now() + interval '1 minute' WHERE id=:i"), {"i": rid})
    with SessionLocal() as db:
        disp = db.get(Job, rid).display_id
    r = c.post(f"/api/jobs/{disp}/cancel")
    assert r.json()["state"] == "cancelling"


def make_finding(aid, jid, state="new", n=[0]):
    n[0] += 1
    with SessionLocal() as db, db.begin():
        f = Finding(assessment_id=aid, job_id=jid, module="headers", severity="medium", confidence="confirmed", state=state,
                    title=f"t{n[0]}", asset="h", location={"kind": "Cookie"}, description="d", impact="i", evidence="e",
                    reproduce="r", remediation="m", references=[], fingerprint=f"fp{n[0]}{aid}", history=[], comments=[])
        db.add(f)
        db.flush()
        return f.display_id


def test_finding_transitions_reasons_audit_and_access(world):
    c, a, aid, uid = world
    jid = add_job(aid, uid, state="completed")
    f = make_finding(aid, jid)
    other, adm = signin(make_user()), signin(make_user("admin"))
    assert other.get(f"/api/findings/{f}").status_code == 404
    assert adm.get(f"/api/findings/{f}").status_code == 200
    assert adm.post(f"/api/findings/{f}/state", json={"action": "acknowledge"}).status_code == 404
    assert adm.post(f"/api/findings/{f}/comments", json={"text": "x"}).status_code == 404
    st = lambda action, reason=None: c.post(f"/api/findings/{f}/state", json={"action": action, "reason": reason})  # noqa: E731
    assert st("accept-risk", "r").status_code == 409  # not from new
    assert st("reopen", "r").status_code == 409
    assert st("false-positive").status_code == 422 and st("false-positive", "  ").status_code == 422
    r = st("acknowledge")
    assert r.status_code == 200 and r.json()["state"] == "open" and r.json()["history"][-1]["text"] == "Open · T"
    assert st("acknowledge").status_code == 409
    assert st("under-review").json()["state"] == "under-review"
    r = st("accept-risk", "Fix next quarter")
    assert r.json()["state"] == "accepted-risk" and r.json()["history"][-1]["text"] == "Accepted risk — Fix next quarter · T"
    assert st("under-review").status_code == 409
    assert st("reopen", "Risk expired").json()["state"] == "reopened"
    assert st("false-positive", "Not real").json()["state"] == "false-positive"
    assert st("bogus").status_code == 422
    r = c.post(f"/api/findings/{f}/comments", json={"text": "Looking at it"})
    assert r.json()["comments"][-1]["text"] == "Looking at it" and c.post(f"/api/findings/{f}/comments", json={"text": " "}).status_code == 422
    ev = c.get(f"/api/assessments/{a}/activity").json()
    assert sum(e["area"] == "finding" for e in ev) >= 6
    lst = c.get(f"/api/assessments/{a}/findings").json()
    assert [x["id"] for x in lst] == [f] and lst[0]["assessment_id"] == a and lst[0]["job_id"].startswith("JOB-")
