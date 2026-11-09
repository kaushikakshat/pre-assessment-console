import pytest
from sqlalchemy import text

from app.db import SessionLocal, engine
from app.models import Assessment, Job
from test_auth import make_user, signin
from test_scheduler import add_job, cfg, claim, make_assessment, sched, state_of, workers  # noqa: F401

R = {"reason": "because"}


def disp(table, id_):
    with SessionLocal() as db:
        return db.execute(text(f"SELECT display_id FROM {table} WHERE id=:i"), {"i": id_}).scalar()


def pending(owner_email, validation=None):
    aid, uid = make_assessment(status="awaiting-approval", owner_email=owner_email)
    with engine.begin() as c:
        c.execute(text("UPDATE assessments SET approval=CAST(:a AS jsonb), validation=CAST(:v AS jsonb) WHERE id=:i"),
                  {"a": '{"state":"pending","note":null,"by":null,"at":null,"self":false}',
                   "v": validation or '{"outcome":"approval","checks":[]}', "i": aid})
    return aid, disp("assessments", aid)


def test_non_admin_forbidden_everywhere(sched):
    c = signin(make_user())
    for m, p in [("get", "/overview"), ("get", "/assessments"), ("get", "/approvals"), ("post", "/approvals/A-1"),
                 ("get", "/jobs"), ("post", "/jobs/J/cancel"), ("post", "/jobs/J/priority"), ("post", "/jobs/J/review"),
                 ("get", "/capacity"), ("put", "/capacity"), ("post", "/workers/1"), ("get", "/audit"), ("get", "/audit.csv")]:
        assert getattr(c, m)("/api/admin" + p).status_code == 403, p


def test_approve_refuse_and_self_approval(sched):
    adm_email = make_user("admin")
    adm = signin(adm_email)
    _, a1 = pending(make_user())
    _, a2 = pending(make_user())
    _, own = pending(adm_email)
    items = {i["assessment"]["id"]: i for i in adm.get("/api/admin/approvals").json()}
    assert items[own]["own"] and not items[a1]["own"]
    assert adm.post(f"/api/admin/approvals/{a1}", json={"decision": "approve", "note": " "}).status_code == 422
    r = adm.post(f"/api/admin/approvals/{a1}", json={"decision": "approve", "note": "ok"})
    assert r.json()["status"] == "active" and r.json()["approval"]["state"] == "approved" and not r.json()["approval"]["self"]
    assert adm.post(f"/api/admin/approvals/{a1}", json={"decision": "approve", "note": "ok"}).status_code == 409
    assert adm.post(f"/api/admin/approvals/{a2}", json={"decision": "refuse", "note": "no"}).json()["status"] == "blocked"
    r = adm.post(f"/api/admin/approvals/{own}", json={"decision": "approve", "note": "mine"}).json()
    assert r["approval"]["self"] is True
    ev = adm.get("/api/admin/audit?q=" + own).json()
    assert ev[0]["action"] == "self-approval" and "self-approval" in ev[0]["detail"]


def test_hard_failed_validation_never_approved(sched):
    adm = signin(make_user("admin"))
    _, a = pending(make_user(), '{"outcome":"approval","checks":[{"key":"addresses","result":"fail"}]}')
    assert adm.post(f"/api/admin/approvals/{a}", json={"decision": "approve", "note": "x"}).status_code == 409


def test_priority_cancel_and_lists(sched):
    adm, owner = signin(make_user("admin")), make_user()
    aid, uid = make_assessment(owner_email=owner)
    q, run = add_job(aid, uid), add_job(aid, uid, state="running")
    qd, rd = disp("jobs", q), disp("jobs", run)
    assert adm.post(f"/api/admin/jobs/{qd}/priority", json={"priority": "High", "reason": ""}).status_code == 422
    assert adm.post(f"/api/admin/jobs/{rd}/priority", json={"priority": "High", **R}).status_code == 409
    assert adm.post(f"/api/admin/jobs/{qd}/priority", json={"priority": "High", **R}).json()["priority"] == "High"
    jobs = adm.get("/api/admin/jobs").json()
    assert {j["id"] for j in jobs} == {qd, rd} and jobs[0]["owner"] == "T" and jobs[0]["target"].startswith("https://")
    assert adm.post(f"/api/admin/jobs/{rd}/cancel", json={}).status_code == 422
    assert adm.post(f"/api/admin/jobs/{rd}/cancel", json=R).json()["state"] == "cancelling"
    assert adm.post(f"/api/admin/jobs/{qd}/cancel", json=R).json()["state"] == "cancelled"
    assert adm.post(f"/api/admin/jobs/{qd}/cancel", json=R).status_code == 409
    ov = adm.get("/api/admin/overview").json()
    assert [j["id"] for j in ov["running"]] == [rd] and ov["running"][0]["owner"] == "T"
    assert any(a["id"] == aid_ for a in adm.get("/api/admin/assessments").json() for aid_ in [disp("assessments", aid)])
    assert adm.get("/api/admin/assessments").json()[0]["owner"]["name"] == "T"


def test_capacity_put(sched):
    adm = signin(make_user("admin"))
    body = {"limit": 2, "aging_enabled": True, "aging_minutes": 20, "queue_cap": 40, "per_user_quota": 4, **R}
    workers(1)
    r = adm.put("/api/admin/capacity", json=body)
    assert r.status_code == 422 and r.json()["detail"] == (
        "Only 1 healthy worker is available. Enable or provision more workers before raising the limit to 2.")
    workers(1)
    assert adm.put("/api/admin/capacity", json={**body, "limit": 4}).status_code == 422
    assert adm.put("/api/admin/capacity", json={**body, "reason": " "}).status_code == 422
    r = adm.put("/api/admin/capacity", json=body).json()
    assert r["config"]["limit"] == 2 and r["config"]["aging_minutes"] == 20 and r["capacity"]["effective_limit"] == 2
    assert "concurrency_limit 1 -> 2" in r["history"][0]["detail"]
    workers_ = r["workers"]
    assert sum(w["status"] == "healthy" for w in workers_) == 2


def test_lowering_keeps_running_and_blocks_claims(sched):
    adm = signin(make_user("admin"))
    names = workers(3)
    cfg(concurrency_limit=2)
    aid, uid = make_assessment()
    a, b, c = (add_job(aid, uid) for _ in range(3))
    assert claim(names[0]) and claim(names[1]) and claim(names[2]) is None
    body = {"limit": 1, "aging_enabled": True, "aging_minutes": 15, "queue_cap": 50, "per_user_quota": 5, **R}
    assert adm.put("/api/admin/capacity", json=body).status_code == 200
    assert state_of(a) == state_of(b) == "running" and claim(names[2]) is None
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET state='completed' WHERE id=:i"), {"i": a})
    assert claim(names[2]) is None  # one still running == limit
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET state='completed' WHERE id=:i"), {"i": b})
    assert claim(names[2]) == c


def test_workers_enable_drain(sched):
    adm = signin(make_user("admin"))
    n = workers(1)[0]
    with SessionLocal() as db:
        wid = db.execute(text("SELECT id FROM workers WHERE name=:n"), {"n": n}).scalar()
    assert adm.post(f"/api/admin/workers/{wid}", json={"action": "enable", **R}).status_code == 409
    assert adm.post(f"/api/admin/workers/{wid}", json={"action": "drain", "reason": ""}).status_code == 422
    w = adm.post(f"/api/admin/workers/{wid}", json={"action": "drain", **R}).json()[0]
    assert w["status"] == "standby" and not w["enabled"] and claim(n) is None
    assert adm.post(f"/api/admin/workers/{wid}", json={"action": "enable", **R}).json()[0]["status"] == "healthy"
    with engine.begin() as cn:
        cn.execute(text("UPDATE workers SET last_heartbeat_at = now() - interval '5 minutes'"))
    assert adm.get("/api/admin/capacity").json()["workers"][0]["status"] == "heartbeat-lost"


def test_review_resume_and_others(sched):
    adm = signin(make_user("admin"))
    aid, uid = make_assessment()
    j = add_job(aid, uid, state="interrupted", modules=("reach", "ports", "tls", "headers"))
    with engine.begin() as cn:
        cn.execute(text("UPDATE module_runs SET state='completed' WHERE job_id=:i AND key IN ('reach','ports')"), {"i": j})
        cn.execute(text("UPDATE module_runs SET state='interrupted' WHERE job_id=:i AND key='tls'"), {"i": j})
        cn.execute(text("UPDATE jobs SET priority='High' WHERE id=:i"), {"i": j})
    jd = disp("jobs", j)
    assert adm.get("/api/admin/overview").json()["interrupted_unreviewed"] == 1
    assert adm.post(f"/api/admin/jobs/{jd}/review", json={"outcome": "resume", "reason": ""}).status_code == 422
    r = adm.post(f"/api/admin/jobs/{jd}/review", json={"outcome": "resume", **R})
    assert r.status_code == 200 and r.json()["review"] == "resumed"
    new = [x for x in adm.get("/api/admin/jobs").json() if x["resume_of"] == jd]
    assert len(new) == 1 and new[0]["priority"] == "High" and new[0]["state"] == "queued"
    assert [m["key"] for m in new[0]["modules"]] == ["reach", "tls", "headers"]
    assert adm.post(f"/api/admin/jobs/{jd}/review", json={"outcome": "closed", **R}).status_code == 409
    assert adm.get("/api/admin/overview").json()["interrupted_unreviewed"] == 0
    # non-resume outcomes and inactive assessment
    j2 = add_job(aid, uid, state="interrupted")
    assert adm.post(f"/api/admin/jobs/{disp('jobs', j2)}/review", json={"outcome": "rerun-advised", **R}).json()["review"] == "rerun-advised"
    j3 = add_job(aid, uid, state="interrupted")
    with engine.begin() as cn:
        cn.execute(text("UPDATE assessments SET status='blocked' WHERE id=:i"), {"i": aid})
    assert adm.post(f"/api/admin/jobs/{disp('jobs', j3)}/review", json={"outcome": "resume", **R}).status_code == 409
    assert adm.post(f"/api/admin/jobs/{disp('jobs', add_job(aid, uid))}/review", json={"outcome": "closed", **R}).status_code == 409


def test_audit_filters_and_csv(sched):
    adm = signin(make_user("admin"))
    adm.put("/api/admin/capacity", json={"limit": 1, "aging_enabled": True, "aging_minutes": 15, "queue_cap": 50,
                                          "per_user_quota": 5, "reason": "=cmd tweak"})
    ev = adm.get("/api/admin/audit?area=capacity").json()
    assert ev and all(e["area"] == "capacity" for e in ev)
    assert adm.get("/api/admin/audit?q=nonexistent-zzz").json() == []
    assert adm.get("/api/admin/audit?q=%25").json() == []  # LIKE wildcards are escaped
    assert adm.get("/api/admin/audit?outcome=failure&area=capacity").json() == []
    r = adm.get("/api/admin/audit.csv?area=capacity")
    assert r.headers["content-type"].startswith("text/csv") and r.text.splitlines()[0].startswith("id,at,actor")
    assert "audit export" not in r.text
    assert adm.get("/api/admin/audit?q=audit export").json()[0]["detail"].startswith("Exported ")
