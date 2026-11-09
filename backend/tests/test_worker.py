import socket
import time
import threading

import pytest
from sqlalchemy import text

from app.db import SessionLocal, engine
from app.models import Finding, Job, ModuleRun
from app.scheduler import admission
from app.worker import main as wm
from app.worker.modules.base import Blocked, FindingDraft, ModuleResult
from test_scheduler import add_job, claim, make_assessment, sched, workers  # noqa: F401

public = lambda host, port, **kw: [(2, 1, 6, "", ("93.184.216.34", 0))]  # noqa: E731


def draft(title="Issue", ev="Cookie: sid=abc\nDB_PASSWORD=hunter2"):
    return FindingDraft("medium", "confirmed", title, "app.example.com", {"kind": "Cookie"}, "d", "i", ev, "r", "m", [])


def run(jid, w, **kw):
    wm.run_job(jid, w, threading.Event(), resolver=public)


def snapshot(jid):
    with SessionLocal() as db:
        j = db.get(Job, jid)
        return j.state, {m.key: (m.state, m.detail) for m in db.query(ModuleRun).filter_by(job_id=jid)}


@pytest.fixture
def setup(sched, monkeypatch):  # noqa: F811
    (w,), (aid, uid) = workers(1), make_assessment()
    fakes = {"reach": lambda ctx: ModuleResult("completed", "ok"),
             "headers": lambda ctx: ModuleResult("completed", "ok", [draft()])}
    monkeypatch.setattr(wm, "MODULES", fakes)
    return w, aid, uid, fakes


def test_completed_dedupes_findings_and_redacts(setup):
    w, aid, uid, _ = setup
    for _ in range(2):
        jid = add_job(aid, uid)
        assert claim(w) == jid
        run(jid, w)
        assert snapshot(jid)[0] == "completed"
    with SessionLocal() as db:
        (f,) = db.query(Finding).filter_by(assessment_id=aid).all()
        assert "hunter2" not in f.evidence and "sid=abc" not in f.evidence and "[REDACTED]" in f.evidence
        assert f.job_id == jid and [h["text"][:5] for h in f.history] == ["Found", "Seen "]
        assert f.state == "new"
        with engine.connect() as c:
            assert c.execute(text("SELECT count(*) FROM audit_events WHERE area='job' AND object=:o AND action='completed'"),
                             {"o": db.get(Job, jid).display_id}).scalar() == 1


def test_failures_never_look_like_success(setup):
    w, aid, uid, fakes = setup
    fakes["reach"] = lambda ctx: (_ for _ in ()).throw(OSError("boom internal-host"))
    fakes["headers"] = lambda ctx: (_ for _ in ()).throw(Blocked())
    jid = add_job(aid, uid, modules=("reach", "headers", "crawl"))
    claim(w)
    run(jid, w)
    state, mods = snapshot(jid)
    assert state == "failed"
    assert mods == {"reach": ("failed", "Could not connect to the target."),
                    "headers": ("inconclusive", "Target rate-limited or blocked the requests"),
                    "crawl": ("unavailable", "Not available in this release")}
    fakes["reach"] = lambda ctx: ModuleResult("completed", "ok")
    jid = add_job(aid, uid, modules=("reach", "headers"))
    claim(w)
    run(jid, w)
    assert snapshot(jid)[0] == "completed-warnings"
    assert wm.final_state(["completed", "completed"]) == "completed" and wm.final_state(["skipped"]) == "failed"


def test_cancel_requested_mid_run_stops_remaining_modules(setup):
    w, aid, uid, fakes = setup
    jid = add_job(aid, uid)

    def reach(ctx):
        with engine.begin() as c:
            c.execute(text("UPDATE jobs SET state='cancelling', cancel_requested=true WHERE id=:i"), {"i": jid})
        return ModuleResult("completed", "ok")
    fakes["reach"] = reach
    claim(w)
    run(jid, w)
    state, mods = snapshot(jid)
    assert state == "cancelled" and mods["reach"][0] == "completed" and mods["headers"][0] == "cancelled"


def test_assessment_no_longer_active_blocks_job(setup):
    w, aid, uid, fakes = setup
    jid = add_job(aid, uid)

    def reach(ctx):
        with engine.begin() as c:
            c.execute(text("UPDATE assessments SET status='blocked' WHERE id=:i"), {"i": aid})
        return ModuleResult("completed", "ok")
    fakes["reach"] = reach
    claim(w)
    run(jid, w)
    state, mods = snapshot(jid)
    assert state == "blocked" and mods["headers"][0] == "blocked"


def test_reaped_job_is_not_resurrected_by_a_late_worker(setup):
    w, aid, uid, fakes = setup
    jid = add_job(aid, uid)

    def reach(ctx):
        with engine.begin() as c:
            c.execute(text("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id=:i"), {"i": jid})
        with SessionLocal() as db:
            admission.reap_expired(db)
        return ModuleResult("completed", "ok")
    fakes["reach"] = reach
    claim(w)
    run(jid, w)
    state, mods = snapshot(jid)
    assert state == "interrupted" and mods["reach"][0] == "interrupted" and mods["headers"][0] == "interrupted"


def test_halt_leaves_job_for_lease_expiry(setup):
    w, aid, uid, _ = setup
    jid = add_job(aid, uid)
    claim(w)
    halt = threading.Event()
    halt.set()
    wm.run_job(jid, w, halt, resolver=public)
    assert snapshot(jid)[0] == "running"


def test_heartbeat_failure_halts_and_worker_waits_for_module_thread(monkeypatch):
    monkeypatch.setattr(wm, "HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(wm, "heartbeat", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    log = {}

    def fake_run(job_id, name, halt, *a):
        halt.wait(10)
        log["halted"] = True
        time.sleep(0.4)  # module still winding down after halt
        log["done"] = time.monotonic()
    monkeypatch.setattr(wm, "run_job", fake_run)
    wm.run_with_lease(1, "w", threading.Event())
    returned = time.monotonic()
    assert log["halted"] and returned >= log["done"]  # no return (so no new claim) while the thread was alive


def test_finding_text_fields_are_redacted_and_fingerprint_uses_redacted(setup):
    w, aid, uid, fakes = setup
    d = draft(title="Software version disclosed: Apache (admin@corp.com) x-token=abc123")
    d.description, d.reproduce, d.asset = "Server: Apache (admin@corp.com)", "curl -H 'Authorization: Bearer abc.def'", "h"
    fakes["headers"] = lambda ctx: ModuleResult("completed", "ok", [d])
    jid = add_job(aid, uid)
    claim(w)
    run(jid, w)
    with SessionLocal() as db:
        (f,) = db.query(Finding).filter_by(assessment_id=aid).all()
        blob = f.title + f.description + f.reproduce
        assert "admin@corp.com" not in blob and "abc123" not in blob and "abc.def" not in blob and "[REDACTED]" in f.title
