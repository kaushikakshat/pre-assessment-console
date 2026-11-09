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


def test_wordlist_seed_keeps_admin_flag(tmp_path):
    from sqlalchemy import text
    from app.worker.modules import wordlists
    for rel, body in (("Discovery/Web/a.txt", "x\ny\n"), ("Fuzzing/f.txt", "1\n"), ("Passwords/p.txt", "pw\n")):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    with engine.begin() as c:
        c.execute(text("DELETE FROM wordlists"))
    with SessionLocal() as db:
        assert wordlists.seed(db, tmp_path) == 2
    with engine.begin() as c:
        c.execute(text("UPDATE wordlists SET enabled=false WHERE key='Fuzzing/f.txt'"))
    with SessionLocal() as db:
        wordlists.seed(db, tmp_path)
    with engine.connect() as c:
        rows = c.execute(text("SELECT key, category, lines, enabled FROM wordlists ORDER BY key")).all()
    assert rows == [("Discovery/Web/a.txt", "discovery", 2, True), ("Fuzzing/f.txt", "fuzzing", 1, False)]
    with SessionLocal() as db:
        assert wordlists.estimate(db, ["Discovery/Web/a.txt", "Fuzzing/f.txt"], forms=10) == 12
        assert wordlists.seed(db, tmp_path) == 0  # already seeded: skipped


def test_lease_heartbeat_updates_engine_ok(monkeypatch):
    from sqlalchemy import text
    from test_scheduler import workers
    (name,) = workers(1, engine_ok=True)
    monkeypatch.setattr(wm, "HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(wm, "engine_ok", lambda: False)
    monkeypatch.setattr(wm, "run_job", lambda job_id, n, halt, *a: time.sleep(0.4))
    wm.run_with_lease(None, name, threading.Event())  # job_id None: only the worker row is touched
    with engine.connect() as c:
        assert c.execute(text("SELECT engine_ok FROM workers WHERE name=:n"), {"n": name}).scalar() is False


@pytest.mark.parametrize("allow", [False, True])
def test_engine_modules_honour_untrusted_cert_decision(setup, monkeypatch, allow):
    import ssl
    w, aid, uid, fakes = setup
    opened = []

    class Probe:
        def __init__(self, *a, **kw): pass
        def get(self, url, **kw): raise ssl.SSLCertVerificationError("self-signed")
        def close(self): pass

    class Session:
        zap, exclude = None, []
        def __init__(self, *a, **kw): opened.append(1)
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fakes["crawl"] = lambda ctx: ModuleResult("completed", "ok")
    monkeypatch.setattr(wm, "SafeClient", Probe)
    monkeypatch.setattr(wm.stages, "EngineSession", Session)
    with engine.begin() as c:
        c.execute(text("UPDATE assessments SET allow_untrusted_cert=:v WHERE id=:i"), {"v": allow, "i": aid})
    jid = add_job(aid, uid, modules=("reach", "crawl"))
    claim(w)
    run(jid, w)
    state, mods = snapshot(jid)
    if allow:  # the probe is skipped and the engine opens
        assert mods["crawl"][0] == "completed" and opened
    else:
        assert mods["crawl"] == ("failed", wm.UNTRUSTED_CERT) and not opened and state == "completed-warnings"


def test_cert_probe_fails_closed_after_one_retry(setup, monkeypatch):
    import httpx
    w, aid, uid, fakes = setup
    calls = []

    class Probe:
        def __init__(self, *a, **kw): pass
        def get(self, url, **kw):
            calls.append(1)
            raise httpx.ConnectTimeout("slow")
        def close(self): pass

    fakes["crawl"] = lambda ctx: ModuleResult("completed", "ok")
    monkeypatch.setattr(wm, "SafeClient", Probe)
    jid = add_job(aid, uid, modules=("reach", "crawl"))
    claim(w)
    run(jid, w)
    assert snapshot(jid)[1]["crawl"] == ("failed", wm.UNREACHABLE_CERT) and len(calls) == 2


def test_login_and_otp_urls_are_excluded_from_engine_and_modules(setup, monkeypatch):
    """Safety constraint: the login/OTP URLs are never crawled, fuzzed or attacked, with or without accounts."""
    w, aid, uid, fakes = setup
    seen = {}

    class Session:
        zap = None
        def __init__(self, job, a, scope, **kw):
            seen["extra"] = kw.get("extra_exclude")
            self.exclude = wm.stages.excluded_regexes(a, kw.get("extra_exclude", ()))
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def crawl(ctx):
        seen["rc"] = ctx.run_ctx["exclude"]
        return ModuleResult("completed", "ok")

    fakes["crawl"] = crawl
    monkeypatch.setattr(wm.stages, "EngineSession", Session)
    monkeypatch.setattr(wm, "untrusted_cert", lambda args: None)
    with SessionLocal() as db:
        db.add(wm.LoginSetup(assessment_id=aid, style="single", login_url="http://x.test/login", username_field="u",
                             password_field="p", logged_in_indicator="ok", otp_url="http://x.test/otp"))
        db.commit()
    jid = add_job(aid, uid, modules=("reach", "crawl"))
    claim(w)
    run(jid, w)
    assert seen["extra"] == ["http://x.test/login", "http://x.test/otp"]
    import re
    assert all(any(re.fullmatch(r, u + "?x=1") for r in seen["rc"]) for u in seen["extra"])  # ZAP exclusions and run_ctx
