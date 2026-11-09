import itertools
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text, update

from app.db import SessionLocal, engine
from app.models import Assessment, Job, ModuleRun, SchedulerConfig, User, Worker
from app.scheduler import admission
from test_auth import make_user

_n = itertools.count()


@pytest.fixture
def sched():
    """Empty queue, default config, no workers; restores config afterwards."""
    with engine.begin() as c:
        for t in ("reports", "findings", "module_runs"):
            c.execute(text(f"DELETE FROM {t}"))
        c.execute(text("UPDATE workers SET current_job_id = NULL"))
        c.execute(text("DELETE FROM jobs"))
        c.execute(text("DELETE FROM workers"))
        c.execute(text("UPDATE scheduler_config SET concurrency_limit=1, aging_enabled=true, aging_minutes=15, "
                       "queue_cap=50, per_user_quota=5, paused=false, emergency=false, engine_slots=1"))
    yield
    with engine.begin() as c:
        c.execute(text("UPDATE scheduler_config SET concurrency_limit=1, paused=false, emergency=false, "
                       "queue_cap=50, per_user_quota=5, aging_enabled=true, aging_minutes=15, engine_slots=1"))


def cfg(**kw):
    with SessionLocal() as db, db.begin():
        db.execute(update(SchedulerConfig).values(**kw))


def workers(n, enabled=True, engine_ok=False):
    names = [f"w{next(_n)}" for _ in range(n)]
    with SessionLocal() as db, db.begin():
        db.add_all(Worker(name=w, enabled=enabled, engine_ok=engine_ok, last_heartbeat_at=datetime.now(timezone.utc)) for w in names)
    return names


def make_assessment(status="active", env="Staging", owner_email=None):
    email = owner_email or make_user()
    with SessionLocal() as db, db.begin():
        u = db.query(User).filter_by(email=email).one()
        a = Assessment(owner_id=u.id, name="T", target="https://app.example.com/", env=env, hosts="app.example.com",
                       ports="443", status=status, policy_version="v1")
        db.add(a)
        db.flush()
        return a.id, u.id


def add_job(aid, uid, priority="Normal", age_min=0, state="queued", modules=("reach", "headers")):
    with SessionLocal() as db, db.begin():
        j = Job(assessment_id=aid, requested_by=uid, priority=priority, state=state, policy_version="v1",
                idempotency_key=f"k{next(_n)}", submitted_at=datetime.now(timezone.utc) - timedelta(minutes=age_min))
        db.add(j)
        db.flush()
        db.add_all(ModuleRun(job_id=j.id, key=k) for k in modules)
        return j.id


def claim(name):
    with SessionLocal() as db:
        j = admission.claim_next(db, name)
        return j and j.id


def state_of(jid):
    with SessionLocal() as db:
        return db.get(Job, jid).state


@pytest.mark.parametrize("limit", [1, 2])
def test_concurrent_claims_never_exceed_limit(sched, limit):
    cfg(concurrency_limit=limit)
    ws, (aid, uid) = workers(8), make_assessment()
    ids = {add_job(aid, uid) for _ in range(20)}
    done, lock, peak, errors = [], threading.Lock(), [0], []

    def running():
        with engine.connect() as c:
            return c.execute(text("SELECT count(*) FROM jobs WHERE state IN ('running','cancelling')")).scalar()

    def work(w):
        try:
            end = time.monotonic() + 40
            while time.monotonic() < end:
                jid = claim(w)
                if jid:
                    seen = running()
                    with lock:
                        peak[0] = max(peak[0], seen)
                        done.append(jid)
                    time.sleep(0.01)
                    with engine.begin() as c:
                        c.execute(text("UPDATE jobs SET state='completed' WHERE id=:i"), {"i": jid})
                else:
                    time.sleep(0.005)
                    with lock:
                        if len(done) == len(ids):
                            return
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=work, args=(w,)) for w in ws]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    assert not errors, errors
    assert 1 <= peak[0] <= limit
    assert sorted(done) == sorted(ids)  # every job exactly once


def test_fifo_and_priority_and_aging(sched):
    (w,), (aid, uid) = workers(1), make_assessment()
    a, b, c = (add_job(aid, uid) for _ in range(3))
    for expect in (a, b, c):
        assert claim(w) == expect
        with engine.begin() as cn:
            cn.execute(text("UPDATE jobs SET state='completed' WHERE id=:i"), {"i": expect})
    low, normal, high = add_job(aid, uid, "Low"), add_job(aid, uid, "Normal"), add_job(aid, uid, "High")
    assert claim(w) == high


def test_aging_promotes_old_low_over_new_normal(sched):
    (w,), (aid, uid) = workers(1), make_assessment()
    new_normal, old_low = add_job(aid, uid, "Normal"), add_job(aid, uid, "Low", age_min=31)
    assert claim(w) == old_low
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET state='completed' WHERE id=:i"), {"i": old_low})
    cfg(aging_enabled=False)
    old_low2 = add_job(aid, uid, "Low", age_min=300)
    assert claim(w) == new_normal and state_of(old_low2) == "queued"


def test_paused_emergency_disabled_unknown_worker_do_not_claim(sched):
    (w,), (aid, uid) = workers(1), make_assessment()
    jid = add_job(aid, uid)
    for flag in ("paused", "emergency"):
        cfg(**{flag: True})
        assert claim(w) is None
        cfg(**{flag: False})
    (off,) = workers(1, enabled=False)
    assert claim(off) is None and claim("nobody") is None
    assert state_of(jid) == "queued"
    with SessionLocal() as db:
        assert admission.capacity(db).blocked_reason is None
    cfg(paused=True, emergency=True)
    with SessionLocal() as db:
        assert admission.capacity(db).blocked_reason == "emergency"
    cfg(emergency=False)
    with SessionLocal() as db:
        assert admission.capacity(db).blocked_reason == "paused"


def test_effective_limit_is_min_of_limit_and_healthy_workers(sched):
    (w,), (aid, uid) = workers(1), make_assessment()
    cfg(concurrency_limit=3)
    with SessionLocal() as db:
        c = admission.capacity(db)
        assert (c.limit, c.effective_limit, c.healthy_workers, c.ceiling) == (3, 1, 1, 3)
    a, b = add_job(aid, uid), add_job(aid, uid)
    assert claim(w) == a and claim(w) is None  # only one healthy worker: second claim refused
    with engine.begin() as cn:  # stale heartbeat is not healthy
        cn.execute(text("UPDATE workers SET last_heartbeat_at = now() - interval '31 seconds'"))
    with SessionLocal() as db:
        assert admission.healthy_workers(db) == 0


def test_expired_lease_is_interrupted_never_completed(sched):
    (w,), (aid, uid) = workers(1), make_assessment()
    jid = add_job(aid, uid, modules=("reach", "ports", "tls"))
    assert claim(w) == jid
    with engine.begin() as c:
        c.execute(text("UPDATE module_runs SET state='completed' WHERE key='reach'"))
        c.execute(text("UPDATE module_runs SET state='running' WHERE key='ports'"))
        c.execute(text("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id=:i"), {"i": jid})
    with SessionLocal() as db:
        assert admission.reap_expired(db) == 1
    with SessionLocal() as db:
        assert db.get(Job, jid).state == "interrupted"
        mods = {m.key: m.state for m in db.query(ModuleRun).filter_by(job_id=jid)}
        assert mods == {"reach": "completed", "ports": "interrupted", "tls": "interrupted"}
        assert db.get(Worker, db.query(Worker.id).filter_by(name=w).scalar()).current_job_id is None
    with SessionLocal() as db:
        assert not admission.heartbeat(db, w, jid)  # lease is gone; the worker must stop writing


def test_heartbeat_extends_only_own_lease_and_position(sched):
    w1, w2 = workers(2)
    (aid, uid) = make_assessment()
    j1, j2, j3 = (add_job(aid, uid) for _ in range(3))
    cfg(concurrency_limit=2)
    assert claim(w1) == j1
    with SessionLocal() as db:
        assert admission.heartbeat(db, w1, j1) and not admission.heartbeat(db, w2, j1)
        assert admission.queue_position(db, db.get(Job, j3)) == 2 and admission.queue_position(db, db.get(Job, j1)) is None
    assert admission.wait_estimate(2) == {"lo_min": 10, "hi_min": 30} and admission.wait_estimate(None) is None


def test_engine_slot_blocks_second_engine_job_not_quick(sched):
    cfg(concurrency_limit=3)
    ws, (aid, uid) = workers(3), make_assessment()
    first = add_job(aid, uid, modules=("reach", "crawl"))
    second = add_job(aid, uid, modules=("reach", "dast"))
    quick = add_job(aid, uid)
    assert claim(ws[0]) == first
    assert claim(ws[1]) == quick  # skips the engine job ahead of it
    assert claim(ws[2]) is None and state_of(second) == "queued"
    cfg(engine_slots=2)
    assert claim(ws[2]) == second
    assert admission.uses_engine(["reach", "api"]) and not admission.uses_engine(["reach", "headers"])
