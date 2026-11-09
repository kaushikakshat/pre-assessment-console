import threading

import pytest
from sqlalchemy import text

from app.core import crypto
from app.db import SessionLocal, engine
from app.models import Credential, Finding, Wordlist, Job
from app.worker import main as wm
from app.worker.modules.base import ModuleResult
from test_auth import make_user, signin
from test_jobs_api import world  # noqa: F401  (fixture)
from test_scheduler import add_job, claim, sched, workers  # noqa: F401
from test_worker import draft, public


def add_finding(aid, jid, state="open", module="headers", cred=None, evidence="orig evidence", title="Issue"):
    d = draft(title)
    with SessionLocal() as db, db.begin():
        f = Finding(assessment_id=aid, job_id=jid, module=module, severity="medium", confidence="confirmed", state=state,
                    title=d.title, asset=d.asset, location={}, description="d", impact="i", evidence=evidence, reproduce="r",
                    remediation="m", fingerprint=wm.fingerprint(module, d), credential_id=cred,
                    history=[{"at": "t", "by": "System", "text": "Found"}])
        db.add(f)
        db.flush()
        return f.display_id


def first_job(aid, uid):
    from test_scheduler import add_job
    return add_job(aid, uid, state="completed")


def retest(c, a, ids, **kw):
    return c.post(f"/api/assessments/{a}/retest", json={"finding_ids": ids, "authorized": True, "idempotency_key": "r1", **kw})


def run_retest(w, monkeypatch, headers_findings, **mods):
    fakes = {"reach": lambda ctx: ModuleResult("completed", "ok"), "headers": lambda ctx: ModuleResult("completed", "ok", headers_findings),
             **mods}
    monkeypatch.setattr(wm, "MODULES", fakes)
    jid = claim(w)
    wm.run_job(jid, w, threading.Event(), resolver=public)
    return jid


def get(fid):
    with SessionLocal() as db:
        f = db.query(Finding).filter_by(display_id=fid).one()
        return f.state, [h["text"] for h in f.history], f.evidence


def test_retest_creates_linked_job(world):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid))
    r = retest(c, a, [fid])
    assert r.status_code == 202, r.text
    j = r.json()
    assert j["type"] == "retest" and j["retest_of"] == [fid] and [m["key"] for m in j["modules"]] == ["reach", "headers"]
    assert retest(c, a, [fid]).json()["id"] == j["id"]  # same key, same job
    assert retest(c, a, [fid], authorized=False).status_code == 422
    assert retest(c, a, ["F-9999"]).status_code == 422


def test_retest_resolves_not_observed(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    j0 = first_job(aid, uid)
    target, other = add_finding(aid, j0), add_finding(aid, j0, title="Other")
    jid = retest(c, a, [target]).json()["id"]
    (w,) = workers(1)
    run_retest(w, monkeypatch, [])
    state, hist, _ = get(target)
    assert state == "resolved" and hist[-1] == f"Fixed in {jid}"
    assert get(other)[0] == "not-retested"  # same module, not targeted, not observed
    with engine.connect() as cn:
        assert cn.execute(text("SELECT count(*) FROM audit_events WHERE area='finding' AND object=:o AND action='retest'"), {"o": target}).scalar() == 1


def test_retest_reopens_resolved_still_present(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid), state="resolved")
    jid = retest(c, a, [fid]).json()["id"]
    (w,) = workers(1)
    run_retest(w, monkeypatch, [draft()])
    state, hist, _ = get(fid)
    assert state == "reopened" and hist[-1] == f"Still present in {jid}"


def test_retest_missing_credential_not_retested(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    with SessionLocal() as db, db.begin():
        cr = Credential(assessment_id=aid, role_label="User", username_enc=crypto.seal("u") if crypto._ENABLED else b"x",
                        password_enc=b"x", deleted_at=text("now()"))
        db.add(cr)
        db.flush()
        cid = cr.id
    fid = add_finding(aid, first_job(aid, uid), module="access", cred=cid)
    r = retest(c, a, [fid])
    assert r.status_code == 202 and [m["key"] for m in r.json()["modules"]] == ["reach", "access"]  # deleted account not re-added
    (w,) = workers(1)
    jid = run_retest(w, monkeypatch, [], access=lambda ctx: ModuleResult("completed", "ok"))
    state, hist, _ = get(fid)
    assert state == "not-retested" and "account" in hist[-1]
    with SessionLocal() as db:
        assert db.get(Job, jid).state == "completed"  # the job does not fail


def test_retest_rejects_false_positive_selection(world):  # noqa: F811
    c, a, aid, uid = world
    j0 = first_job(aid, uid)
    ok, fp, ar = add_finding(aid, j0), add_finding(aid, j0, "false-positive", title="B"), add_finding(aid, j0, "accepted-risk", title="C")
    for bad in (fp, ar):
        assert retest(c, a, [ok, bad]).status_code == 422
    with SessionLocal() as db:
        assert db.query(Job).filter_by(type="retest").count() == 0


def test_retest_non_owner_404(world):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid))
    assert retest(signin(make_user()), a, [fid]).status_code == 404
    assert retest(signin(make_user("admin")), a, [fid]).status_code == 404


def test_retest_keeps_original_evidence(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid), evidence="original proof")
    retest(c, a, [fid])
    (w,) = workers(1)
    run_retest(w, monkeypatch, [])
    state, _, ev = get(fid)
    assert state == "resolved" and ev == "original proof"


def test_retest_incomplete_module_not_retested(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid))
    retest(c, a, [fid])
    (w,) = workers(1)
    run_retest(w, monkeypatch, [], headers=lambda ctx: ModuleResult("inconclusive", "x"))
    assert get(fid)[0] == "not-retested"


def test_retest_and_scan_exclude_each_other(world):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid))
    busy = add_job(aid, uid)  # queued scan
    r = retest(c, a, [fid])
    assert r.status_code == 409 and r.json()["detail"] == "This assessment already has a queued or running scan."
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET state='cancelled' WHERE id=:i"), {"i": busy})
    assert retest(c, a, [fid]).status_code == 202
    r = c.post("/api/jobs", json={"assessment_id": a, "profile": "quick", "authorized": True, "idempotency_key": "s1"})
    assert r.status_code == 409 and r.json()["detail"] == "A retest is running for this assessment. Wait for it to finish."


def test_retest_inherits_profile_and_wordlists(world):  # noqa: F811
    c, a, aid, uid = world
    with SessionLocal() as db, db.begin():
        db.merge(Wordlist(key="Discovery/x.txt", category="discovery", label="x", lines=10))
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET profile='pre', wordlists='[\"Discovery/x.txt\"]' WHERE id=:i"), {"i": first_job(aid, uid)})
    with SessionLocal() as db:
        origin = db.query(Job).order_by(Job.id.desc()).first().id
    fid = add_finding(aid, origin, module="exposed")
    j = retest(c, a, [fid])
    assert j.status_code == 202, j.text
    with SessionLocal() as db:
        row = db.query(Job).filter_by(type="retest").one()
        assert row.profile == "pre" and row.wordlists == ["Discovery/x.txt"]


def test_retest_resolved_unverifiable_and_missing_module(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    j0 = first_job(aid, uid)
    fixed, other = add_finding(aid, j0, "resolved"), add_finding(aid, j0, module="crawl", title="Crawl")
    with engine.begin() as cn:
        cn.execute(text("UPDATE assessments SET env='Production' WHERE id=:i"), {"i": aid})
    r = retest(c, a, [fixed, other])
    assert r.status_code == 202 and [m["key"] for m in r.json()["modules"]] == ["reach", "headers"]  # crawl is not Quick
    (w,) = workers(1)
    jid = run_retest(w, monkeypatch, [], headers=lambda ctx: ModuleResult("inconclusive", "x"))
    state, hist, _ = get(fixed)
    assert state == "resolved" and "could not verify: the headers check did not complete" in hist[-1]
    state, hist, _ = get(other)
    assert state == "not-retested" and "crawl check could not run" in hist[-1]


def test_retest_drops_unavailable_wordlists_and_marks_not_retested(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    with SessionLocal() as db, db.begin():
        db.merge(Wordlist(key="Discovery/off.txt", category="discovery", label="off", lines=10, enabled=False))
        db.merge(Wordlist(key="Discovery/ok.txt", category="discovery", label="ok", lines=10))
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET profile='pre', wordlists='[\"Discovery/off.txt\", \"Discovery/ok.txt\"]' WHERE id=:i"),
                   {"i": first_job(aid, uid)})
    with SessionLocal() as db:
        origin = db.query(Job).order_by(Job.id.desc()).first().id
    fid = add_finding(aid, origin, module="exposed")
    assert retest(c, a, [fid]).status_code == 202
    with SessionLocal() as db:
        assert db.query(Job).filter_by(type="retest").one().wordlists == ["Discovery/ok.txt"]
    (w,) = workers(1)
    run_retest(w, monkeypatch, [], exposed=lambda ctx: ModuleResult("completed", "ok"))
    state, hist, _ = get(fid)
    assert state == "not-retested" and "no longer available" in hist[-1]


def test_retest_over_cap_drops_largest_list(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    with SessionLocal() as db, db.begin():
        db.merge(Wordlist(key="Discovery/big.txt", category="discovery", label="big", lines=10_000_000))
        db.merge(Wordlist(key="Discovery/ok.txt", category="discovery", label="ok", lines=10))
    with engine.begin() as cn:
        cn.execute(text("UPDATE jobs SET profile='pre', wordlists='[\"Discovery/big.txt\", \"Discovery/ok.txt\"]' WHERE id=:i"),
                   {"i": first_job(aid, uid)})
    with SessionLocal() as db:
        origin = db.query(Job).order_by(Job.id.desc()).first().id
    fid = add_finding(aid, origin, module="exposed")
    assert retest(c, a, [fid]).status_code == 202
    with SessionLocal() as db:
        assert db.query(Job).filter_by(type="retest").one().wordlists == ["Discovery/ok.txt"]
    (w,) = workers(1)
    run_retest(w, monkeypatch, [], exposed=lambda ctx: ModuleResult("completed", "ok"))
    assert "exceeds the current request limit" in get(fid)[1][-1]


def test_production_retest_of_only_non_quick_findings_422(world):  # noqa: F811
    c, a, aid, uid = world
    fid = add_finding(aid, first_job(aid, uid), module="crawl")
    with engine.begin() as cn:
        cn.execute(text("UPDATE assessments SET env='Production' WHERE id=:i"), {"i": aid})
    r = retest(c, a, [fid])
    assert r.status_code == 422 and r.json()["detail"]["fields"]["finding_ids"] == "These findings need checks that Production targets do not allow."
