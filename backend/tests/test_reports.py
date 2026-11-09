import pytest
from pypdf import PdfReader
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, Finding, Job, ModuleRun, Report
from app.reports import model, pdf
from app.worker import main as wm
from test_auth import make_user, signin
from test_jobs_api import world  # noqa: F401  (fixture)
from test_scheduler import add_job, make_assessment, sched  # noqa: F401


@pytest.fixture(autouse=True)
def reports_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))


def seed(aid, uid, untested=0):
    jid = add_job(aid, uid, state="completed", modules=("reach", "headers", "exposed", "dast", "tls"))
    with SessionLocal() as db, db.begin():
        db.add(Finding(assessment_id=aid, job_id=jid, module="headers", severity="high", confidence="confirmed",
                       title="Missing HSTS", asset="app.example.com", description="d", impact="i", reproduce="r", remediation="m",
                       evidence="GET / HTTP/1.1\nAuthorization: Bearer abcdef123456\nDB_PASSWORD=hunter2", fingerprint="x",
                       location={"url": "https://app.example.com/", "host": "app.example.com", "port": 443, "kind": "Response header",
                                 "component": "Strict-Transport-Security"},
                       history=[{"at": "2026-11-09T10:00:00Z", "by": "System", "text": "Found"}]))
        for k, st, n in (("exposed", "interrupted", 0), ("dast", "completed", untested), ("tls", "unavailable", 0)):
            db.query(ModuleRun).filter_by(job_id=jid, key=k).update({"state": st, "untested": n})
        db.query(ModuleRun).filter_by(job_id=jid, key="reach").update({"state": "completed"})
        db.query(ModuleRun).filter_by(job_id=jid, key="headers").update({"state": "completed"})
        return db.get(Job, jid).display_id


def make(c, a, jid, type="technical"):
    r = c.post(f"/api/assessments/{a}/reports", json={"type": type, "job_id": jid})
    assert r.status_code == 202, r.text
    return r.json()


def build(rid):
    with SessionLocal() as db:
        return model.build(db, db.scalar(select(Report).where(Report.display_id == rid)))


def test_model_has_all_seven_categories_in_order(world):  # noqa: F811
    c, a, aid, uid = world
    rep = make(c, a, seed(aid, uid))
    m = build(rep["id"])
    assert [x["label"] for x in m["categories"]] == ["Confirmed", "Suspected", "False positive", "Unresolved", "Blocked", "Skipped", "Not tested"]
    assert set(m) == {"header", "title", "watermark", "scope", "categories", "modules", "summary", "findings_overview", "details", "limitations"}
    assert m["watermark"].startswith("PRE-ASSESSMENT RESULTS") and m["header"]["classification"] == "TBD · OD-8"
    assert m["categories"][0]["count"] == 1 and m["findings_overview"][0]["location"].startswith("Response header")
    assert make(c, a, rep["job_id"], "management")["version"] == 1 and make(c, a, rep["job_id"])["version"] == 2
    assert build(make(c, a, rep["job_id"], "management")["id"])["details"] == []


def test_model_counts_untested_modules_as_not_tested(world):  # noqa: F811
    c, a, aid, uid = world
    m = build(make(c, a, seed(aid, uid, untested=3))["id"])
    # interrupted exposed + unavailable tls + dast completed with untested>0
    assert {x["key"]: x["count"] for x in m["categories"]}["not-tested"] == 3


def test_model_redacts_and_has_no_credentials(world):  # noqa: F811
    c, a, aid, uid = world
    m = build(make(c, a, seed(aid, uid))["id"])
    blob = str(m)
    assert "abcdef123456" not in blob and "hunter2" not in blob and "[REDACTED]" in blob
    assert not any(k in blob.lower() for k in ("password_enc", "username_enc", "bypass_code"))


def test_pdf_renders_and_has_watermark_text(world, tmp_path):  # noqa: F811
    c, a, aid, uid = world
    m = build(make(c, a, seed(aid, uid))["id"])
    m["title"]["assessment"] = 'Q"</style><b>& co'  # must not break the page or the footer
    out = str(tmp_path / "r.pdf")
    pdf.render(m, out)
    assert open(out, "rb").read(4) == b"%PDF"
    r = PdfReader(out)
    text = " ".join(p.extract_text() for p in r.pages)
    assert len(r.pages) > 0 and "PRE-ASSESSMENT RESULTS" in text and "Page 1 of" in text and "Missing HSTS" in text


def test_worker_generates_then_download_audited(world):  # noqa: F811
    c, a, aid, uid = world
    rep = make(c, a, seed(aid, uid))
    assert c.get(f"/api/reports/{rep['id']}/pdf").status_code == 409  # still generating
    with SessionLocal() as db:
        assert wm.generate_report(db) and not wm.generate_report(db)
    got = c.get(f"/api/reports/{rep['id']}").json()
    assert got["state"] == "ready" and got["model"]["title"]["report_id"] == rep["id"] and got["requested_by"] == "T"
    r = c.get(f"/api/reports/{rep['id']}/pdf")
    assert r.status_code == 200 and r.content[:4] == b"%PDF" and r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].endswith(f'{rep["id"]}-v1-technical-report-T.pdf"')
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "report-downloaded", AuditEvent.object == rep["id"]))
    assert [x["id"] for x in c.get(f"/api/assessments/{a}/reports").json()] == [rep["id"]]


def test_report_retry_does_not_create_job(world, monkeypatch):  # noqa: F811
    c, a, aid, uid = world
    rep = make(c, a, seed(aid, uid))
    assert c.post(f"/api/reports/{rep['id']}/retry").status_code == 409  # not failed
    monkeypatch.setattr(pdf, "render", lambda *_: 1 / 0)
    with SessionLocal() as db:
        wm.generate_report(db)
    f = c.get(f"/api/reports/{rep['id']}").json()
    assert f["state"] == "failed" and f["error"].startswith("Report generation failed")
    with SessionLocal() as db:
        jobs = db.query(Job).count()
    monkeypatch.undo()
    assert c.post(f"/api/reports/{rep['id']}/retry").json()["state"] == "generating"
    with SessionLocal() as db:
        wm.generate_report(db)
        assert db.query(Job).count() == jobs
    assert c.get(f"/api/reports/{rep['id']}").json()["state"] == "ready"


def test_stale_generating_report_fails(world):  # noqa: F811
    c, a, aid, uid = world
    rep = make(c, a, seed(aid, uid))
    with SessionLocal() as db, db.begin():
        db.execute(Report.__table__.update().values(created_at=Report.created_at - __import__("datetime").timedelta(minutes=11)))
    with SessionLocal() as db:
        assert not wm.generate_report(db)
    assert c.get(f"/api/reports/{rep['id']}").json()["state"] == "failed"


def test_report_other_owner_404(world):  # noqa: F811
    c, a, aid, uid = world
    rep = make(c, a, seed(aid, uid))
    o = signin(make_user())
    for r in (o.get(f"/api/reports/{rep['id']}"), o.get(f"/api/reports/{rep['id']}/pdf"), o.post(f"/api/reports/{rep['id']}/retry"),
              o.get(f"/api/assessments/{a}/reports"), o.post(f"/api/assessments/{a}/reports", json={"type": "technical", "job_id": rep["job_id"]})):
        assert r.status_code == 404
    other_aid, other_uid = make_assessment()
    assert c.post(f"/api/assessments/{a}/reports", json={"type": "technical", "job_id": seed(other_aid, other_uid)}).status_code == 422
