import json

import httpx
import pytest
from sqlalchemy import text

from app.api import policies
from app.db import SessionLocal, engine
from test_assessments import BODY, fake_net
from test_auth import make_user, signin
from test_scheduler import add_job, make_assessment

P = "/api/admin/policies"


@pytest.fixture(autouse=True)
def restore_policy():
    with engine.begin() as c:  # other tests leave validated assessments behind; dry runs would list them
        c.execute(text("UPDATE assessments SET validation=NULL"))
    yield
    with engine.begin() as c:
        for q in ("UPDATE assessments SET policy_version='v1' WHERE policy_version <> 'v1'",
                  "UPDATE jobs SET policy_version='v1' WHERE policy_version <> 'v1'",
                  "DELETE FROM policy_versions WHERE version <> 'v1'",
                  "UPDATE policy_versions SET status='published' WHERE version='v1'"):
            c.execute(text(q))


@pytest.fixture
def adm():
    return signin(make_user("admin"))


def rule(n, **kw):
    return {"id": f"R-{n:02d}", "outcome": "deny", "match": "suffix", "value": "example.com", **kw}


def test_owner_forbidden_on_every_route():
    c = signin(make_user())
    for m, p, b in [("get", "", None), ("post", "/draft", {}), ("put", "/draft", {"document": {}, "note": "", "rev": 0}),
                    ("post", "/draft/import", {"text": "{}", "rev": 0}), ("delete", "/draft", None),
                    ("post", "/draft/validate", None), ("post", "/draft/dry-run", None),
                    ("post", "/draft/publish", {"rev": 0}), ("get", "/versions", None), ("get", "/versions/v1", None),
                    ("post", "/versions/v1/rollback", {"reason": "x"})]:
        assert c.request(m, P + p, json=b).status_code == 403, (m, p)


def test_start_save_discard(adm):
    r = adm.get(P).json()
    assert r["draft"] is None and r["published"]["version"] == "v1" and r["invariants"]
    d = adm.post(P + "/draft", json={})
    assert d.status_code == 201
    d = d.json()
    pub = r["published"]["document"]
    assert any(x.get("dev_only") for x in pub["rules"])  # v1 carries the dev-only demo rules
    without_dev = {**pub, "rules": [x for x in pub["rules"] if not x.get("dev_only")]}
    assert (d["version"], d["stage"], d["document"], d["note"]) == ("v2", "draft", without_dev, "")  # tests run with APP_ENV unset (prod)
    assert adm.post(P + "/draft", json={}).status_code == 409
    doc = {**d["document"], "rules": d["document"]["rules"] + [rule(3)]}
    r = adm.put(P + "/draft", json={"document": doc, "note": "n", "rev": 0})
    assert r.status_code == 200 and r.json()["rev"] == 1 and r.json()["note"] == "n"
    assert adm.delete(P + "/draft").status_code == 204
    assert adm.get(P).json()["draft"] is None
    assert adm.delete(P + "/draft").status_code == 404
    acts = [e["action"] for e in adm.get("/api/admin/audit?area=policy").json()]
    assert {"draft-start", "draft-save", "draft-discard"} <= set(acts)


def test_stale_rev_conflict(adm):
    doc = adm.post(P + "/draft", json={}).json()["document"]
    a = {**doc, "no_match": "allow"}
    b = {**doc, "no_match": "deny"}
    assert adm.put(P + "/draft", json={"document": a, "note": "", "rev": 0}).status_code == 200
    r = adm.put(P + "/draft", json={"document": b, "note": "", "rev": 0})
    assert r.status_code == 409 and r.json()["detail"].startswith("Someone else")
    assert adm.get(P).json()["draft"]["document"] == a


def test_save_rejects_schema_errors(adm):
    doc = adm.post(P + "/draft", json={}).json()["document"]
    bad = {**doc, "rules": [rule(9, match="cidr", value="10.0.0/33")]}
    r = adm.put(P + "/draft", json={"document": bad, "note": "", "rev": 0})
    assert r.status_code == 422 and any("CIDR must look like 203.0.113.0/24" in e for e in r.json()["errors"])
    d = adm.get(P).json()["draft"]
    assert d["rev"] == 0 and d["document"] == doc


def test_import_rejects_bad_json(adm):
    doc = adm.post(P + "/draft", json={}).json()["document"]
    many = {**doc, "rules": [rule(i + 1, value=f"h{i}.example.com", match="domain") for i in range(501)]}
    for t in ["{", "[]", json.dumps(many), "x" * 262145]:
        assert adm.post(P + "/draft/import", json={"text": t, "rev": 0}).status_code == 422, t[:10]
    assert adm.get(P).json()["draft"]["rev"] == 0
    new = {**doc, "no_match": "allow"}
    r = adm.post(P + "/draft/import", json={"text": json.dumps(new), "rev": 0})
    assert r.status_code == 200 and r.json()["document"] == new and r.json()["rev"] == 1
    assert "draft-import" in [e["action"] for e in adm.get("/api/admin/audit?area=policy").json()]


def test_validate_sets_stage_and_edit_clears_it(adm):
    d = adm.post(P + "/draft", json={}).json()
    r = adm.post(P + "/draft/validate").json()
    assert r["stage"] == "validated" and r["checks"]
    r = adm.put(P + "/draft", json={"document": d["document"], "note": "", "rev": 0}).json()
    assert r["stage"] == "draft" and r["checks"] is None
    bad = {**d["document"], "rules": [rule(9, outcome="allow", match="cidr", value="127.0.0.0/8")]}
    adm.put(P + "/draft", json={"document": bad, "note": "", "rev": 1})
    r = adm.post(P + "/draft/validate").json()
    assert r["stage"] == "draft" and any(c["result"] == "fail" for c in r["checks"])


def test_draft_never_used_for_validation(adm, monkeypatch):
    doc = adm.post(P + "/draft", json={}).json()["document"]
    adm.put(P + "/draft", json={"document": {**doc, "rules": [rule(9)]}, "note": "", "rev": 0})
    o = signin(make_user())
    aid = o.post("/api/assessments", json=BODY).json()["id"]
    fake_net(monkeypatch, {"app.example.com": ["93.184.216.34"]})
    r = o.post(f"/api/assessments/{aid}/validate")
    assert r.status_code == 200, r.text
    assert r.json()["policy_version"] == "v1" and r.json()["outcome"] != "blocked"


def validated_assessment(outcome="allowed", status="active", host="app.example.com", approval=None):
    aid, uid = make_assessment(status=status)
    with engine.begin() as c:
        c.execute(text("UPDATE assessments SET target=:t, hosts=:h, validation=CAST(:v AS jsonb), approval=CAST(:a AS jsonb)"
                       " WHERE id=:i"), {"t": f"https://{host}/", "h": host, "i": aid, "a": approval,
                                         "v": json.dumps({"outcome": outcome, "checks": []})})
    return aid, uid


def dns(monkeypatch):
    def fake(host, **kw):
        if host == "gone.example.com":
            raise OSError("nope")
        return ["93.184.216.34"]
    monkeypatch.setattr("app.targets.ipguard.resolve", fake)


def edit_draft(adm, **changes):
    d = adm.post(P + "/draft", json={}).json()
    doc = {**d["document"], **changes}
    assert adm.put(P + "/draft", json={"document": doc, "note": "edit", "rev": 0}).status_code == 200
    return doc


def go(adm, **changes):
    edit_draft(adm, **changes)
    assert adm.post(P + "/draft/validate").status_code == 200
    return adm.post(P + "/draft/dry-run")


def disp_id(aid):
    with engine.connect() as c:
        return c.execute(text("SELECT display_id FROM assessments WHERE id=:i"), {"i": aid}).scalar()


def a_state(aid):
    with engine.connect() as c:
        return c.execute(text("SELECT status, validation FROM assessments WHERE id=:i"), {"i": aid}).one()


def test_dry_run_requires_validation_and_lists_changes(adm, monkeypatch):
    dns(monkeypatch)
    a, _ = validated_assessment("approval", "awaiting-approval")
    g, _ = validated_assessment("approval", "awaiting-approval", host="gone.example.com")
    edit_draft(adm, rules=[rule(5, match="domain", value="app.example.com")])
    assert adm.post(P + "/draft/dry-run").status_code == 409
    adm.post(P + "/draft/validate")
    real = httpx.Client.send

    def send(self, req, **kw):  # the test client itself uses httpx; anything else is outbound HTTP
        assert req.url.host == "testserver", req.url
        return real(self, req, **kw)
    monkeypatch.setattr(httpx.Client, "send", send)
    r = adm.post(P + "/draft/dry-run")
    assert r.status_code == 200 and r.json()["stage"] == "dry-run"
    rows = {x["assessment"]: x for x in r.json()["dry_run"]["rows"]}
    x = rows[disp_id(a)]
    assert (x["published"], x["draft"], x["changed"], x["reset"]) == ("approval", "blocked", True, True)
    y = rows[disp_id(g)]
    assert y["draft"] == "unresolved" and not y["reset"]


def test_publish_requires_current_dry_run(adm, monkeypatch):
    dns(monkeypatch)
    doc = go(adm, no_match="allow").json()["document"]
    assert adm.put(P + "/draft", json={"document": {**doc, "no_match": "deny"}, "note": "", "rev": 1}).status_code == 200
    r = adm.post(P + "/draft/publish", json={"rev": 2})
    assert r.status_code == 409 and r.json()["detail"] == "Run a dry run of the current draft first."


def test_publish_resets_stricter_and_cancels_queued_only(adm, monkeypatch):
    dns(monkeypatch)
    aid, uid = validated_assessment("allowed")
    q, run = add_job(aid, uid), add_job(aid, uid, state="running")
    d = go(adm, rules=[rule(5, match="domain", value="app.example.com")]).json()
    assert d["dry_run"]["resets"] == 1
    r = adm.post(P + "/draft/publish", json={"rev": 1})
    assert r.status_code == 200 and r.json() == {"version": "v2", "changed": 1, "reset": 1, "jobs_cancelled": 1}
    st, val = a_state(aid)
    assert st == "draft" and val is None
    with engine.connect() as c:
        states = dict(c.execute(text("SELECT id, state FROM jobs WHERE assessment_id=:i"), {"i": aid}).all())
        v = dict(c.execute(text("SELECT version, status FROM policy_versions")).all())
        pub = c.execute(text("SELECT published_at FROM policy_versions WHERE version='v2'")).scalar()
    assert states[q] == "cancelled" and states[run] == "running" and v == {"v1": "superseded", "v2": "published"} and pub
    acts = {e["action"] for e in adm.get("/api/admin/audit?area=policy").json()}
    assert {"dry-run", "publish"} <= acts
    assert "policy-reset" in {e["action"] for e in adm.get("/api/admin/audit?area=validation").json()}


def test_publish_keeps_approved_when_not_stricter(adm, monkeypatch):
    dns(monkeypatch)
    aid, _ = validated_assessment("approval", "active", approval='{"state":"approved","note":"ok","by":"x","at":null,"self":false}')
    go(adm, rules=[rule(5, match="domain", value="other.example.com")])
    assert adm.post(P + "/draft/publish", json={"rev": 1}).json()["reset"] == 0
    assert a_state(aid)[0] == "active"


def test_looser_outcome_untouched(adm, monkeypatch):
    dns(monkeypatch)
    aid, _ = validated_assessment("approval", "awaiting-approval")
    r = go(adm, rules=[rule(5, outcome="allow", match="domain", value="app.example.com")]).json()
    x = r["dry_run"]["rows"][0]
    assert x["draft"] == "allowed" and x["changed"] and not x["reset"]
    assert adm.post(P + "/draft/publish", json={"rev": 1}).json()["reset"] == 0
    assert a_state(aid)[0] == "awaiting-approval"


def test_versions_and_rollback(adm, monkeypatch):
    dns(monkeypatch)
    go(adm, no_match="allow")
    adm.post(P + "/draft/publish", json={"rev": 1})
    vs = adm.get(P + "/versions").json()
    assert [(v["version"], v["status"]) for v in vs] == [("v2", "published"), ("v1", "superseded")]
    assert all("document" not in v and "used_by" in v for v in vs)
    assert adm.get(P + "/versions/v1").json()["document"]["no_match"] == "approval"
    assert adm.get(P + "/versions/v9").status_code == 404
    assert adm.post(P + "/versions/v2/rollback", json={"reason": "x"}).status_code == 409
    assert adm.post(P + "/versions/v1/rollback", json={"reason": "  "}).status_code == 422
    adm.post(P + "/draft", json={})
    assert adm.get(P + "/versions/v3").status_code == 404
    assert adm.post(P + "/versions/v1/rollback", json={"reason": "bad"}).json()["detail"] == "Discard or publish the open draft first."
    adm.delete(P + "/draft")
    r = adm.post(P + "/versions/v1/rollback", json={"reason": "bad"})
    assert r.status_code == 200 and r.json()["version"] == "v3"
    top = adm.get(P).json()["published"]
    assert top["version"] == "v3" and top["note"] == "Rollback to v1: bad" and top["document"]["no_match"] == "approval"


def test_validate_racing_publish_is_refused(monkeypatch):
    o = signin(make_user())
    aid = o.post("/api/assessments", json=BODY).json()["id"]
    from app.api import assessments

    def racing(*a, **k):
        with SessionLocal() as db:
            policies.apply_publish(db, {"no_match": "deny", "permitted_ports": [443], "rules": []}, "v2", "t", "race")
        return {"outcome": "allowed", "checks": []}
    monkeypatch.setattr(assessments, "validate_target", racing)
    r = o.post(f"/api/assessments/{aid}/validate")
    assert r.status_code == 409 and r.json()["detail"] == "The target policy changed while validating. Validate again."


def test_dns_failure_under_deny_rule_resets(adm, monkeypatch):
    dns(monkeypatch)
    aid, uid = validated_assessment("allowed", host="gone.example.com")
    q = add_job(aid, uid)
    d = go(adm, rules=[rule(5, outcome="deny", match="suffix", value="example.com")]).json()
    x = d["dry_run"]["rows"][0]
    assert (x["draft"], x["changed"], x["reset"]) == ("blocked", True, True)
    assert adm.post(P + "/draft/publish", json={"rev": 1}).json()["jobs_cancelled"] == 1
    assert a_state(aid)[0] == "draft"
    with engine.connect() as c:
        assert c.execute(text("SELECT state FROM jobs WHERE id=:i"), {"i": q}).scalar() == "cancelled"


def test_domain_values_are_canonicalised(adm, monkeypatch):
    dns(monkeypatch)
    validated_assessment("allowed")
    d = go(adm, rules=[rule(5, outcome="deny", match="suffix", value="Example.COM."),
                       rule(6, outcome="deny", match="domain", value="bücher.de")]).json()
    assert [r["value"] for r in d["document"]["rules"]] == ["example.com", "xn--bcher-kva.de"]
    assert d["dry_run"]["rows"][0]["draft"] == "blocked"


def test_import_deep_json_is_422(adm):
    adm.post(P + "/draft", json={})
    assert adm.post(P + "/draft/import", json={"text": "[" * 200000, "rev": 0}).status_code == 422


def test_publish_stale_rev_is_409(adm, monkeypatch):
    dns(monkeypatch)
    go(adm, no_match="allow")
    assert adm.post(P + "/draft/publish", json={"rev": 0}).status_code == 409


def test_rollback_refuses_failing_document_and_resets_stricter(adm, monkeypatch):
    dns(monkeypatch)
    bad = {"no_match": "approval", "permitted_ports": [], "rules": []}
    with engine.begin() as c:
        c.execute(text("INSERT INTO policy_versions(version, rules, status, note, created_by, rev) "
                       "VALUES ('v0', CAST(:r AS jsonb), 'superseded', '', 'x', 0)"), {"r": json.dumps(bad)})
    r = adm.post(P + "/versions/v0/rollback", json={"reason": "x"})
    assert r.status_code == 422 and r.json()["errors"]
    go(adm, rules=[rule(5, outcome="deny", match="domain", value="app.example.com")])
    adm.post(P + "/draft/publish", json={"rev": 1})  # v2 denies the target
    assert adm.post(P + "/versions/v1/rollback", json={"reason": "loosen"}).status_code == 200
    aid, uid = validated_assessment("allowed")
    q = add_job(aid, uid)
    assert adm.post(P + "/versions/v2/rollback", json={"reason": "tighten"}).status_code == 200
    assert a_state(aid)[0] == "draft"
    with engine.connect() as c:
        assert c.execute(text("SELECT state FROM jobs WHERE id=:i"), {"i": q}).scalar() == "cancelled"
