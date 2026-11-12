import json

import pytest
from sqlalchemy import text

from app.db import engine
from test_assessments import BODY, fake_net
from test_auth import make_user, signin

P = "/api/admin/policies"


@pytest.fixture(autouse=True)
def restore_policy():
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
                    ("post", "/draft/validate", None)]:
        assert c.request(m, P + p, json=b).status_code == 403, (m, p)


def test_start_save_discard(adm):
    r = adm.get(P).json()
    assert r["draft"] is None and r["published"]["version"] == "v1" and r["invariants"]
    d = adm.post(P + "/draft", json={})
    assert d.status_code == 201
    d = d.json()
    assert (d["version"], d["stage"], d["document"], d["note"]) == ("v2", "draft", r["published"]["document"], "")
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
