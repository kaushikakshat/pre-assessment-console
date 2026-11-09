import time
from types import SimpleNamespace

from app.engine.zap import Zap
from app.worker.modules import MODULES, api, crawl, dast
from test_engine import Fake

ALERT = {"id": "1", "pluginId": "40012", "alert": "XSS", "risk": "High", "confidence": "High", "url": "http://t.test/a?q=1",
         "param": "q", "method": "GET"}
MSGS = [{"requestHeader": "GET http://t.test/a HTTP/1.1\r\nHost: t.test", "requestBody": ""},
        {"requestHeader": "POST http://t.test/transfer HTTP/1.1\r\nHost: t.test", "requestBody": "to=bob&amount=5"}]


def replies(**over):
    r = {"/JSON/context/action/newContext/": (200, {"contextId": "1"}),
         "/JSON/replacer/view/rules/": (200, {"rules": []}),
         "/JSON/spider/action/scan/": (200, {"scan": "0"}),
         "/JSON/spider/view/status/": (200, {"status": "100"}),
         "/JSON/spider/view/results/": (200, {"results": ["http://t.test/", "http://t.test/a", "http://evil.test/x"]}),
         "/JSON/spider/view/fullResults/": (200, {"fullResults": [{"urlsOutOfScope": ["http://cdn.test/y"]}]}),
         "/JSON/core/view/numberOfMessages/": (200, {"numberOfMessages": "0"}),
         "/JSON/core/view/messages/": (200, {"messages": MSGS}),
         "/JSON/ascan/view/scanPolicyNames/": (200, {"scanPolicyNames": ["pa-safe", "pa-deep"]}),
         "/JSON/ascan/view/scanners/": (200, {"scanners": []}),
         "/JSON/ascan/action/scan/": (200, {"scan": "5"}),
         "/JSON/ascan/view/status/": (200, {"status": "100"}),
         "/JSON/core/view/alerts/": (200, {"alerts": [ALERT]})}
    return {**r, **over}


def mk(f, profile="pre", notes="", sessions=None, **rc):
    zap = Zap(f.url, "k", poll=0.01)
    run_ctx = {"zap": zap, "profile": profile, "notes": notes, "exclude": [], **({"sessions": sessions} if sessions else {}), **rc}
    return SimpleNamespace(url="http://t.test/", scheme="http", host="t.test", port=80, permitted_ports={80},
                           run_ctx=run_ctx, deadline=time.monotonic() + 60, remaining=lambda: 60,
                           resolver=None, guard=None)


def test_registered():
    assert {"crawl", "dast", "api"} <= set(MODULES)


def test_crawl_per_account_records_pages():
    f = Fake(replies())
    ctx = mk(f, sessions={"C-0001": "sid=abc"})
    r = crawl.run(ctx)
    pages, reqs = ctx.run_ctx["pages"], ctx.run_ctx["requests"]
    assert set(pages) == {None, "C-0001"} and pages[None] == {"http://t.test/", "http://t.test/a"}
    assert reqs["C-0001"] == [("POST", "http://t.test/transfer", {"to": "bob", "amount": "5"})]
    assert r.state == "completed" and r.findings == [] and r.untested == 2  # evil.test and cdn.test
    assert r.detail == "2 pages found; 2 links to other hosts not tested"
    cookie_sets = [c for c in f.calls if c[1] == "/JSON/replacer/action/addRule/"]
    assert len(cookie_sets) == 1 and cookie_sets[0][2]["replacement"] == ["sid=abc"]
    f.shutdown()


def test_dast_maps_alerts_with_credential():
    f = Fake(replies())
    ctx = mk(f, profile="deep", sessions={"C-0001": "sid=abc"}, pages={None: {"u1"}, "C-0001": {"u1", "u2"}})
    r = dast.run(ctx)
    assert r.state == "completed" and len(r.findings) == 1  # the same alert is not reported twice
    assert r.findings[0].credential_id is None
    scans = [c[2] for c in f.calls if c[1] == "/JSON/ascan/action/scan/"]
    assert len(scans) == 2 and scans[0]["scanPolicyName"] == ["pa-deep"]
    f.shutdown()


def test_dast_credential_alert_tagged():
    f = Fake(replies())
    ctx = mk(f, sessions={"C-0001": "sid=abc"}, seen_alerts={("x",)})
    ctx.run_ctx["sessions"] = {"C-0001": "sid=abc"}
    f.replies["/JSON/core/view/alerts/"] = (200, lambda s: {"alerts": [{**ALERT, "id": str(len(s.calls))}]})
    r = dast.run(ctx)
    assert [d.credential_id for d in r.findings] == [None, "C-0001"]
    assert r.findings[1].fingerprint_key.endswith(":C-0001")
    f.shutdown()


def test_dast_deadline_completed_warnings_not_completed():
    f = Fake(replies(**{"/JSON/ascan/view/status/": (200, {"status": "40"})}))
    ctx = mk(f, pages={None: {f"u{i}" for i in range(10)}})
    ctx.remaining = lambda: 0.05
    r = dast.run(ctx)
    assert r.state == "completed-warnings" and r.untested == 6
    assert r.detail == "Stopped at the time limit; 6 URLs not tested"
    f.shutdown()


def test_api_no_spec_skipped():
    f = Fake(replies(**{"/JSON/openapi/action/importUrl/": (400, {"code": "url_not_found"})}))
    r = api.run(mk(f, profile="deep"))
    assert (r.state, r.detail) == ("skipped", "No API description found")
    assert [c[2]["url"][0] for c in f.calls if c[1] == "/JSON/openapi/action/importUrl/"] == [
        f"http://t.test{p}" for p in api.COMMON]
    assert api.run(mk(f, profile="pre")).state == "skipped"
    f.shutdown()


def test_api_spec_out_of_scope_ignored():
    f = Fake(replies(**{"/JSON/openapi/action/importUrl/": (200, {"importUrl": ["a", "b"]})}))
    r = api.run(mk(f, profile="deep", notes="x\nopenapi: http://evil.test/spec.json\n"))
    urls = [c[2]["url"][0] for c in f.calls if c[1] == "/JSON/openapi/action/importUrl/"]
    assert urls == ["http://t.test/openapi.json"] and r.state == "completed"
    f = Fake(replies(**{"/JSON/openapi/action/importUrl/": (200, {"importUrl": ["a"]})}))
    api.run(mk(f, profile="deep", notes="openapi: http://t.test/docs/spec.yaml"))
    assert [c[2]["url"] for c in f.calls if c[1] == "/JSON/openapi/action/importUrl/"] == [["http://t.test/docs/spec.yaml"]]
