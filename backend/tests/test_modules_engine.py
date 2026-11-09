import time
from types import SimpleNamespace

from app.engine.zap import Zap
from app.worker.modules import MODULES, api, crawl, dast
from test_engine import Fake

ALERT = {"id": "1", "pluginId": "40012", "alert": "XSS", "risk": "High", "confidence": "High", "url": "http://t.test/a?q=1",
         "param": "q", "method": "GET"}
MSGS = [{"requestHeader": "GET http://t.test/a HTTP/1.1\r\nHost: t.test", "requestBody": ""},
        {"requestHeader": "POST http://t.test/transfer HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded", "requestBody": "to=bob&amount=5"}]


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


def test_passive_alerts_from_account_crawl_tagged_to_that_account():
    f = Fake(replies())
    ctx = mk(f, sessions={"C-0001": "sid=abc12345"})
    n = {"i": 0}

    def alerts(srv):  # crawl as anonymous: none; crawl as C-0001: id 7 appears; dast scans add id 8 (anonymous pass)
        n["i"] += 1
        return {"alerts": [{**ALERT, "id": i, "url": f"http://t.test/{i}"} for i in (["7"] if n["i"] == 2 else ["7", "8"] if n["i"] == 3 else ["7", "8"] if n["i"] == 4 else [])]}
    f.replies["/JSON/core/view/alerts/"] = (200, alerts)
    crawl.run(ctx)
    r = dast.run(ctx)
    assert sorted(d.credential_id or "" for d in r.findings) == ["", "C-0001"]
    assert [d.credential_id for d in r.findings if d.location["url"].endswith("/7")] == ["C-0001"]
    f.shutdown()


def _two_account_failure(exc_kind):
    import pytest
    from app.engine.zap import EngineDown, EngineError
    f = Fake(replies(**{"/JSON/replacer/view/rules/": (500, {})} if exc_kind == "cleanup" else {}))
    ctx = mk(f, sessions={"C-0001": "sid=abc12345"})
    real, n = ctx.run_ctx["zap"].spider, [0]

    def spider(*a):
        n[0] += 1
        if n[0] == 2:
            raise EngineDown("x") if exc_kind == "down" else EngineError("y")
        return real(*a)
    ctx.run_ctx["zap"].spider = spider
    return f, ctx, (EngineDown if exc_kind == "down" else EngineError)


def test_crawl_failure_clears_cookie_and_anonymous_pass_has_none():
    import pytest
    for kind in ("down", "error"):
        f, ctx, exc = _two_account_failure(kind)
        with pytest.raises(exc):
            crawl.run(ctx)
        paths = f.paths()
        first_spider = paths.index(("POST", "/JSON/spider/action/scan/"))
        assert ("POST", "/JSON/replacer/action/addRule/") not in paths[:first_spider]  # anonymous: no Cookie
        assert paths[-1] == ("GET", "/JSON/replacer/view/rules/")  # cleared last, in finally
        f.shutdown()


def test_cleanup_failure_does_not_replace_original_error():
    import pytest
    from app.engine.zap import EngineError
    f, ctx, _ = _two_account_failure("error")
    from app.engine.zap import EngineDown
    calls = []
    ctx.run_ctx["zap"].clear_headers = lambda: calls.append(1) if len(calls) < 1 else (_ for _ in ()).throw(EngineDown("x"))
    ctx.run_ctx["zap"].spider = lambda *a: (_ for _ in ()).throw(EngineError("original"))
    with pytest.raises(EngineError, match="original"):
        crawl.run(ctx)
    f.shutdown()


def test_api_other_engine_error_fails_not_skipped():
    import pytest
    from app.engine.zap import EngineError
    f = Fake(replies(**{"/JSON/openapi/action/importUrl/": (400, {"code": "internal_error"})}))
    with pytest.raises(EngineError):
        api.run(mk(f, profile="deep"))
    f.shutdown()


def test_requests_never_hold_credentials():
    msgs = [{"requestHeader": "POST http://t.test/login HTTP/1.1", "requestBody": "user=a&password=p"},
            {"requestHeader": "POST http://t.test/otp/verify HTTP/1.1", "requestBody": "code=123456"},
            {"requestHeader": "POST http://t.test/api/settings?token=zzz&x=1 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded",
             "requestBody": "name=bob&csrf_token=abc&secret=s&passcode=1&otp=2&note=hi"}]
    f = Fake(replies(**{"/JSON/core/view/messages/": (200, {"messages": msgs})}))
    ctx = mk(f)
    crawl.run(ctx)
    assert ctx.run_ctx["requests"][None] == [("POST", "http://t.test/api/settings?token=[REDACTED]&x=1", {
        "name": "bob", "csrf_token": "[REDACTED]", "secret": "[REDACTED]", "passcode": "[REDACTED]", "otp": "[REDACTED]",
        "note": "hi"})]
    f.shutdown()


def test_session_cookie_values_masked_in_alert_text():
    f = Fake(replies())
    a = {**ALERT, "id": "9", "alert": "Cookie No HttpOnly Flag", "evidence": "Set-Cookie: sid=abc12345; Path=/", "other": "token abc12345 seen"}
    f.replies["/JSON/core/view/alerts/"] = (200, {"alerts": [a]})
    ctx = mk(f, sessions={"C-0001": "sid=abc12345; theme=dark"})
    r = dast.run(ctx)
    text = " ".join(f"{d.evidence} {d.impact} {d.description} {d.reproduce}" for d in r.findings)
    assert "abc12345" not in text and "[REDACTED]" in text
    f.shutdown()


def test_request_filter_matches_path_segments_not_host_or_substrings():
    msgs = [{"requestHeader": f"POST http://{u} HTTP/1.1", "requestBody": ""} for u in
            ("auth.example.test/orders", "t.test/authors", "t.test/login", "t.test/a/Sign-In/x", "t.test/password.php")]
    f = Fake(replies(**{"/JSON/core/view/messages/": (200, {"messages": msgs})}))
    ctx = mk(f)
    crawl.run(ctx)
    assert [r[1] for r in ctx.run_ctx["requests"][None]] == ["http://auth.example.test/orders", "http://t.test/authors"]
    f.shutdown()


def test_non_urlencoded_body_not_stored():
    msgs = [{"requestHeader": "POST http://t.test/x HTTP/1.1\r\nContent-Type: application/json", "requestBody": '{"pw":"s"}'}]
    f = Fake(replies(**{"/JSON/core/view/messages/": (200, {"messages": msgs})}))
    ctx = mk(f)
    crawl.run(ctx)
    assert ctx.run_ctx["requests"][None] == [("POST", "http://t.test/x", "[REDACTED BODY]")]
    f.shutdown()


def test_cleanup_failure_on_success_raises_and_api_clears_headers():
    import pytest
    from app.engine.zap import EngineDown
    f = Fake(replies(**{"/JSON/replacer/view/rules/": (500, {})}))
    with pytest.raises(EngineDown):
        crawl.run(mk(f))
    f.shutdown()
    f = Fake(replies(**{"/JSON/openapi/action/importUrl/": (400, {"code": "bad_external_data"})}))
    api.run(mk(f, profile="deep"))
    p = f.paths()
    assert p.index(("GET", "/JSON/replacer/view/rules/")) < p.index(("POST", "/JSON/openapi/action/importUrl/"))
    f.shutdown()


def test_only_session_like_cookies_masked():
    f = Fake(replies())
    a = {**ALERT, "id": "9", "evidence": "sid=abc12345 theme=dark lang=en", "other": ""}
    f.replies["/JSON/core/view/alerts/"] = (200, {"alerts": [a]})
    r = dast.run(mk(f, sessions={"C-0001": "sid=abc12345; theme=dark; lang=en"}))
    assert "abc12345" not in r.findings[0].evidence and "theme=dark" in r.findings[0].evidence
    f.shutdown()
