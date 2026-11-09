import http.server
import json
import re
import socket
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.engine import stages
from app.engine.zap import EngineDown, EngineError, Zap, alert_to_draft
from app.worker import main as wm
from app.worker.modules.base import ModuleResult
from test_scheduler import add_job, claim, make_assessment, sched, workers  # noqa: F401
from test_worker import public, run, snapshot

JOB, ASSESSMENT = SimpleNamespace(display_id="JOB-1"), SimpleNamespace(exclusions="/admin/*, /billing")
SCOPE = {"hosts": {"app.example.com"}, "ports": {443}, "internal": {}}


class Fake(http.server.ThreadingHTTPServer):
    """One local server standing in for both ZAP and the egress control API; records every request."""
    def __init__(self, replies=None):
        self.calls, self.replies = [], replies or {}

        class H(http.server.BaseHTTPRequestHandler):
            def handle_any(h):
                u = urlsplit(h.path)
                body = h.rfile.read(int(h.headers.get("Content-Length") or 0)).decode()
                self.calls.append((h.command, u.path, {**parse_qs(u.query), **parse_qs(body)}))
                code, out = self.replies.get(u.path, (200, {}))
                out = json.dumps(out(self) if callable(out) else out).encode()
                h.send_response(204 if u.path == "/scope" else code)
                h.send_header("Content-Length", "0" if u.path == "/scope" else str(len(out)))
                h.end_headers()
                if u.path != "/scope":
                    h.wfile.write(out)
            do_GET = do_POST = do_PUT = do_DELETE = handle_any

            def log_message(h, *a):
                pass
        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def paths(self):
        return [(m, p) for m, p, _ in self.calls]


def test_engine_session_always_clears_scope_on_error():
    f = Fake()
    zap = Zap(f.url, "k", poll=0.01)
    with pytest.raises(RuntimeError):
        with stages.EngineSession(JOB, ASSESSMENT, SCOPE, zap=zap, egress_url=f.url, token="t"):
            raise RuntimeError("boom")
    p = f.paths()
    assert p[0] == ("PUT", "/scope") and p[-1] == ("DELETE", "/scope")
    assert p.count(("POST", "/JSON/core/action/newSession/")) == 2  # wiped on entry and exit
    f.shutdown()


def test_engine_session_clears_scope_when_zap_is_down():
    f = Fake()
    with pytest.raises(EngineDown):
        with stages.EngineSession(JOB, ASSESSMENT, SCOPE, zap=Zap("http://127.0.0.1:1", "k"), egress_url=f.url, token="t"):
            pytest.fail("must not enter")
    assert f.paths() == [("PUT", "/scope"), ("DELETE", "/scope")]
    f.shutdown()


def test_exclusions_cover_never_list_assessment_and_login():
    ex = stages.excluded_regexes(ASSESSMENT, ["https://app.example.com/login"])
    hit = lambda u: any(re.fullmatch(e, u) for e in ex)  # noqa: E731  ZAP full-matches
    for u in ("https://a/account/delete?id=1", "https://a/Logout", "https://a/user/password/change",
              "https://a/admin/x/y", "https://a/billing?x=1", "https://app.example.com/login?next=/"):
        assert hit(u), u
    assert not hit("https://a/products/12")


def test_alert_mapping_and_fingerprint_stable_across_ids():
    ctx = SimpleNamespace(host="app.example.com", port=443, url="https://app.example.com/")
    base = {"pluginId": "40012", "alert": "Cross Site Scripting", "risk": "High", "confidence": "High", "param": "q",
            "method": "GET", "description": "d", "solution": "s", "reference": "https://x.example/a https://x.example/b"}
    a = alert_to_draft({**base, "url": "https://app.example.com/user/12/edit?q=1"}, ctx)
    b = alert_to_draft({**base, "url": "https://app.example.com/user/99/edit?q=2", "confidence": "Medium",
                        "risk": "Informational"}, ctx)
    assert a.fingerprint_key == b.fingerprint_key == "zap:40012:/user/{id}/edit:q"
    assert (a.severity, a.confidence) == ("high", "confirmed") and (b.severity, b.confidence) == ("info", "suspected")
    assert a.references == ["https://x.example/a", "https://x.example/b"]
    c = alert_to_draft({**base, "url": "https://app.example.com/o/3f2b8c1e-1111-2222-3333-444455556666/x"}, ctx)
    assert c.fingerprint_key == "zap:40012:/o/{id}/x:q"


def test_budget_rollover():
    now = [1000.0]
    b = stages.Budget(100, ["crawl", "dast", "api", "access"], clock=lambda: now[0])
    assert b.start("crawl") == 1030
    now[0] += 10  # crawl used 10 of 30 seconds
    b.end("crawl")
    assert b.start("dast") == now[0] + 70 / 2  # active stage = 50 + 20 rolled over, shared by dast and api
    now[0] += 5
    b.end("dast")
    assert b.start("api") == now[0] + 65  # dast's leftover goes to api, which gets the rest
    now[0] += 65
    b.end("api")
    assert b.start("access") == now[0] + 20


def test_budget_skipped_stage_rolls_forward():
    now = [0.0]
    b = stages.Budget(100, ["dast"], clock=lambda: now[0])  # no crawl scheduled: its 30s reach the active stage
    assert b.start("dast") == 80
    now[0] = 80
    b.end("dast")
    assert b.start("access") == 100


def test_active_scan_deadline_returns_partial_and_counts_untested(sched, monkeypatch):  # noqa: F811
    f = Fake({"/JSON/ascan/action/scan/": (200, {"scan": "7"}), "/JSON/ascan/view/status/": (200, {"status": "40"}),
              "/JSON/ascan/view/scanPolicyNames/": (200, {"scanPolicyNames": []}),
              "/JSON/ascan/view/scanners/": (200, {"scanners": [{"id": "40012"}, {"id": "6"}]})})
    z = Zap(f.url, "k", poll=0.01)
    assert z.active_scan("https://app.example.com/", 1, "pa-safe", time.monotonic() + 0.1) == 40
    assert ("POST", "/JSON/ascan/action/stop/") in f.paths()
    enable = [c for c in f.calls if c[1].endswith("enableScanners/")][0][2]
    assert enable["ids"] == ["6,40012"]  # only installed allowlist ids
    f.shutdown()
    # the module's untested count is persisted
    (w,), (aid, uid) = workers(1), make_assessment()
    monkeypatch.setattr(wm, "MODULES", {"reach": lambda ctx: ModuleResult("completed-warnings", "Stopped at 40%", untested=12)})
    jid = add_job(aid, uid, modules=("reach",))
    assert claim(w) == jid
    run(jid, w)
    from app.db import SessionLocal
    from app.models import ModuleRun
    with SessionLocal() as db:
        assert db.query(ModuleRun).filter_by(job_id=jid).one().untested == 12


def test_engine_unreachable_module_unavailable(sched, monkeypatch):  # noqa: F811
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    for k, v in {"ENGINE_URL": dead, "EGRESS_CONTROL": dead, "ZAP_API_KEY": "k", "EGRESS_TOKEN": "t"}.items():
        monkeypatch.setenv(k, v)
    called = []
    monkeypatch.setattr(wm, "MODULES", {"crawl": lambda ctx: called.append(1) or ModuleResult("completed", "ok"),
                                        "reach": lambda ctx: ModuleResult("completed", "ok")})
    (w,), (aid, uid) = workers(1), make_assessment()
    jid = add_job(aid, uid, modules=("reach", "crawl"))
    assert claim(w) == jid
    run(jid, w)
    state, mods = snapshot(jid)
    assert mods["crawl"] == ("unavailable", "The scanning engine is not running.") and not called
    assert mods["reach"][0] == "completed" and state == "completed-warnings"


def test_zap_4xx_is_engine_error_not_down_and_missing_field_is_clear():
    f = Fake({"/JSON/core/view/version/": (400, {}), "/JSON/ascan/action/scan/": (200, {}),
              "/JSON/ascan/view/scanPolicyNames/": (200, {"scanPolicyNames": ["pa-safe"]}),
              "/JSON/ascan/view/scanners/": (200, {"scanners": []})})
    z = Zap(f.url, "k")
    with pytest.raises(EngineError):
        z.version()
    with pytest.raises(EngineError, match="without scan"):
        z.active_scan("https://app.example.com/", 1, "pa-safe", time.monotonic() + 1)
    f.replies["/JSON/core/view/version/"] = (503, {})
    with pytest.raises(EngineDown):
        z.version()
    f.shutdown()


def test_user_confirmed_counts_as_confirmed():
    ctx = SimpleNamespace(host="h", port=443, url="https://h/")
    assert alert_to_draft({"pluginId": "1", "risk": "Low", "confidence": "User Confirmed", "url": "https://h/x"}, ctx).confidence == "confirmed"
