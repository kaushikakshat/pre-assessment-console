import http.server
import json
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import unquote_plus

import pytest

from app.worker import advisories
from app.worker.modules import cms, config, exposed, tls, wordlists
from app.worker.modules.base import Blocked
from test_modules import cert, local, make_ctx, serve  # noqa: F401  (serve is a fixture)

HTML = {"content-type": "text/html"}


def page(body, extra=()):
    return (200, [("Content-Type", "text/html"), *extra], body)


def test_cms_wordpress_eol(serve):
    port = serve({"/": page(b'<html><meta name="generator" content="WordPress 4.6.1"></html>')})
    r = cms.run(make_ctx(port))
    assert any(d.title == "wordpress 4.6.1 is no longer supported" and d.severity == "medium" for d in r.findings)
    assert r.detail.endswith(f"Advisory data as of {advisories.AS_OF}") and r.state == "completed"


def test_cms_current_wordpress_not_eol():
    assert advisories.eol_findings("wordpress", "7.1.4") == [] and advisories.eol_findings("nothing", "1.0") == []


def test_js_library_vulnerable_jquery():
    out = advisories.js_library_findings("http://app.test/", b'<script src="/js/jquery-1.7.1.min.js"></script>'
                                                              b'<script src="/js/jquery-3.7.1.min.js"></script>')
    assert out and all("jquery 1.7.1" in d.title for d in out) and {d.severity for d in out} <= {"low", "medium", "high", "critical"}


def test_cors_reflected_with_credentials_high(serve):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        r = config.run(make_ctx(s.server_port))
    finally:
        s.shutdown()
    assert [d.severity for d in r.findings if "CORS" in d.title] == ["high"]


def test_config_directory_listing_cookie_and_trace(serve):
    port = serve({"/": page(b"<title>Index of /</title>", [("Set-Cookie", "sid=1; Path=/")])})
    ctx = make_ctx(port)
    ctx.run_ctx["pages"] = {None: {ctx.url + "a"}}
    r = config.run(ctx)
    titles = [d.title for d in r.findings]
    assert any(t.startswith("Directory listing") for t in titles) and "Cookie sid is missing security flags" in titles


def test_tls_testssl_uses_safe_ip_and_maps_medium(monkeypatch, serve):
    port = serve({"/": page(b"x")})
    ctx = make_ctx(port, "https", run_ctx={"profile": "deep"})
    seen = {}

    class FakeProc:
        pid = 0

        def __init__(self, args, **kw):
            seen["args"], seen["kw"] = args, kw
            rows = [{"id": "BEAST", "severity": "MEDIUM", "finding": "vulnerable"}, {"id": "x", "severity": "LOW", "finding": "m"},
                    {"id": "ROBOT", "severity": "HIGH", "finding": "bad", "cve": "CVE-1"}, {"id": "i", "severity": "OK", "finding": ""},
                    {"id": "BEAST", "severity": "MEDIUM", "finding": "dup"}, "junk"]
            Path(args[args.index("--jsonfile") + 1]).write_text(json.dumps(rows))

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0
    monkeypatch.setattr(tls.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(tls.shutil, "which", lambda n: "/bin/true")
    drafts, version, note = tls._testssl(ctx, ctx.safe_ip())
    a = seen["args"]
    assert a[a.index("--ip") + 1] == ctx.safe_ip() == "127.0.0.1" and a[-1] == f"app.test:{port}" and "shell" not in a
    assert a[a.index("--nodns") + 1] == "none" and seen["kw"]["start_new_session"] is True
    assert [d.severity for d in drafts] == ["medium", "high"] and note == "" and version.startswith("testssl.sh")


def test_tls_testssl_missing_is_warning(monkeypatch, serve):
    monkeypatch.setattr(tls.shutil, "which", lambda n: None)
    assert tls._testssl(make_ctx(1, "https"), "127.0.0.1")[2]


def _wl(tmp_path, monkeypatch, **files):
    for k, v in files.items():
        p = tmp_path / k.replace("__", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(v)
    monkeypatch.setattr(wordlists, "ROOT", tmp_path)


def test_wordlist_key_must_stay_in_vendored_tree(tmp_path, monkeypatch):
    _wl(tmp_path, monkeypatch, Discovery__a_txt="admin\n")
    (tmp_path / "Passwords").mkdir()
    (tmp_path / "Passwords" / "p.txt").write_text("x\n")
    for bad in ("../etc/passwd", "/etc/passwd", "Passwords/p.txt", "Discovery/../Passwords/p.txt", "Discovery/missing.txt"):
        with pytest.raises(ValueError):
            wordlists.read(bad, tmp_path)


def test_discovery_soft404_ignored(serve, tmp_path, monkeypatch):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            real = self.path == "/admin"
            self.send_response(403 if real else 200)
            body = b"Forbidden area" if real else b"<html>Sorry, this page does not exist anywhere on this site, try the menu</html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    _wl(tmp_path, monkeypatch, Discovery__a_txt="admin\nnothing\nother\n")
    try:
        ctx = make_ctx(s.server_port, run_ctx={"wordlists": ["Discovery/a_txt"], "rate_per_s": 50})
        monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["admin", "nothing", "other"])
        drafts, status, skipped = wordlists.discover(ctx, ["Discovery/a.txt"])
    finally:
        s.shutdown()
    assert [d.location["path"] for d in drafts] == ["/admin"] and status == "ok" and skipped == 0


def test_discovery_blocked_keeps_findings(monkeypatch):
    class C:
        url, host, port, deadline, run_ctx = "http://app.test/", "app.test", 80, time.monotonic() + 30, {"rate_per_s": 50}
        n = 0

        def get(self, path):
            self.n += 1
            if self.n == 3:
                raise Blocked
            return type("R", (), {"status_code": 404 if self.n == 1 else 200, "content": b"found " * 5 + path.encode(),
                                  "headers": {}})()
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["a", "b", "c"])
    drafts, status, skipped = wordlists.discover(C(), ["Discovery/x.txt"])
    assert len(drafts) == 1 and status == "blocked" and skipped == 2


class Fuzzed(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        Fuzzed.hits.append(self.path)
        body = f"<p>you searched {unquote_plus(self.path.split('q=', 1)[-1])}</p>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        Fuzzed.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def fuzzed():
    Fuzzed.hits = []
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fuzzed)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield s.server_port
    s.shutdown()


def test_fuzz_reflection_suspected_xss(fuzzed, monkeypatch):
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["<script>x</script>", "harmless"])
    ctx = make_ctx(fuzzed, run_ctx={"rate_per_s": 50, "pages": {None: {f"http://app.test:{fuzzed}/s?q=hello"}}})
    drafts, status, _ = wordlists.fuzz(ctx, ["Fuzzing/xss.txt"])
    assert [(d.severity, d.confidence, d.location["param"]) for d in drafts] == [("high", "suspected", "q")]
    assert "<script>x</script>" in drafts[0].evidence and status == "ok"


def test_fuzz_skips_login_form(fuzzed, monkeypatch):
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["<b>"])
    u = f"http://app.test:{fuzzed}"
    rc = {"rate_per_s": 50, "requests": {None: [("POST", f"{u}/login", {"user": "a", "password": "[REDACTED]"}),
                                                 ("POST", f"{u}/account/delete", {"x": "1"}),
                                                 ("POST", f"{u}/contact", {"name": "n", "token": "[REDACTED]"})]},
          "pages": {None: {f"{u}/auth/verify?code=1"}}}
    drafts, status, _ = wordlists.fuzz(make_ctx(fuzzed, run_ctx=rc), ["Fuzzing/xss.txt"])
    assert Fuzzed.hits == [] and drafts == [] and status == "ok"


def test_fuzz_respects_request_cap(fuzzed, monkeypatch):
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: [f"p{i}" for i in range(100)])
    ctx = make_ctx(fuzzed, run_ctx={"rate_per_s": 1000, "pages": {None: {f"http://app.test:{fuzzed}/s?q=1"}}})
    ctx.client.max_requests = 5
    _, status, skipped = wordlists.fuzz(ctx, ["Fuzzing/x.txt"])
    assert status == "stopped" and skipped > 0 and ctx.client.count == 5


def test_exposed_runs_discovery_when_lists_selected(serve, monkeypatch):
    port = serve({"/": page(b"home"), "/secret": (200, [], b"hidden admin console with lots of unique words here")})
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["secret", "zzz"])
    ctx = make_ctx(port, run_ctx={"wordlists": ["Discovery/c.txt"], "rate_per_s": 100})
    r = exposed.run(ctx)
    assert any(d.location["path"] == "/secret" for d in r.findings)


def test_eol_uses_vendored_eol_dates():
    from datetime import date
    assert advisories.eol_findings("python", "3.8.1")[0].title == "python 3.8.1 is no longer supported"
    assert advisories.eol_findings("nodejs", "22.1.0", today=date(2026, 11, 9)) == []  # supported LTS cycle
    assert advisories.eol_findings("nodejs", "22.1.0", today=date(2030, 1, 1))  # its eol date has passed
    assert advisories.eol_findings("python", "9.9") == []  # no cycle data: say nothing


def test_retire_range_boundaries():
    a = advisories.affected
    assert a("4.0", {"below": "4.0.0"}) is False and a("4.0.0", {"below": "4.0"}) is False
    assert a("3.9.9", {"below": "4.0"}) and a("1.2.1", {"atOrAbove": "1.2.1", "below": "1.9"})
    assert not a("1.2.0", {"atOrAbove": "1.2.1", "below": "1.9"}) and not a("1.9", {"atOrAbove": "1.2.1", "below": "1.9.0"})
    assert a("2.0", {"atOrBelow": "2.0.0"}) and not a("2.0.1", {"atOrBelow": "2.0"})
    assert not a("1.0", {"atOrAbove": "0.5"})  # no upper bound: not a range retire would flag


def test_bad_retire_regex_is_skipped(monkeypatch):
    monkeypatch.setattr(advisories, "_retire", lambda: {"broken": {"extractors": {"uri": ["(unclosed§§version§§"]}, "vulnerabilities": []}})
    assert advisories.js_library_findings("http://a/", b'<script src="/x.js"></script>') == []


def test_discovery_baseline_blocked_returns_status(monkeypatch):
    class C:
        url, host, port, deadline, run_ctx = "http://app.test/", "app.test", 80, time.monotonic() + 30, {}

        def get(self, path):
            raise Blocked
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["a", "b"])
    assert wordlists.discover(C(), ["Discovery/x.txt"]) == ([], "blocked", 2)


def _cms_over_tls(cert, serve, verify, monkeypatch):
    import functools

    from app.worker import main
    from app.worker.main import UNTRUSTED_CERT, execute_module
    monkeypatch.setattr(main, "SafeClient", functools.partial(main.SafeClient, guard=lambda ip, allow: None))  # loopback test server
    port = serve({"/": page(b"<html>hi</html>")}, cert("app.test"))
    args = {"url": f"https://app.test:{port}/", "scheme": "https", "host": "app.test", "port": port, "permitted_ports": {port},
            "resolver": local, "internal": None, "internal_hosts": {"app.test": None}, "verify": verify}
    return execute_module("cms", args, 20, None, {}), UNTRUSTED_CERT


def test_untrusted_cert_flag_off_gives_clear_detail(cert, serve, monkeypatch):
    (state, detail, *_), msg = _cms_over_tls(cert, serve, True, monkeypatch)
    assert state == "failed" and detail == msg and "Allow untrusted certificate" in msg


def test_untrusted_cert_flag_on_runs_pinned(cert, serve, monkeypatch):
    (state, detail, *_), _ = _cms_over_tls(cert, serve, False, monkeypatch)
    assert state == "completed", detail


def test_testssl_groups_dedupes_and_caps_severity(monkeypatch, serve):
    port = serve({"/": page(b"x")})
    ctx = make_ctx(port, "https", run_ctx={"profile": "deep"})
    rows = [{"id": "overall_grade", "severity": "CRITICAL", "finding": "T"}, {"id": "scanTime", "severity": "MEDIUM", "finding": "1"},
            {"id": "cert_trust", "severity": "HIGH", "finding": "self"}, {"id": "TLS1", "severity": "MEDIUM", "finding": "offered"},
            {"id": "cipher-tls1_xc018", "severity": "CRITICAL", "finding": "a"}, {"id": "cipher-tls1_2_xc019", "severity": "HIGH", "finding": "b"},
            {"id": "cipherlist_aNULL", "severity": "CRITICAL", "finding": "c"}, {"id": "BEAST", "severity": "MEDIUM", "finding": "d"}]

    class P:
        pid = 0

        def __init__(self, args, **kw):
            Path(args[args.index("--jsonfile") + 1]).write_text(json.dumps(rows))

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0
    monkeypatch.setattr(tls.subprocess, "Popen", P)
    monkeypatch.setattr(tls.shutil, "which", lambda n: "/bin/true")
    drafts, _, _ = tls._testssl(ctx, "127.0.0.1")
    got = {d.title: d for d in drafts}
    assert set(got) == {"TLS weakness: cipher", "TLS weakness: cipherlist", "TLS weakness: BEAST"}
    assert {d.severity for d in drafts} == {"high", "medium"} and "cipher-tls1_2_xc019" in got["TLS weakness: cipher"].evidence


class Seen(http.server.BaseHTTPRequestHandler):
    paths = []

    def do_GET(self):
        Seen.paths.append(self.path)
        body = b"A=b\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    log_message = lambda *a: None  # noqa: E731


@pytest.mark.parametrize("pattern", ["/.env", "/admin/*"])
def test_exposed_and_discovery_skip_excluded_urls(pattern, monkeypatch):
    from types import SimpleNamespace
    from app.engine import stages
    Seen.paths = []
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Seen)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    monkeypatch.setattr(wordlists, "read", lambda k, root=None: ["admin/x", ".env", "other"])
    rc = {"exclude": stages.excluded_regexes(SimpleNamespace(exclusions=pattern)), "wordlists": ["Discovery/c.txt"], "rate_per_s": 100}
    try:
        r = exposed.run(make_ctx(s.server_port, run_ctx=rc))
    finally:
        s.shutdown()
    prefix = pattern.rstrip("*")
    assert Seen.paths and not any(p.startswith(prefix) for p in Seen.paths)
    assert not any(f.location["path"].startswith(prefix) for f in r.findings)


def test_config_failed_fetch_ends_with_warnings(serve):
    ctx = make_ctx(serve({"/": page(b"ok")}))
    ctx.run_ctx["pages"] = {None: {ctx.url + "a"}}
    real = ctx.client.request
    ctx.client.request = lambda m, u, **kw: (_ for _ in ()).throw(ConnectionError("boom")) if u.endswith("/a") else real(m, u, **kw)
    r = config.run(ctx)
    assert r.state == "completed-warnings" and "1 page request(s) failed" in r.detail


def test_cms_failed_fetch_ends_with_warnings(serve):
    ctx = make_ctx(serve({"/": page(b"<html></html>")}))
    real = ctx.get
    ctx.get = lambda path=None: (_ for _ in ()).throw(ConnectionError("boom")) if path == "/readme.html" else real(path)
    r = cms.run(ctx)
    assert r.state == "completed-warnings" and "failed" in r.detail


def test_tls_old_protocol_timeout_is_not_refused(serve, cert, monkeypatch):
    port = serve({}, cert("app.test"))
    monkeypatch.setattr(tls, "_can_offer", lambda c: True)
    real = tls._connect

    def connect(ctx, ip, c):
        if c.maximum_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            raise TimeoutError("timed out")
        return real(ctx, ip, c)
    monkeypatch.setattr(tls, "_connect", connect)
    r = tls.run(make_ctx(port, "https"))
    assert r.state == "completed-warnings" and "probe(s) failed" in r.detail
