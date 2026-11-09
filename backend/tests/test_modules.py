import http.server
import ssl
import subprocess
import threading

import pytest

from app.targets.safe_http import BlockedAddress, SafeClient
from app.worker.modules import exposed, finger, headers, ports, reach, tls
from app.worker.modules.base import Blocked, Ctx

allow_all = lambda ip, allow_private: None  # noqa: E731  test-only guard override
local = lambda host, port, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))]  # noqa: E731


def handler(routes):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, hdrs, body = routes.get(self.path, (404, [], b"not found"))
            self.send_response_only(status)  # no default Server header
            for k, v in hdrs:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return H


@pytest.fixture
def serve():
    servers = []

    def start(routes, tls_pair=None):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler(routes))
        if tls_pair:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c.load_cert_chain(*tls_pair)
            s.socket = c.wrap_socket(s.socket, server_side=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return s.server_port
    yield start
    for s in servers:
        s.shutdown()


def make_ctx(port, scheme="http", **kw):
    import time
    client = SafeClient({"app.test"}, resolver=local, guard=allow_all, max_requests=50)
    return Ctx(url=f"{scheme}://app.test:{port}/", scheme=scheme, host="app.test", port=port, permitted_ports={port},
               client=client, deadline=time.monotonic() + 30, resolver=local, guard=allow_all, **kw)


WEAK = {"/": (200, [("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/7.4.3"), ("Set-Cookie", "sessionid=abc123; Path=/"),
                    ("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Lax")],
              b'<html><meta name="generator" content="WordPress 5.8"></html>'),
        "/.env": (200, [], b"DB_PASSWORD=hunter2\nAPI_KEY=sk_test_123\nPLAIN=value\n"),
        "/.git/HEAD": (200, [], b"ref: refs/heads/main\n"),
        "/phpinfo.php": (200, [], b"<html>soft 404 page</html>"),
        "/.DS_Store": (200, [], b"\x00\x00\x00\x01Bud1xxxx"),
        "/backup.sql": (200, [], b"CREATE TABLE users (email text);\nINSERT ...")}


def test_headers_module(serve):
    ctx = make_ctx(serve(WEAK))
    r = headers.run(ctx)
    titles = {f.title: f for f in r.findings}
    assert r.state == "completed"
    assert "Content-Security-Policy header is missing" in titles and "Strict-Transport-Security header is missing" not in titles  # http
    assert titles["Referrer-Policy header is missing"].severity == "info"
    cookies = [f for f in r.findings if f.location["kind"] == "Cookie"]
    assert [f.title for f in cookies] == ["Cookie sessionid is missing security flags"]  # one per offending cookie
    assert cookies[0].severity == "medium" and "abc123" not in cookies[0].evidence
    assert all(f.confidence == "confirmed" for f in r.findings)


def test_headers_secure_site_has_no_findings(serve):
    good = [("Strict-Transport-Security", "max-age=1"), ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]
    assert headers.run(make_ctx(serve({"/": (200, good, b"")}))).findings == []


def test_exposed_module_signatures_and_redaction(serve):
    r = exposed.run(make_ctx(serve(WEAK)))
    by = {f.location["path"]: f for f in r.findings}
    assert set(by) == {"/.env", "/.git/HEAD", "/.DS_Store", "/backup.sql", "/.well-known/security.txt"}  # phpinfo soft-404 ignored
    assert by["/.env"].severity == "high" and by["/.git/HEAD"].severity == "high" and by["/backup.sql"].severity == "high"
    assert "hunter2" not in by["/.env"].evidence and "PLAIN=value" not in by["/.env"].evidence
    assert "CREATE TABLE" not in by["/backup.sql"].evidence and "ref: refs/heads/main" in by["/.git/HEAD"].evidence
    assert by["/.well-known/security.txt"].severity == "info" and r.state == "completed"
    ok = exposed.run(make_ctx(serve({"/.well-known/security.txt": (200, [], b"Contact: mailto:a@b.c")})))
    assert ok.findings == []


def test_finger_module(serve):
    r = finger.run(make_ctx(serve(WEAK)))
    got = {f.title: f.confidence for f in r.findings}
    assert got == {"Software version disclosed: nginx/1.18.0": "confirmed", "Software version disclosed: PHP/7.4.3": "confirmed",
                   "Software version disclosed: WordPress 5.8": "confirmed"}
    r = finger.run(make_ctx(serve({"/": (200, [("Server", "nginx")], b"")})))
    assert [(f.title, f.confidence) for f in r.findings] == [("Software version disclosed: nginx", "suspected")]


def test_rate_limit_and_waf_detection(serve):
    with pytest.raises(Blocked):
        reach.run(make_ctx(serve({"/": (429, [], b"")})))
    with pytest.raises(Blocked):
        headers.run(make_ctx(serve({"/": (403, [("Server", "cloudflare")], b"")})))
    assert reach.run(make_ctx(serve({"/": (403, [], b"forbidden")}))).state == "completed"  # plain 403 is not a WAF


def test_reach_records_status(serve):
    r = reach.run(make_ctx(serve({"/": (200, [], b"hi")})))
    assert r.state == "completed" and "HTTP 200" in r.detail


NMAP_XML = """<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93"><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port></ports></host></nmaprun>"""


def test_ports_module_stubbed_nmap(monkeypatch):
    seen = {}

    def fake(cmd, **kw):
        seen.update(cmd=cmd, kw=kw)
        return subprocess.CompletedProcess(cmd, 0, NMAP_XML, "")
    monkeypatch.setattr(ports.subprocess, "run", fake)
    ctx = make_ctx(443, "https")
    r = ports.run(ctx)
    assert seen["cmd"] == ["nmap", "-sT", "-Pn", "-n", "--top-ports", "100", "--host-timeout", "150s", "-oX", "-", "127.0.0.1"]
    assert not seen["kw"].get("shell") and r.tool_version == "7.93" and r.state == "completed"
    assert [f.title for f in r.findings] == ["Unexpected open port 3306/mysql"] and r.findings[0].severity == "low"
    monkeypatch.setattr(ports.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "<nmaprun", ""))
    assert ports.run(ctx).state == "failed"
    monkeypatch.setattr(ports.subprocess, "run", lambda cmd, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd, 1)))
    assert ports.run(ctx).state == "inconclusive"


def test_ports_and_tls_refuse_unsafe_addresses(monkeypatch):
    monkeypatch.setattr(ports.subprocess, "run", lambda *a, **k: pytest.fail("nmap must not run"))
    ctx = make_ctx(443, "https")
    ctx.guard = __import__("app.targets.safe_http", fromlist=["default_guard"]).default_guard  # production guard
    for mod in (ports, tls):
        with pytest.raises(BlockedAddress):
            mod.run(ctx)


def test_tls_http_target_is_skipped_with_finding():
    r = tls.run(make_ctx(80))
    assert r.state == "skipped" and r.detail == "Target uses http; TLS not tested"
    assert [(f.severity, f.confidence, f.title) for f in r.findings] == [("medium", "confirmed", "Site is served without HTTPS")]


@pytest.fixture
def cert(tmp_path):
    def make(name):
        k, c = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c, "-days", "1",
                        "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"], check=True, capture_output=True)
        return str(c), str(k)
    return make


def test_tls_self_signed_and_hostname_mismatch(serve, cert, monkeypatch):
    own = cert("app.test")
    port = serve({}, own)
    r = tls.run(make_ctx(port, "https"))  # not in the system trust store
    assert [f.title for f in r.findings if f.severity == "medium"][:1] == ["Certificate is self-signed or not trusted"]
    assert r.state == "completed"
    other = cert("other.test")
    port = serve({}, other)
    monkeypatch.setenv("SSL_CERT_FILE", other[0])  # trusted, but issued for another name
    r = tls.run(make_ctx(port, "https"))
    assert [(f.severity, f.title) for f in r.findings][:1] == [("high", "Certificate does not match the site name")]
    port = serve({}, own)
    monkeypatch.setenv("SSL_CERT_FILE", own[0])  # trusted and matching, 1 day validity -> expires soon
    r = tls.run(make_ctx(port, "https"))
    assert [(f.severity, f.title) for f in r.findings][:1] == [("low", "Certificate expires soon")]


def test_exposed_keeps_findings_when_blocked_midway(serve):
    routes = {"/.env": (200, [], b"A=b\n"), "/.git/HEAD": (200, [], b"ref: x"), "/server-status": (429, [], b"")}
    r = exposed.run(make_ctx(serve(routes)))
    assert r.state == "inconclusive" and r.detail == "Target rate-limited or blocked the requests"
    assert {f.location["path"] for f in r.findings} == {"/.env", "/.git/HEAD"}


def test_tls_outdated_protocol_check_cannot_run_or_refused(serve, cert, monkeypatch):
    port = serve({}, cert("app.test"))
    monkeypatch.setattr(tls, "_can_offer", lambda c: False)
    r = tls.run(make_ctx(port, "https"))
    assert r.state == "completed-warnings" and r.detail == "Outdated protocol check could not run"
    assert any("self-signed" in f.title for f in r.findings)  # other TLS checks still reported
    real = tls._lenient
    monkeypatch.setattr(tls, "_lenient", lambda only=None: (_ for _ in ()).throw(ValueError("unsupported")) if only else real())
    assert tls.run(make_ctx(port, "https")).state == "completed-warnings"  # no crash
    monkeypatch.setattr(tls, "_lenient", real)
    monkeypatch.setattr(tls, "_can_offer", lambda c: True)  # offered, server (TLS 1.2+) refuses -> not accepted
    r = tls.run(make_ctx(port, "https"))
    assert r.state == "completed" and not any("outdated" in f.title for f in r.findings)
