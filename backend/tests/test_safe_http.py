import http.server
import ssl
import subprocess
import threading
import zlib

import httpx
import pytest

from app.targets.safe_http import BlockedAddress, RequestCapExceeded, SafeClient, ScopeError

allow_all = lambda ip, allow_private: None  # noqa: E731  test-only guard override


def resolver_to(ip):
    return lambda host, port, **kw: [(2, 1, 6, "", (ip, 0))]


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/big":
            body = b"x" * 2_000_000
        elif self.path == "/bomb":
            body = zlib.compress(b"\0" * 60_000_000)
            self.send_response(200)
            self.send_header("Content-Encoding", "deflate")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://app.test/next")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            body = ("host=" + self.headers["Host"]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(tls=None):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def test_rebinding_refused_at_connect_time():
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])  # public when validated, loopback when connecting
    r = lambda host, port, **kw: [(2, 1, 6, "", (next(answers)[0], 0))]  # noqa: E731
    from app.targets import ipguard
    assert ipguard.resolve("app.test", r) == ["93.184.216.34"]
    with SafeClient({"app.test"}, resolver=r) as c, pytest.raises(BlockedAddress):
        c.get("http://app.test:1/")


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "10.0.0.1"])
def test_default_guard_refuses(ip):
    with SafeClient({"app.test"}, resolver=resolver_to(ip)) as c, pytest.raises(BlockedAddress):
        c.get("http://app.test/")


def test_private_allowed_only_for_internal_host_but_never_loopback():
    with SafeClient({"app.test"}, internal_hosts={"app.test"}, resolver=resolver_to("127.0.0.1")) as c:
        with pytest.raises(BlockedAddress):
            c.get("http://app.test/")


def test_internal_ranges_enforced_at_connect_time():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/24")]
    r = lambda host, port, **kw: [(2, 1, 6, "", ("10.0.0.5", 0)), (2, 1, 6, "", ("10.9.9.9", 0))]  # noqa: E731
    with SafeClient({"app.test"}, internal_hosts={"app.test": nets}, resolver=r) as c, pytest.raises(BlockedAddress):
        c.get("http://app.test/")


def test_transport_integrity_assertion(monkeypatch):
    import httpcore
    from app.targets import safe_http
    monkeypatch.setattr(safe_http._Transport, "__init__",
                        lambda self, backend: httpx.HTTPTransport.__init__(self))  # unguarded pool
    with pytest.raises(RuntimeError):
        SafeClient({"app.test"})


def test_out_of_scope_raises_before_connecting():
    with SafeClient({"app.test"}, resolver=lambda *a, **k: pytest.fail("resolved")) as c:
        for u in ("http://other.test/", "ftp://app.test/", "http://127.0.0.1/"):
            with pytest.raises(ScopeError):
                c.get(u)


def test_local_server_host_header_truncate_no_redirect_cap():
    s = serve()
    try:
        port = s.server_port
        with SafeClient({"app.test"}, resolver=resolver_to("127.0.0.1"), guard=allow_all, max_requests=5) as c:
            assert c.get(f"http://app.test:{port}/").text == f"host=app.test:{port}"
            big = c.get(f"http://app.test:{port}/big")
            assert big.truncated and len(big.content) == 1_000_000
            bomb = c.get(f"http://app.test:{port}/bomb")
            assert bomb.truncated and len(bomb.content) == 1_000_000
            r = c.get(f"http://app.test:{port}/redir")
            assert r.status_code == 302 and r.headers["location"] == "http://app.test/next"
            assert c.head(f"http://app.test:{port}/").status_code in (200, 501)
            with pytest.raises(RequestCapExceeded):
                c.get(f"http://app.test:{port}/")
    finally:
        s.shutdown()


@pytest.fixture
def certs(tmp_path, monkeypatch):
    def make(name):
        k, c = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c,
                        "-days", "1", "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"],
                       check=True, capture_output=True)
        return str(c), str(k)
    return make


def test_tls_verifies_certificate_against_hostname_not_ip(certs, monkeypatch):
    good, other = certs("good.test"), certs("other.test")
    s = serve(good)
    try:
        monkeypatch.setenv("SSL_CERT_FILE", good[0])  # trust only this self-signed cert
        url = f"https://good.test:{s.server_port}/"
        with SafeClient({"good.test"}, resolver=resolver_to("127.0.0.1"), guard=allow_all) as c:
            assert c.get(url).text == f"host=good.test:{s.server_port}"  # SAN is a DNS name; connected by IP
    finally:
        s.shutdown()
    s = serve(other)  # cert for another hostname must be rejected even though the TCP target is the same
    try:
        monkeypatch.setenv("SSL_CERT_FILE", other[0])
        with SafeClient({"good.test"}, resolver=resolver_to("127.0.0.1"), guard=allow_all) as c:
            with pytest.raises(httpx.ConnectError):
                c.get(f"https://good.test:{s.server_port}/")
    finally:
        s.shutdown()
