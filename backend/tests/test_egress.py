import asyncio
import http.server
import json
import socket
import threading
import time

import pytest

from app.egress.proxy import EgressState, serve

allow_all = lambda ip, allow_private: None  # noqa: E731  test-only guard override
TOKEN = "tok"


def resolver_to(ip):
    return lambda host, port, **kw: [(2, 1, 6, "", (ip, 0))]


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"host={self.headers['Host']} path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def echo():
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield s.server_address[1]
    s.shutdown()


def start(state):
    pp, cp = free_port(), free_port()
    ready = threading.Event()

    def run():
        loop = asyncio.new_event_loop()
        loop.call_soon(ready.set)
        loop.run_until_complete(serve(("127.0.0.1", pp), ("127.0.0.1", cp), token=TOKEN, state=state))
    threading.Thread(target=run, daemon=True).start()
    ready.wait()
    for p in (pp, cp):  # wait until listening
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", p), 0.1).close()
                break
            except OSError:
                threading.Event().wait(0.05)
    return pp, cp


def raw(port, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), 5) as s:
        s.sendall(data)
        out = b""
        while chunk := s.recv(65536):
            out += chunk
        return out


def connect(pp, target):
    return raw(pp, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())


def connect_status(pp, target):
    with socket.create_connection(("127.0.0.1", pp), 5) as s:  # a good tunnel stays open, so read one chunk
        s.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
        return int(s.recv(100).split()[1])


def control(cp, method, path, body=None, token=TOKEN):
    b = json.dumps(body).encode() if body is not None else b""
    r = raw(cp, f"{method} {path} HTTP/1.1\r\nX-Egress-Token: {token}\r\nContent-Length: {len(b)}\r\n\r\n".encode() + b)
    return int(r.split()[1]), r.partition(b"\r\n\r\n")[2]


def test_no_scope_refuses_everything(echo):
    pp, _ = start(EgressState(resolver_to("127.0.0.1"), allow_all))
    assert connect(pp, f"target.test:{echo}").startswith(b"HTTP/1.1 403")


def test_connect_in_scope_pinned(echo):
    calls = []
    def r(host, port, **kw):
        calls.append(host)
        return [(2, 1, 6, "", ("127.0.0.1", 0))]
    st = EgressState(r, allow_all)
    st.set_scope("j", {"target.test"}, {echo}, {})
    pp, _ = start(st)
    out = raw(pp, f"CONNECT target.test:{echo} HTTP/1.1\r\n\r\nGET /x HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n".encode())
    assert out.startswith(b"HTTP/1.1 200 Connection Established") and b"host=target.test path=/x" in out
    assert calls == ["target.test"] and st.connections == 1  # resolved once, tunnelled to the checked IP


def test_plain_http_forwarded_with_host_kept(echo):
    st = EgressState(resolver_to("127.0.0.1"), allow_all)
    st.set_scope("j", {"target.test"}, {echo}, {})
    pp, _ = start(st)
    out = raw(pp, f"GET http://target.test:{echo}/a?b=1 HTTP/1.1\r\nHost: target.test:{echo}\r\n\r\n".encode())
    assert b"200 OK" in out and f"host=target.test:{echo} path=/a?b=1".encode() in out


def test_connect_rebinding_refused(echo):
    answers = iter(["93.184.216.34", "127.0.0.1"])
    st = EgressState(lambda host, port, **kw: [(2, 1, 6, "", (next(answers), 0))])  # real default guard
    st.set_scope("j", {"target.test"}, {echo}, {})
    pp, cp = start(st)
    assert st.allowed("target.test", echo) == ("93.184.216.34", None)
    assert connect(pp, f"target.test:{echo}").startswith(b"HTTP/1.1 403")
    assert st.refused == 1
    assert json.loads(control(cp, "GET", "/stats")[1]) == {"job_id": "j", "connections": 1, "refused": 1}


def test_plain_http_out_of_scope_refused(echo):
    st = EgressState(resolver_to("127.0.0.1"), allow_all)
    st.set_scope("j", {"target.test"}, {echo}, {})
    pp, _ = start(st)
    assert raw(pp, b"GET http://other.test/ HTTP/1.1\r\nHost: other.test\r\n\r\n").startswith(b"HTTP/1.1 403")


def test_port_not_permitted_refused(echo):
    st = EgressState(resolver_to("127.0.0.1"), allow_all)
    st.set_scope("j", {"target.test"}, {echo}, {})
    pp, _ = start(st)
    assert connect(pp, "target.test:22").startswith(b"HTTP/1.1 403")


def test_internal_rule_allows_only_listed_ranges():
    ip = ["172.18.0.5"]
    st = EgressState(lambda host, port, **kw: [(2, 1, 6, "", (ip[0], 0))])
    st.set_scope("j", {"testtarget"}, {80}, {"testtarget": ["172.18.0.0/16"]})
    assert st.allowed("testtarget", 80) == ("172.18.0.5", None)
    ip[0] = "10.0.0.5"
    assert st.allowed("testtarget", 80)[0] is None
    ip[0] = "127.0.0.1"  # hard-forbidden is never overridable
    st.set_scope("j", {"testtarget"}, {80}, {"testtarget": None})
    assert st.allowed("testtarget", 80)[0] is None


def test_control_requires_token(echo):
    st = EgressState(resolver_to("127.0.0.1"), allow_all)
    _, cp = start(st)
    body = {"job_id": "j", "hosts": ["target.test"], "ports": [80], "internal": {}}
    assert control(cp, "PUT", "/scope", body, token="bad")[0] == 401 and not st.active
    assert control(cp, "PUT", "/scope", body)[0] == 204 and st.active
    assert control(cp, "DELETE", "/scope", token="bad")[0] == 401 and st.active
    assert control(cp, "DELETE", "/scope")[0] == 204 and not st.active


@pytest.fixture
def holder():
    """TCP server that accepts and keeps connections open."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    keep = []
    threading.Thread(target=lambda: [keep.append(srv.accept()) for _ in iter(int, 1)], daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


def scoped(port, hosts=("target.test",), **kw):
    st = EgressState(resolver_to("127.0.0.1"), allow_all, **kw)
    st.set_scope("j", set(hosts), {port}, {})
    return st


def test_userinfo_refused(echo):
    pp, _ = start(scoped(echo))
    assert raw(pp, f"GET http://target.test@evil.test:{echo}/ HTTP/1.1\r\n\r\n".encode()).startswith(b"HTTP/1.1 403")
    assert raw(pp, f"GET http://evil.test@target.test:{echo}/ HTTP/1.1\r\n\r\n".encode()).startswith(b"HTTP/1.1 403")


def test_host_header_rewritten_to_authority(echo):
    pp, _ = start(scoped(echo))
    out = raw(pp, f"GET http://target.test:{echo}/ HTTP/1.1\r\nHost: evil.test\r\n\r\n".encode())
    assert f"host=target.test:{echo} ".encode() in out and b"evil.test" not in out


def test_case_and_trailing_dot_accepted(echo):
    pp, _ = start(scoped(echo))
    assert connect_status(pp, f"TARGET.Test.:{echo}") == 200


def test_ipv6_literal_scope(echo):
    pp, _ = start(scoped(echo, hosts=("::1",)))
    assert connect_status(pp, f"[::1]:{echo}") == 200
    assert connect_status(pp, f"[::2]:{echo}") == 403


def test_absolute_https_refused(echo):
    pp, _ = start(scoped(echo))
    assert raw(pp, b"GET https://target.test/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403")


def test_bad_ports_refused(echo):
    pp, _ = start(scoped(echo))
    assert connect(pp, "target.test:0").startswith(b"HTTP/1.1 403")
    assert connect(pp, "target.test:70000").startswith(b"HTTP/1.1 403")
    with pytest.raises(ValueError):
        scoped(echo).set_scope("j", {"a"}, {0}, {})
    with pytest.raises(ValueError):
        scoped(echo).set_scope("j", {"a"}, {65536}, {})


def test_tunnel_closed_on_scope_delete(holder):
    pp, cp = start(scoped(holder))
    with socket.create_connection(("127.0.0.1", pp), 5) as s:
        s.sendall(f"CONNECT target.test:{holder} HTTP/1.1\r\n\r\n".encode())
        assert s.recv(100).startswith(b"HTTP/1.1 200")
        assert control(cp, "DELETE", "/scope")[0] == 204
        assert s.recv(100) == b""
    assert json.loads(control(cp, "GET", "/stats")[1])["connections"] == 1  # stats survive clear


def test_idle_timeout_closes_tunnel(holder):
    pp, _ = start(scoped(holder, idle_timeout=0.3))
    with socket.create_connection(("127.0.0.1", pp), 5) as s:
        s.sendall(f"CONNECT target.test:{holder} HTTP/1.1\r\n\r\n".encode())
        assert s.recv(100).startswith(b"HTTP/1.1 200")
        assert s.recv(100) == b""


def test_malformed_put_keeps_previous_scope(echo):
    st = scoped(echo)
    _, cp = start(st)
    for bad in ({"job_id": "k", "hosts": ["x"], "ports": [80], "internal": {"x": ["not-a-cidr"]}},
                {"job_id": "k", "hosts": ["x"], "ports": ["80"], "internal": {}},
                {"job_id": "k", "hosts": [1], "ports": [80], "internal": {}}, [1]):
        assert control(cp, "PUT", "/scope", bad)[0] == 400
    assert st.active and st.job_id == "j" and st.hosts == {"target.test"} and st.ports == {echo}


def test_control_slowloris_times_out(echo):
    _, cp = start(scoped(echo, control_timeout=0.3))
    with socket.create_connection(("127.0.0.1", cp), 5) as s:  # headers never finish
        s.sendall(b"PUT /scope HTTP/1.1\r\nX-Egress-Token: tok\r\n")
        assert s.recv(100) == b""
    with socket.create_connection(("127.0.0.1", cp), 5) as s:  # valid token, body never arrives
        s.sendall(b"PUT /scope HTTP/1.1\r\nX-Egress-Token: tok\r\nContent-Length: 100\r\n\r\n{")
        assert s.recv(100) == b""
    assert control(cp, "PUT", "/scope", token="bad")[0] == 401


def test_delete_for_other_job_is_a_noop_and_ttl_expires_scope():
    st = EgressState(resolver_to("127.0.0.1"), allow_all)
    _, cp = start(st)
    body = {"job_id": "j", "hosts": ["target.test"], "ports": [80], "internal": {}}
    assert control(cp, "PUT", "/scope", {**body, "ttl_s": 1})[0] == 204
    assert control(cp, "DELETE", "/scope?job_id=other")[0] == 204 and st.active
    assert st.allowed("target.test", 80)[1] is None
    time.sleep(1.2)
    assert st.allowed("target.test", 80)[1] == "no active scope"  # expired even before the reaper tick
    time.sleep(1.2)
    assert not st.active and json.loads(control(cp, "GET", "/stats")[1])["job_id"] is None
    assert control(cp, "PUT", "/scope", {**body, "ttl_s": -1})[0] == 400
    assert control(cp, "PUT", "/scope", body)[0] == 204 and control(cp, "DELETE", "/scope?job_id=j")[0] == 204 and not st.active
