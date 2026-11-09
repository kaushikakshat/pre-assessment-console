import asyncio
import http.server
import json
import socket
import threading

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
    assert control(cp, "PUT", "/scope", body, token="bad")[0] == 401 and st.job_id is None
    assert control(cp, "PUT", "/scope", body)[0] == 204 and st.job_id == "j"
    assert control(cp, "DELETE", "/scope", token="bad")[0] == 401 and st.job_id == "j"
    assert control(cp, "DELETE", "/scope")[0] == 204 and st.job_id is None
