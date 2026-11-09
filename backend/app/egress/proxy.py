"""Forward proxy that is the only way out for the scan engine. Every connection is resolved, guarded (Phase 2
ipguard + internal-range rules) and pinned to the checked IP; the hostname is never resolved a second time."""
import asyncio
import hmac
import ipaddress
import json
import socket
from urllib.parse import urlsplit

from app.targets import ipguard
from app.targets.safe_http import default_guard

CONNECT_TIMEOUT = 10
MAX_HEAD = 65536
_DENY = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


class EgressState:
    def __init__(self, resolver=socket.getaddrinfo, guard=default_guard):
        # resolver/guard are injection points for tests only; nothing in env or requests reaches them.
        self._resolver, self._guard = resolver, guard
        self.clear()

    def set_scope(self, job_id, hosts, ports, internal):
        self.job_id = job_id
        self.hosts = {ipguard.normalize_host(h) for h in hosts}
        self.ports = set(ports)
        self.internal = {ipguard.normalize_host(h): n for h, n in internal.items()}
        self.connections = self.refused = 0

    def clear(self):
        self.job_id, self.hosts, self.ports, self.internal = None, set(), set(), {}
        self.connections = self.refused = 0

    def allowed(self, host: str, port: int) -> tuple[str | None, str | None]:
        """-> (ip to connect to, None) or (None, refusal reason). Counts the outcome."""
        ip, why = self._check(host, port)
        if why:
            self.refused += 1
        else:
            self.connections += 1
        return ip, why

    def _check(self, host, port):
        if self.job_id is None:
            return None, "no active scope"
        try:
            host = ipguard.normalize_host(host)
        except UnicodeError:
            return None, "bad host"
        if host not in self.hosts:
            return None, "host out of scope"
        if port not in self.ports:
            return None, "port not permitted"
        try:
            ips = ipguard.resolve(host, self._resolver)
        except OSError:
            return None, "unresolvable"
        nets = self.internal.get(host, False)  # False: none, None: any private, else allowed ranges
        nets = nets if nets is None or nets is False else [ipaddress.ip_network(n) for n in nets]
        for ip in ips:  # every answer must pass, as in SafeClient
            allow = nets is not False and (nets is None or any(ipaddress.ip_address(ip) in n for n in nets))
            if (why := self._guard(ip, allow)):
                return None, f"destination refused: {why}"
        return ips[0], None


async def _read_head(reader):
    head = await reader.readuntil(b"\r\n\r\n")
    if len(head) > MAX_HEAD:
        raise ValueError("head too large")
    lines = head[:-4].decode("latin-1").split("\r\n")
    return lines[0], lines[1:]


async def _pump(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def _tunnel(cr, cw, ur, uw):
    await asyncio.gather(_pump(cr, uw), _pump(ur, cw))


async def _handle_proxy(state, cr, cw):
    try:
        try:
            line, headers = await asyncio.wait_for(_read_head(cr), 30)
            method, target, version = line.split(" ", 2)
            if method.upper() == "CONNECT":
                host, _, p = target.rpartition(":")
                host, port, path = host.strip("[]"), int(p), None
            else:
                u = urlsplit(target)
                if u.scheme != "http" or not u.hostname:
                    raise ValueError("absolute-form http only")
                host, port = u.hostname, u.port or 80
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            cw.write(_DENY)
            return
        ip, why = await asyncio.to_thread(state.allowed, host, port)
        if why:
            cw.write(_DENY)
            return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        if path is None:
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:  # one request per connection (Connection: close) so each request is re-checked
            keep = [h for h in headers if h.split(":", 1)[0].strip().lower()
                    not in ("proxy-connection", "proxy-authorization", "connection", "keep-alive")]
            uw.write("\r\n".join([f"{method} {path} {version}", *keep, "Connection: close", "", ""]).encode("latin-1"))
        await _tunnel(cr, cw, ur, uw)
    finally:
        try:
            cw.close()
        except Exception:
            pass


async def _handle_control(state, token, cr, cw):
    status, body = 400, b""
    try:
        line, headers = await asyncio.wait_for(_read_head(cr), 10)
        method, path, _ = line.split(" ", 2)
        h = {k.strip().lower(): v.strip() for k, _, v in (x.partition(":") for x in headers)}
        n = int(h.get("content-length", 0))
        raw = await cr.readexactly(n) if 0 < n <= 1_000_000 else b""
        if not hmac.compare_digest(h.get("x-egress-token", "").encode(), token.encode()):
            status = 401
        elif (method, path) == ("PUT", "/scope"):
            d = json.loads(raw)
            state.set_scope(str(d["job_id"]), set(d["hosts"]), {int(p) for p in d["ports"]}, dict(d.get("internal") or {}))
            status = 204
        elif (method, path) == ("DELETE", "/scope"):
            state.clear()
            status = 204
        elif (method, path) == ("GET", "/stats"):
            status, body = 200, json.dumps({"job_id": state.job_id, "connections": state.connections,
                                            "refused": state.refused}).encode()
        else:
            status = 404
    except Exception:  # malformed request or scope body
        status = 400
    cw.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
             f"Connection: close\r\n\r\n".encode() + body)
    cw.close()


async def serve(listen=("0.0.0.0", 3128), control=("0.0.0.0", 3129), *, token: str, state: EgressState | None = None):
    if not token:
        raise ValueError("token required")
    state = state or EgressState()
    ps = await asyncio.start_server(lambda r, w: _handle_proxy(state, r, w), *listen)
    cs = await asyncio.start_server(lambda r, w: _handle_control(state, token, r, w), *control)
    async with ps, cs:
        await asyncio.gather(ps.serve_forever(), cs.serve_forever())
