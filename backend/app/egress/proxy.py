"""Forward proxy that is the only way out for the scan engine. Every connection is resolved, guarded (Phase 2
ipguard + internal-range rules) and pinned to the checked IP; the hostname is never resolved a second time."""
import asyncio
import collections
import logging
import re
import hmac
import ipaddress
import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from app.targets import ipguard
from app.targets.safe_http import default_guard

CONNECT_TIMEOUT = 10
MAX_HEAD = 65536
MAX_CONNS = 64
MAX_CONTROL_BODY = 65536
log = logging.getLogger("egress")
_DENY = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


class EgressState:
    def __init__(self, resolver=socket.getaddrinfo, guard=default_guard, *, idle_timeout=120, control_timeout=10):
        # resolver/guard/timeouts are injection points for tests only; nothing in env or requests reaches them.
        self._resolver, self._guard = resolver, guard
        self.idle_timeout, self.control_timeout = idle_timeout, control_timeout
        self._lock = threading.RLock()  # allowed() runs in worker threads; control handlers run on the loop
        self._conns: set = set()  # writers of live tunnels (event-loop only)
        self.active, self.job_id, self.connections, self.refused = False, None, 0, 0
        self.recent_refused = collections.deque(maxlen=20)
        self.hosts, self.ports, self.internal, self.expires = set(), set(), {}, None

    def set_scope(self, job_id, hosts, ports, internal, ttl_s=None):
        """Validates everything first, then swaps the scope in one step. Must be called on the event loop
        (or before serving) because it closes live tunnels."""
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("job_id")
        if isinstance(hosts, (str, bytes)) or not all(isinstance(h, str) for h in hosts):
            raise ValueError("hosts")
        if isinstance(ports, (str, bytes)) or not all(type(p) is int and 0 < p < 65536 for p in ports):
            raise ValueError("ports")
        if not isinstance(internal, dict):
            raise ValueError("internal")
        if ttl_s is not None and not (type(ttl_s) in (int, float) and 0 < ttl_s <= 86400):
            raise ValueError("ttl_s")
        new_internal = {}
        for h, n in internal.items():
            if not isinstance(h, str) or not (n is None or (isinstance(n, list) and all(isinstance(x, str) for x in n))):
                raise ValueError("internal")
            new_internal[ipguard.normalize_host(h)] = None if n is None else [ipaddress.ip_network(x) for x in n]
        new_hosts, new_ports = {ipguard.normalize_host(h) for h in hosts}, set(ports)
        with self._lock:
            self.active, self.job_id = True, job_id
            self.expires = None if ttl_s is None else time.monotonic() + ttl_s  # self-expiring if the worker dies
            self.hosts, self.ports, self.internal = new_hosts, new_ports, new_internal
            self.connections = self.refused = 0
            self.recent_refused.clear()
        self.close_all()

    def clear(self, job_id=None):
        """Drops the scope and live tunnels (counters stay readable; job_id becomes None). With job_id, only if it
        is the active job's: a late DELETE from an old job must not end a newer job's scope."""
        with self._lock:
            if job_id is not None and job_id != self.job_id:
                return
            self.active, self.job_id, self.hosts, self.ports, self.internal, self.expires = False, None, set(), set(), {}, None
        self.close_all()

    def _expired(self):
        return self.expires is not None and time.monotonic() >= self.expires

    def expire(self):
        """Event-loop tick: drops an expired scope together with its tunnels."""
        with self._lock:
            due = self.active and self._expired()
        if due:
            self.clear()

    def stats(self):
        with self._lock:
            return {"job_id": self.job_id, "connections": self.connections, "refused": self.refused,
                    "recent_refused": list(self.recent_refused)}

    def close_all(self):
        for w in list(self._conns):
            w.close()
        self._conns.clear()

    def allowed(self, host: str, port: int) -> tuple[str | None, str | None]:
        """-> (ip to connect to, None) or (None, refusal reason). Counts the outcome."""
        ip, why = self._check(host, port)
        with self._lock:
            if why:
                self.refused += 1
                h = re.sub(r"[^\w.:\[\]-]", "?", str(host)[:255])  # host only: never paths, queries or headers
                self.recent_refused.append({"host": h, "port": port, "reason": why})
                log.info("refused host=%s port=%s reason=%s", h, port, why)
            else:
                self.connections += 1
        return ip, why

    def _check(self, host, port):
        with self._lock:  # snapshot; the (slow) DNS lookup happens outside the lock
            active, hosts, ports, internal = self.active and not self._expired(), self.hosts, self.ports, self.internal
        if not active:
            return None, "no active scope"
        try:
            host = ipguard.normalize_host(host)
        except UnicodeError:
            return None, "bad host"
        if host not in hosts:
            return None, "host out of scope"
        if port not in ports:
            return None, "port not permitted"
        try:
            ips = ipguard.resolve(host, self._resolver)
        except OSError:
            return None, "unresolvable"
        nets = internal.get(host, False)  # False: none, None: any private, else allowed ranges
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


async def _pump(r, w, idle, kill):
    try:
        while data := await asyncio.wait_for(r.read(65536), idle):
            w.write(data)
            await w.drain()
        if w.can_write_eof():  # half-close: the other direction may still be draining
            w.write_eof()
    except (ConnectionError, OSError, asyncio.TimeoutError):
        kill()


async def _handle_proxy(state, sem, cr, cw):
    uw = None
    try:
        if sem.locked():
            cw.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        async with sem:
            state._conns.add(cw)
            try:
                line, headers = await asyncio.wait_for(_read_head(cr), 30)
                method, target, version = line.split(" ", 2)
                if method.upper() == "CONNECT":
                    host, _, p = target.rpartition(":")
                    host, port, path, authority = host.strip("[]"), int(p), None, None
                else:
                    u = urlsplit(target)
                    if u.scheme != "http" or not u.hostname or u.username is not None or u.password is not None:
                        raise ValueError("absolute-form http without userinfo only")
                    host, port = u.hostname, u.port or 80
                    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                    authority = (f"[{host}]" if ":" in host else host) + (f":{u.port}" if u.port else "")
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
            state._conns.add(uw)
            if path is None:
                cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                # Host is rewritten to the request-line authority. Bytes after the head are tunnelled as-is, so
                # pipelined requests stay pinned to this same checked IP and never reach another destination.
                drop = ("proxy-connection", "proxy-authorization", "connection", "keep-alive", "host")
                keep = [h for h in headers if h.split(":", 1)[0].strip().lower() not in drop]
                uw.write("\r\n".join([f"{method} {path} {version}", f"Host: {authority}", *keep,
                                       "Connection: close", "", ""]).encode("latin-1"))
            def kill():
                cw.close()
                uw.close()
            await asyncio.gather(_pump(cr, uw, state.idle_timeout, kill), _pump(ur, cw, state.idle_timeout, kill))
    finally:
        for w in (cw, uw):
            if w is not None:
                state._conns.discard(w)
                w.close()


async def _control_request(state, token, cr):
    line, headers = await _read_head(cr)
    method, target, _ = line.split(" ", 2)
    u = urlsplit(target)
    path, query = u.path, parse_qs(u.query)
    h = {k.strip().lower(): v.strip() for k, _, v in (x.partition(":") for x in headers)}
    if not hmac.compare_digest(h.get("x-egress-token", "").encode(), token.encode()):
        return 401, b""  # before any body is read
    n = int(h.get("content-length", 0))
    if not 0 <= n <= MAX_CONTROL_BODY:
        return 413, b""
    raw = await cr.readexactly(n) if n else b""
    if (method, path) == ("PUT", "/scope"):
        d = json.loads(raw)
        state.set_scope(d["job_id"], d["hosts"], d["ports"], d.get("internal") or {}, d.get("ttl_s"))
        return 204, b""
    if (method, path) == ("DELETE", "/scope"):
        state.clear((query.get("job_id") or [None])[0])
        return 204, b""
    if (method, path) == ("GET", "/stats"):
        return 200, json.dumps(state.stats()).encode()
    return 404, b""


async def _handle_control(state, token, cr, cw):
    try:
        try:
            status, body = await asyncio.wait_for(_control_request(state, token, cr), state.control_timeout)
        except asyncio.TimeoutError:
            return  # slow client: just drop it
        except Exception:  # malformed request or scope body; previous scope is untouched
            status, body = 400, b""
        cw.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                 f"Connection: close\r\n\r\n".encode() + body)
    finally:
        cw.close()


async def serve(listen=("0.0.0.0", 3128), control=("0.0.0.0", 3129), *, token: str, state: EgressState | None = None):
    if not token:
        raise ValueError("token required")
    state, sem = state or EgressState(), asyncio.Semaphore(MAX_CONNS)
    ps = await asyncio.start_server(lambda r, w: _handle_proxy(state, sem, r, w), *listen)
    cs = await asyncio.start_server(lambda r, w: _handle_control(state, token, r, w), *control)
    async def reaper():
        while True:
            state.expire()
            await asyncio.sleep(1)
    async with ps, cs:
        await asyncio.gather(ps.serve_forever(), cs.serve_forever(), reaper())
