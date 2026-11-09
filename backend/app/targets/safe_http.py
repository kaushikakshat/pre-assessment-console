"""The only HTTP client scan code may use. Resolution + guard + connect happen in one place (the network
backend), so the address that was checked is the address that is connected to (no DNS-rebinding gap).
httpcore still sees the hostname, so Host header, SNI and certificate verification use it."""
import ipaddress
import socket
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass

import httpcore
import httpx

from app.targets import ipguard

TIMEOUT = 10
MAX_BYTES = 1_000_000
MAX_REQUESTS = 200


class ScopeError(Exception):
    pass


class BlockedAddress(Exception):
    pass


class RequestCapExceeded(Exception):
    pass


def default_guard(ip: str, allow_private: bool) -> str | None:
    return ipguard.is_forbidden(ip, allow_private)


class _GuardedBackend(httpcore.SyncBackend):
    def __init__(self, internal_hosts, resolver, guard):
        self.internal_hosts, self.resolver, self.guard = internal_hosts, resolver, guard

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ips = ipguard.resolve(host, self.resolver)
        nets = self.internal_hosts.get(host.lower(), False)  # False: none, None: any private, else allowed ranges
        for ip in ips:  # every answer must pass, as in validation
            allow = nets is not False and (nets is None or any(ipaddress.ip_address(ip) in n for n in nets))
            if (why := self.guard(ip, allow)):
                raise BlockedAddress(f"Destination refused: {why}")
        last = None
        for ip in ips:
            try:
                return super().connect_tcp(ip, port, timeout, local_address, socket_options)
            except httpcore.ConnectError as e:
                last = e
        raise last


class _Transport(httpx.HTTPTransport):
    def __init__(self, backend):
        super().__init__()
        self._pool.close()
        # keepalive off: every request re-resolves and re-guards
        self._pool = httpcore.ConnectionPool(ssl_context=httpx.create_ssl_context(), max_keepalive_connections=0,
                                             network_backend=backend)


@dataclass
class Response:
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")


class SafeClient:
    def __init__(self, scope, internal_hosts=(), *, max_requests=MAX_REQUESTS,
                 resolver=socket.getaddrinfo, guard=default_guard):
        # resolver/guard are injection points for tests only; nothing in env or requests reaches them.
        self.scope = {ipguard.normalize_host(h) for h in scope}
        self.max_requests, self.count = max_requests, 0
        items = internal_hosts.items() if isinstance(internal_hosts, Mapping) else ((h, None) for h in internal_hosts)
        backend = _GuardedBackend({ipguard.normalize_host(h): n for h, n in items}, resolver, guard)
        self._client = httpx.Client(transport=_Transport(backend), follow_redirects=False, trust_env=False,
                                    timeout=httpx.Timeout(TIMEOUT))
        # Fail closed if an upstream change stops our guarded pool from being the one in use.
        t = self._client._transport
        if not (isinstance(t, _Transport) and t._pool._network_backend is backend and not self._client._mounts):
            raise RuntimeError("SafeClient transport is not the guarded transport")

    def request(self, method: str, url: str, headers: dict | None = None, deadline: float | None = None) -> Response:
        """deadline: absolute time.monotonic() value shared across a multi-request operation."""
        u = httpx.URL(url)
        if u.scheme not in ("http", "https") or u.host.lower() not in self.scope:
            raise ScopeError("URL is outside the assessment scope")
        if self.count >= self.max_requests:
            raise RequestCapExceeded("Request cap reached")
        self.count += 1
        end = min(time.monotonic() + TIMEOUT, deadline or float("inf"))
        if end - time.monotonic() <= 0:
            raise TimeoutError("Time budget exhausted")
        body, truncated = bytearray(), False
        with self._client.stream(method, u, headers={"Accept-Encoding": "identity", **(headers or {})},
                                 timeout=httpx.Timeout(end - time.monotonic())) as r:
            for chunk in r.iter_raw():  # raw: we decode ourselves with a hard output cap
                body += chunk
                if len(body) > MAX_BYTES or time.monotonic() > end:  # deadline stops slow-drip bodies
                    truncated = True
                    del body[MAX_BYTES:]
                    break
            data = bytes(body)
            if r.headers.get("content-encoding", "identity").lower() in ("gzip", "x-gzip", "deflate"):
                try:
                    d = zlib.decompressobj(47)
                    data = d.decompress(data, MAX_BYTES + 1)
                    if len(data) > MAX_BYTES or d.unconsumed_tail:
                        data, truncated = data[:MAX_BYTES], True
                except zlib.error:
                    pass  # leave undecodable bodies raw
            return Response(r.status_code, r.headers, data, truncated)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
