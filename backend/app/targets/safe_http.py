"""The only HTTP client scan code may use. Resolution + guard + connect happen in one place (the network
backend), so the address that was checked is the address that is connected to (no DNS-rebinding gap).
httpcore still sees the hostname, so Host header, SNI and certificate verification use it."""
import socket
import time
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
        allow = host.lower() in self.internal_hosts
        for ip in ips:  # every answer must pass, as in validation
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
        backend = _GuardedBackend({ipguard.normalize_host(h) for h in internal_hosts}, resolver, guard)
        self._client = httpx.Client(transport=_Transport(backend), follow_redirects=False, trust_env=False,
                                    timeout=httpx.Timeout(TIMEOUT))

    def request(self, method: str, url: str, headers: dict | None = None) -> Response:
        u = httpx.URL(url)
        if u.scheme not in ("http", "https") or u.host.lower() not in self.scope:
            raise ScopeError("URL is outside the assessment scope")
        if self.count >= self.max_requests:
            raise RequestCapExceeded("Request cap reached")
        self.count += 1
        deadline, body, truncated = time.monotonic() + TIMEOUT, bytearray(), False
        with self._client.stream(method, u, headers={"Accept-Encoding": "identity", **(headers or {})}) as r:
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_BYTES or time.monotonic() > deadline:  # deadline stops slow-drip bodies
                    truncated = True
                    del body[MAX_BYTES:]
                    break
            return Response(r.status_code, r.headers, bytes(body), truncated)

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
