"""Destination-address safety invariants. Hard-forbidden is never overridable; private is overridable only by
an approved internal policy rule (the caller decides that)."""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

_METADATA = {ipaddress.ip_address("fd00:ec2::254"): "cloud metadata",
             ipaddress.ip_address("100.100.100.200"): "cloud metadata"}
_6TO4 = ipaddress.ip_network("2002::/16")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_pool = ThreadPoolExecutor(max_workers=8)  # getaddrinfo has no timeout of its own


def classify(ip) -> tuple[str | None, str | None]:
    """-> ('hard'|'private'|None, reason)."""
    ip = ipaddress.ip_address(ip) if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip
    if ip.version == 6:
        embedded = ip.ipv4_mapped
        if embedded is None and ip in _6TO4:
            embedded = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            kind, why = classify(embedded)
            return ("hard", f"embedded IPv4 is {why}") if kind else (None, None)
    if ip in _METADATA:
        return "hard", _METADATA[ip]
    for name in ("loopback", "unspecified", "link_local", "multicast", "reserved"):
        if getattr(ip, f"is_{name}"):
            return "hard", name.replace("_", "-")
    if not ip.is_global:  # RFC1918, CGNAT, fc00::/7, 198.18.0.0/15, other non-routable space
        return "private", "private"
    return None, None


def is_forbidden(ip, allow_private: bool = False) -> str | None:
    kind, why = classify(ip)
    return why if kind == "hard" or (kind == "private" and not allow_private) else None


def normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower().encode("idna").decode("ascii")


def resolve(host: str, resolver=socket.getaddrinfo, timeout: float = 3) -> list[str]:
    """All A/AAAA answers (deduplicated, in order). Raises OSError on failure or timeout."""
    try:
        infos = _pool.submit(resolver, host, None, type=socket.SOCK_STREAM).result(timeout)
    except FutureTimeout:
        raise OSError("DNS lookup timed out") from None
    out = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    if not out:
        raise OSError("no addresses")
    return out
