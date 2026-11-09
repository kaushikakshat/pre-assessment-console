import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from app.targets.safe_http import BlockedAddress, SafeClient, default_guard
from app.targets import ipguard

REFS = {"hsts": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "csp": "https://developer.mozilla.org/docs/Web/HTTP/CSP",
        "xfo": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
        "xcto": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "referrer": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
        "cookies": "https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
        "tls": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
        "exposed": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        "info": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "ports": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"}


class Blocked(Exception):
    """The target rate-limited or blocked our requests."""


@dataclass
class FindingDraft:
    severity: str
    confidence: str
    title: str
    asset: str
    location: dict
    description: str
    impact: str
    evidence: str
    reproduce: str
    remediation: str
    references: list = field(default_factory=list)
    fingerprint_key: str | None = None  # stable identity when title/asset would drift (engine alerts)
    credential_id: str | None = None  # display id of the account the finding was seen with


@dataclass
class ModuleResult:
    state: str
    detail: str
    findings: list = field(default_factory=list)
    tool_version: str | None = None
    untested: int = 0  # work the module could not reach (deadline); shown as Not tested


def location(ctx, kind, path=None, port=None, method=None, component=None, param=None, url=None):
    return {"url": url or ctx.url, "host": ctx.host, "port": port or ctx.port, "path": path, "param": param,
            "method": method, "component": component, "kind": kind}


_WAF = ("attention required", "request blocked", "web application firewall", "incapsula",
        "sucuri", "mod_security")


def looks_blocked(r) -> bool:
    if r.status_code == 429:
        return True
    if r.status_code != 403:
        return False
    h = " ".join(f"{k}={v}" for k, v in r.headers.items()).lower()
    return any(s in h for s in ("cloudflare", "sucuri", "akamai", "incapsula", "x-sucuri", "awselb")) \
        or any(s in r.text[:4000].lower() for s in _WAF)


@dataclass
class Ctx:
    url: str  # normalized target
    scheme: str
    host: str
    port: int
    permitted_ports: set
    client: SafeClient
    deadline: float  # absolute time.monotonic()
    internal: object = False  # False: none, None: any private, else allowed ranges (as in SafeClient)
    resolver: object = socket.getaddrinfo  # resolver/guard are test injection points only
    guard: object = default_guard
    run_ctx: dict = field(default_factory=dict)  # shared by one job's modules (zap client, crawl output, accounts)

    def get(self, path=None):
        r = self.client.get(urljoin(self.url, path) if path else self.url, deadline=self.deadline)
        if looks_blocked(r):
            raise Blocked
        return r

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def safe_ip(self) -> str:
        """The address raw-socket modules (ports, tls) may touch: every answer must pass the same guard as SafeClient."""
        ips = ipguard.resolve(self.host, self.resolver)
        for ip in ips:
            allow = self.internal is not False and (
                self.internal is None or any(ipaddress.ip_address(ip) in n for n in self.internal))
            if (why := self.guard(ip, allow)):
                raise BlockedAddress(f"Destination refused: {why}")
        return ips[0]
