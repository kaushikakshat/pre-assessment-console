"""Target validation: fixed check order, first fail blocks and skips the rest (DESIGN_SYSTEM §6.15)."""
import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from app.targets import ipguard
from app.targets.safe_http import BlockedAddress, SafeClient

LABELS = {"url": "URL", "dns": "DNS resolution", "addresses": "Destination addresses", "redirects": "Redirects",
          "ports": "Ports", "rules": "Allow and deny rules", "environment": "Environment policy"}
SKIPPED = "Not evaluated after a blocking result"
MAX_HOPS = 5
_NUMERIC_TLD = re.compile(r"0x[0-9a-f]*|[0-9]+", re.I)
_HOSTNAME = re.compile(r"[a-z0-9_.-]+")


@dataclass
class Parsed:
    scheme: str
    host: str
    port: int | None  # explicit only
    path: str

    @property
    def effective_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)

    @property
    def normalized(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{h}{f':{self.port}' if self.port else ''}{self.path}"


def parse_target(target: str) -> Parsed:
    """Raises ValueError with the user-facing message (DESIGN_SYSTEM §7.2)."""
    t = (target or "").strip()
    if not t:
        raise ValueError("Enter a target URL.")
    try:
        u = urlsplit(t)
        port = u.port
        raw_host = u.hostname
    except ValueError:
        raise ValueError("Enter a valid URL, for example https://app.example.com.") from None
    if u.scheme.lower() not in ("http", "https"):
        raise ValueError("Use http or https.")
    if "@" in u.netloc:
        raise ValueError("Remove credentials from the URL. Authenticated testing is set up in scan configuration.")
    if not raw_host:
        raise ValueError("Enter a valid URL, for example https://app.example.com.")
    try:
        ipaddress.ip_address(raw_host)
        host = raw_host.lower()
    except ValueError:
        if _NUMERIC_TLD.fullmatch(raw_host.rstrip(".").rsplit(".", 1)[-1]):  # 2130706433, 0x7f.1, 127.1, 017...
            raise ValueError("Use a hostname or a standard IP address.") from None
        try:
            host = ipguard.normalize_host(raw_host)
        except UnicodeError:
            raise ValueError("Enter a valid URL, for example https://app.example.com.") from None
        if not host or not _HOSTNAME.fullmatch(host):
            raise ValueError("Enter a valid URL, for example https://app.example.com.")
    return Parsed(u.scheme.lower(), host, port, u.path or "/")


def parse_ports(field: str) -> list[int]:
    toks = [t for t in re.split(r"[,\s]+", (field or "").strip()) if t]
    if not toks or not all(t.isdigit() and 0 < int(t) < 65536 for t in toks):
        raise ValueError("Enter port numbers between 1 and 65535, separated by commas.")
    return [int(t) for t in toks]


def _matches(rule, host, addrs, env) -> bool:
    kind, val = rule.get("match"), str(rule.get("value", "")).strip().lower()
    if kind == "domain":
        return host == val
    if kind == "suffix":
        val = val.lstrip(".")
        return host == val or host.endswith("." + val)
    if kind == "env":
        return env.lower() == val
    try:
        if kind == "ip":
            return ipaddress.ip_address(val) in {ipaddress.ip_address(a) for a in addrs}
        if kind == "cidr":
            net = ipaddress.ip_network(val, strict=False)
            return any(ipaddress.ip_address(a) in net for a in addrs if ipaddress.ip_address(a).version == net.version)
    except ValueError:
        pass
    return False


def first_rule(policy, host, addrs, env):
    return next((r for r in policy.get("rules", []) if _matches(r, host, addrs, env)), None)


def _internal_ok(rule, app_env) -> bool:
    return bool(rule and rule.get("internal") and (not rule.get("dev_only") or app_env == "dev"))


def _check_addrs(addrs, internal: bool):
    private = False
    for a in addrs:
        kind, why = ipguard.classify(a)
        if kind == "hard":
            return "fail", f"Resolves to a forbidden address ({why})."
        private |= kind == "private"
    if private and not internal:
        return "fail", "Resolves to a private address. Internal targets need an approved policy rule."
    return "pass", f"All {len(addrs)} resolved address(es) are permitted."


def validate_target(target, env, ports_field, policy, resolver=socket.getaddrinfo, fetch_redirect=None,
                    hosts="", app_env="prod") -> dict:
    """policy: {'version', 'permitted_ports', 'no_match', 'rules'}. fetch_redirect(url) -> (status, location|None);
    the default uses SafeClient. Unknown APP_ENV is treated as non-dev."""
    c = {"internal": set(), "needs_approval": False}
    scope = {t for t in re.split(r"[,\s]+", (hosts or "").lower()) if t}

    def url():
        try:
            c["p"] = parse_target(target)
        except ValueError as e:
            return "fail", str(e)
        return "pass", f"Valid {c['p'].scheme} URL."

    def dns():
        try:
            c["addrs"] = ipguard.resolve(c["p"].host, resolver)
        except OSError:
            return "fail", "The hostname did not resolve."
        return "pass", f"Resolved to {len(c['addrs'])} address(es)."

    def addresses():
        c["rule"] = first_rule(policy, c["p"].host, c["addrs"], env)
        internal = _internal_ok(c["rule"], app_env)
        res, detail = _check_addrs(c["addrs"], internal)
        if res == "pass" and internal and any(ipguard.classify(a)[0] for a in c["addrs"]):
            c["internal"].add(c["p"].host)
            return "warn", f"Internal target allowed by rule {c['rule']['id']}"
        return res, detail

    def ports():
        try:
            wanted = {c["p"].effective_port, *parse_ports(ports_field)}
        except ValueError as e:
            return "fail", str(e)
        bad = sorted(wanted - set(policy.get("permitted_ports", [])))
        return ("fail", f"Port {bad[0]} is not permitted by policy.") if bad else ("pass", "All ports are permitted.")

    def rules():
        r = c["rule"]
        out, ref = (r["outcome"], f"rule {r['id']}") if r else (policy.get("no_match", "approval"), "policy default")
        if out == "deny":
            return "fail", f"Denied by {ref}."
        if out == "allow":
            return "pass", f"Allowed by {ref}."
        c["needs_approval"] = True
        return "warn", (f"Approval required by {ref}." if r else "No rule matches this target. Approval is required.")

    def default_fetch(u):
        with SafeClient(scope | {c["p"].host}, c["internal"], resolver=resolver) as cl:
            r = cl.get(u)
            return r.status_code, r.headers.get("location")

    def redirects():
        # Ports/rules are pure, so evaluate them first: a target that policy blocks never receives a request.
        if ports()[0] == "fail" or rules()[0] == "fail":
            return "skip", "Not evaluated: policy blocks this target, so no request was sent."
        fetch, cur = fetch_redirect or default_fetch, c["p"].normalized
        allowed = scope | {c["p"].host}
        for hop in range(MAX_HOPS + 1):
            try:
                status, loc = fetch(cur)
            except BlockedAddress:
                return "fail", "A request was refused because the destination address is not permitted."
            except Exception:
                return "warn", "Target did not respond; redirects not checked"
            if status not in (301, 302, 303, 307, 308) or not loc:
                return "pass", "No redirect leaves the approved scope." if hop else "No redirects."
            if hop == MAX_HOPS:
                return "fail", f"More than {MAX_HOPS} redirects."
            cur = urljoin(cur, loc)
            try:
                nxt = parse_target(cur)
            except ValueError:
                return "fail", "Redirect leaves the approved scope: unsupported destination"
            if nxt.host not in allowed:
                return "fail", f"Redirect leaves the approved scope: {nxt.host}"
            try:
                addrs = ipguard.resolve(nxt.host, resolver)
            except OSError:
                return "fail", f"Redirect leaves the approved scope: {nxt.host}"
            rule = first_rule(policy, nxt.host, addrs, env)
            internal = _internal_ok(rule, app_env)
            res, detail = _check_addrs(addrs, internal)
            if res == "fail":
                return "fail", f"Redirect blocked: {detail}"
            if nxt.effective_port not in policy.get("permitted_ports", []):
                return "fail", f"Redirect blocked: port {nxt.effective_port} is not permitted by policy."
            if internal:
                c["internal"].add(nxt.host)
            cur = nxt.normalized
        return "pass", ""  # unreachable

    def environment():
        if env == "Production":
            return "warn", "Production target: scans are limited to Quick Scan in this release"
        return "pass", f"{env} target."

    results, failed = [], False
    for key, fn in (("url", url), ("dns", dns), ("addresses", addresses), ("redirects", redirects),
                    ("ports", ports), ("rules", rules), ("environment", environment)):
        if failed:
            res, detail = "skip", SKIPPED
        else:
            res, detail = fn()
            failed = res == "fail"
        results.append({"key": key, "label": LABELS[key], "result": res, "detail": detail})
    outcome = "blocked" if failed else "approval" if c["needs_approval"] else "allowed"
    return {"outcome": outcome, "checks": results, "policy_version": policy.get("version"),
            "normalized_target": c["p"].normalized if "p" in c else (target or "").strip(),
            "decided_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
