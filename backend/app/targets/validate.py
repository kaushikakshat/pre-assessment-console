"""Target validation: fixed check order, first fail blocks and skips the rest (DESIGN_SYSTEM §6.15)."""
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from app.targets import ipguard
import httpx

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


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


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
        try:
            host = ipguard.normalize_host(raw_host)  # NFKC/IDNA first: the resolver sees this form, so check it
        except UnicodeError:
            raise ValueError("Enter a valid URL, for example https://app.example.com.") from None
        # a non-ASCII spelling of an IP is ambiguous too
        if _is_ip(host) or _NUMERIC_TLD.fullmatch(host.rsplit(".", 1)[-1]):  # 2130706433, 0x7f.1, 127.1, 017...
            raise ValueError("Use a hostname or a standard IP address.")
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


def first_rule(policy, host, addrs, env, app_env="prod"):
    """dev_only rules are not part of the policy outside APP_ENV=dev."""
    return next((r for r in policy.get("rules", [])
                 if (app_env == "dev" or not r.get("dev_only")) and _matches(r, host, addrs, env)), None)


def _internal(rule, app_env, addrs):
    """Private-address allowance from the matching rule: False, or the allowed ranges (None = any private).
    Only host/address-specific rule types qualify; every private answer must be inside an ip/cidr rule's range."""
    if not (rule and rule.get("internal") and (not rule.get("dev_only") or app_env == "dev")
            and rule.get("match") in ("domain", "suffix", "ip", "cidr")):
        return False
    if rule["match"] in ("domain", "suffix"):
        return None
    try:
        net = ipaddress.ip_network(str(rule["value"]).strip(), strict=False)
    except ValueError:
        return False
    private = [a for a in addrs if ipguard.classify(a)[0] == "private"]
    return [net] if all(ipaddress.ip_address(a) in net for a in private) else False


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
                    hosts="", app_env="prod", budget=15, verify=True) -> dict:
    """policy: {'version', 'permitted_ports', 'no_match', 'rules'}. fetch_redirect(url) -> (status, location|None);
    the default uses SafeClient.
    budget: wall-clock seconds for all redirect hops combined. Unknown APP_ENV is treated as non-dev."""
    c = {"internal": {}, "needs_approval": False}
    deadline = time.monotonic() + budget
    scope = set()
    for t in re.split(r"[,\s]+", hosts or ""):
        try:
            if t:
                scope.add(ipguard.normalize_host(t))
        except UnicodeError:
            pass  # an unusable entry can never match a host

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
        c["rule"] = first_rule(policy, c["p"].host, c["addrs"], env, app_env)
        internal = _internal(c["rule"], app_env, c["addrs"])
        res, detail = _check_addrs(c["addrs"], internal is not False)
        if res == "pass" and internal is not False and any(ipguard.classify(a)[0] for a in c["addrs"]):
            c["internal"][c["p"].host] = internal
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
        with SafeClient(scope | {c["p"].host}, c["internal"], resolver=resolver, verify=verify) as cl:
            r = cl.get(u, deadline=deadline)
            return r.status_code, r.headers.get("location")

    def redirects():
        # Ports/rules are pure, so evaluate them first: a target that policy blocks never receives a request.
        if ports()[0] == "fail" or rules()[0] == "fail":
            return "skip", "Not evaluated: policy blocks this target, so no request was sent."
        fetch, cur = fetch_redirect or default_fetch, c["p"].normalized
        allowed = scope | {c["p"].host}
        for hop in range(MAX_HOPS + 1):
            try:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                status, loc = fetch(cur)
            except BlockedAddress:
                return "fail", "A request was refused because the destination address is not permitted."
            except (httpx.HTTPError, OSError, TimeoutError):
                return "warn", "Target did not respond; redirects not checked"
            except Exception:  # fail closed: anything unexpected is not a pass
                return "fail", "The redirect check could not be completed safely."
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
            rule = first_rule(policy, nxt.host, addrs, env, app_env)
            if rule and rule.get("outcome") == "deny":
                return "fail", f"Redirect blocked: denied by rule {rule['id']}."
            internal = _internal(rule, app_env, addrs)
            res, detail = _check_addrs(addrs, internal is not False)
            if res == "fail":
                return "fail", f"Redirect blocked: {detail}"
            if nxt.effective_port not in policy.get("permitted_ports", []):
                return "fail", f"Redirect blocked: port {nxt.effective_port} is not permitted by policy."
            if internal is not False and any(ipguard.classify(a)[0] for a in addrs):
                c["internal"][nxt.host] = internal
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
