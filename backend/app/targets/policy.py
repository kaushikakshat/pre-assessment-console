"""Pure policy-document checks and outcome evaluation (no DB, no network)."""
import hashlib
import ipaddress
import json
import re

from app.targets import ipguard
from app.targets.validate import _HOSTNAME, _check_addrs, _internal, first_rule, parse_ports, parse_target

ENVS = ("Development", "Staging", "UAT", "Production")
RANK = {"allowed": 0, "approval": 1, "blocked": 2}
INVARIANTS = [
    "Loopback addresses (127.0.0.0/8, ::1)",
    "Unspecified addresses (0.0.0.0, ::)",
    "Link-local addresses (169.254.0.0/16, fe80::/10)",
    "Cloud metadata (169.254.169.254, fd00:ec2::254)",
    "Private ranges, unless an allow rule permits private addresses",
    "Redirects or DNS answers that leave the approved scope",
]
LABELS = {"schema": "Schema", "conflicts": "Conflicts", "invariants": "Safety invariants", "ports": "Ports"}
# shortcut: ipguard has no range list, so overlap is sampled against one address per hard range, plus the
# rule network's own ends; ipguard still blocks at scan time.
_HARD_SAMPLES = ["127.0.0.1", "0.0.0.0", "169.254.169.254", "100.100.100.200", "224.0.0.1", "255.255.255.255",
                 "::1", "::", "fe80::1", "ff02::1", "fd00:ec2::254"]
_MATCHES = ("domain", "suffix", "ip", "cidr", "env")


def _net(value):
    return ipaddress.ip_network(str(value).strip(), strict=False)


def _value_error(match, value):
    v = str(value).strip()
    try:
        if match in ("suffix", "domain"):
            if not v or not _HOSTNAME.fullmatch(ipguard.normalize_host(v.lstrip("."))):
                return "hostname is not valid"
        elif match == "ip":
            ipaddress.ip_address(v)
        elif match == "cidr":
            if "/" not in v:
                raise ValueError
            _net(v)
        elif match == "env" and v not in ENVS:
            return f"environment must be one of {', '.join(ENVS)}"
    except (ValueError, UnicodeError):
        return {"ip": "IP must look like 203.0.113.7", "cidr": "CIDR must look like 203.0.113.0/24"}.get(
            match, "hostname is not valid")
    return None


def _tag(i, r):
    return f"rules[{i}] ({r.get('id')})"


def schema_errors(doc) -> list[str]:
    if not isinstance(doc, dict):
        return ["Policy must be a JSON object"]
    errs = []
    if doc.get("no_match") not in ("allow", "approval", "deny"):
        errs.append("no_match must be allow, approval or deny")
    if not isinstance(doc.get("permitted_ports"), list):
        errs.append("permitted_ports must be a list")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return errs + ["rules must be a list"]
    seen = set()
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            errs.append(f"rules[{i}]: must be an object")
            continue
        t = _tag(i, r)
        if not isinstance(r.get("id"), str) or not re.fullmatch(r"R-\d{2,}", r["id"]):
            errs.append(f"{t}: ID must look like R-01")
        elif r["id"] in seen:
            errs.append(f"{t}: Duplicate rule ID")
        seen.add(r.get("id"))
        if r.get("outcome") not in ("allow", "approval", "deny"):
            errs.append(f"{t}: outcome must be allow, approval or deny")
        if r.get("match") not in _MATCHES:
            errs.append(f"{t}: match must be one of {', '.join(_MATCHES)}")
        elif (e := _value_error(r["match"], r.get("value", ""))):
            errs.append(f"{t}: {e}")
    return errs


def _shadows(a, b):
    if (a["match"], a["value"]) == (b["match"], b["value"]):
        return True
    if a["match"] != "suffix" or b["match"] not in ("domain", "suffix"):
        return False
    av, bv = str(a["value"]).strip().lower().lstrip("."), str(b["value"]).strip().lower().lstrip(".")
    return bv == av or bv.endswith("." + av)


def _conflicts(rules):
    out = []
    for j, b in enumerate(rules):
        for a in rules[:j]:
            if (a["match"], a["value"]) == (b["match"], b["value"]) and a["outcome"] != b["outcome"]:
                out.append(("fail", f"{b['id']} and {a['id']} match the same {a['match']} {a['value']} with different outcomes"))
            elif _shadows(a, b):
                out.append(("warn", f"{b['id']} is never reached: {a['id']} already covers it"))
    return out


def _invariants(doc):
    out = []
    for r in doc["rules"]:
        internal = r.get("internal")
        if internal and (r["outcome"] != "allow" or r["match"] not in ("domain", "suffix", "ip", "cidr")):
            out.append(("fail", f"{r['id']}: internal applies only to allow rules matching a host or address"))
        if r["outcome"] == "allow" and r["match"] in ("ip", "cidr"):
            net = _net(r["value"])
            ends = [net.network_address, net.broadcast_address]
            hard = [a for a in ends if ipguard.classify(a)[0] == "hard"] + [
                s for s in _HARD_SAMPLES if ipaddress.ip_address(s).version == net.version and ipaddress.ip_address(s) in net]
            if hard:
                out.append(("fail", f"{r['id']}: {r['value']} includes a forbidden address ({hard[0]}); safety invariants override rules"))
            elif ipguard.classify(net.network_address)[0] == "private" and not internal:
                out.append(("warn", f"{r['id']}: allows private addresses but is not marked internal, so it will not take effect"))
    if doc["no_match"] == "allow":
        out.append(("warn", "no_match is allow: unmatched targets run without approval"))
    return out


def _ports(doc):
    p = doc["permitted_ports"]
    if not p:
        return [("fail", "permitted_ports must not be empty")]
    bad = [x for x in p if not isinstance(x, int) or isinstance(x, bool) or not 0 < x < 65536]
    if bad:
        return [("fail", f"Invalid port {bad[0]}: use numbers between 1 and 65535")]
    return [("fail", "Duplicate ports")] if len(set(p)) != len(p) else []


def check_policy(doc: dict) -> list[dict]:
    errs = schema_errors(doc)
    groups = {"schema": [("fail", e) for e in errs]}
    if not errs:
        groups |= {"conflicts": _conflicts(doc["rules"]), "invariants": _invariants(doc), "ports": _ports(doc)}
    ok = {"schema": "Policy is valid", "conflicts": "No conflicting or shadowed rules",
          "invariants": "No rule overrides a safety invariant", "ports": "Permitted ports are valid"}
    out = []
    for k, label in LABELS.items():
        if k not in groups:  # a broken schema makes later groups meaningless
            continue
        out += [{"key": k, "label": label, "result": res, "detail": d} for res, d in groups[k]] or [
            {"key": k, "label": label, "result": "pass", "detail": ok[k]}]
    return out


def content_hash(doc: dict) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def evaluate_outcome(target, env, ports_field, policy, addrs, app_env) -> str:
    """Mirrors validate_target's url -> addresses -> ports -> rules order, without the redirect step."""
    try:
        p = parse_target(target)
    except ValueError:
        return "blocked"
    if addrs is None:
        return "unresolved"
    rule = first_rule(policy, p.host, addrs, env)
    if _check_addrs(addrs, _internal(rule, app_env, addrs) is not False)[0] == "fail":
        return "blocked"
    try:
        wanted = {p.effective_port, *(parse_ports(ports_field) if (ports_field or "").strip() else [])}
    except ValueError:
        return "blocked"
    if wanted - set(policy.get("permitted_ports", [])):
        return "blocked"
    out = rule["outcome"] if rule else policy.get("no_match", "approval")
    return {"deny": "blocked", "allow": "allowed"}.get(out, "approval")
