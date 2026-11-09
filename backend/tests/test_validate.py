import httpx
import pytest

from app.targets.validate import parse_target, validate_target

POLICY = {"version": "v1", "no_match": "approval", "permitted_ports": [80, 443, 8080, 8443], "rules": [
    {"id": "R-01", "outcome": "allow", "match": "domain", "value": "testtarget", "internal": True, "dev_only": True},
    {"id": "R-02", "outcome": "deny", "match": "domain", "value": "bad.example.com"},
    {"id": "R-03", "outcome": "allow", "match": "suffix", "value": "example.com"},
    {"id": "R-04", "outcome": "approval", "match": "cidr", "value": "8.8.8.0/24"},
]}
PUB = "93.184.216.34"


def resolver(table):
    def r(host, port, **kw):
        if host not in table:
            raise OSError("nx")
        return [(2, 1, 6, "", (ip, 0)) for ip in table[host]]
    return r


class Fetch:
    def __init__(self, *responses):
        self.responses, self.urls = list(responses), []

    def __call__(self, url):
        self.urls.append(url)
        r = self.responses.pop(0) if self.responses else (200, None)
        if isinstance(r, Exception):
            raise r
        return r


def run(target="https://app.example.com/", table=None, fetch=None, env="Staging", ports="443", hosts="", app_env="dev"):
    return validate_target(target, env, ports, POLICY, resolver(table or {"app.example.com": [PUB]}),
                           fetch or Fetch(), hosts, app_env)


def results(v):
    return {c["key"]: c["result"] for c in v["checks"]}


@pytest.mark.parametrize("t,msg", [
    ("2130706433", "Use http or https."), ("http://2130706433/", "Use a hostname or a standard IP address."),
    ("http://0x7f.1/", "standard IP"), ("http://017700000001/", "standard IP"), ("http://127.1/", "standard IP"),
    ("http://1.2.3.4.5/", "standard IP"), ("http://017.0.0.1/", "standard IP"),
    ("ftp://example.com/", "Use http or https."), ("https://user:pw@example.com/", "Remove credentials"),
    ("https://@example.com/", "Remove credentials"), ("", "Enter a target URL."), ("https:///x", "valid URL"),
    ("https://exa mple.com/", "valid URL"), ("http://２１３０７０６４３３/", "standard IP"),
    ("http://127。1/", "standard IP"), ("http://１５６６４６４５２２/", "standard IP"),
    ("http://９３.１８４.２１６.３４/", "standard IP"), ("http://a..b/", "valid URL"), ("https://example.com:99999/", "valid URL")])
def test_parse_rejects(t, msg):
    with pytest.raises(ValueError, match=msg):
        parse_target(t)


def test_internal_rule_types_and_ranges():
    def go(rule, host, ips):
        pol = {**POLICY, "rules": [{"id": "R-X", "outcome": "allow", "internal": True, **rule}]}
        return validate_target(f"http://{host}/", "Staging", "80", pol, resolver({host: ips}), Fetch(), "", "dev")
    assert go({"match": "env", "value": "staging"}, "x.test", ["10.0.0.5"])["outcome"] == "blocked"
    assert go({"match": "domain", "value": "x.test"}, "x.test", ["10.9.9.9"])["outcome"] == "allowed"
    cidr = {"match": "cidr", "value": "10.0.0.0/24"}
    assert go(cidr, "z.test", ["10.0.0.5"])["outcome"] == "allowed"
    assert go(cidr, "z.test", ["10.0.0.5", "10.5.5.5"])["outcome"] == "blocked"  # one answer outside the range


def test_redirect_hop_deny_rule():
    t = {"app.example.com": [PUB], "bad.example.com": [PUB]}
    v = run(table=t, hosts="bad.example.com", fetch=Fetch((302, "https://bad.example.com/")))
    assert results(v)["redirects"] == "fail" and "denied by rule R-02" in v["checks"][3]["detail"]


def test_unexpected_fetch_error_fails_closed_but_http_errors_warn():
    assert results(run(fetch=Fetch(KeyError("boom"))))["redirects"] == "fail"
    assert results(run(fetch=Fetch(httpx.ConnectError("x"))))["redirects"] == "warn"
    assert results(run(hosts="a..b"))["url"] == "pass"  # junk scope entries are ignored, not fatal


def test_budget_exhausted_warns():
    v = validate_target("https://app.example.com/", "Staging", "443", POLICY,
                        resolver({"app.example.com": [PUB]}), Fetch(), budget=-1)
    assert results(v)["redirects"] == "warn"


def test_default_fetch_blocks_rebinding():
    answers = iter([[PUB], ["127.0.0.1"]])  # public at validation (dns), loopback at connect time
    r = lambda host, port, **kw: [(2, 1, 6, "", (ip, 0)) for ip in next(answers)]  # noqa: E731
    v = validate_target("http://app.example.com/", "Staging", "80", POLICY, r)
    assert v["outcome"] == "blocked" and results(v)["redirects"] == "fail"
    assert "refused" in v["checks"][3]["detail"]


def test_parse_normalises():
    assert parse_target("HTTPS://App.Example.COM.:8443/x?q=1#f").normalized == "https://app.example.com:8443/x"
    assert parse_target("https://bücher.example/").host == "xn--bcher-kva.example"
    assert parse_target("http://[::1]/").normalized == "http://[::1]/"
    assert parse_target("http://10.0.0.1").normalized == "http://10.0.0.1/"


def test_happy_path_allowed():
    v = run()
    assert v["outcome"] == "allowed" and results(v)["redirects"] == "pass"
    assert [c["key"] for c in v["checks"]] == ["url", "dns", "addresses", "redirects", "ports", "rules", "environment"]
    assert v["normalized_target"] == "https://app.example.com/" and v["policy_version"] == "v1"


def test_first_fail_skips_rest_and_sends_nothing():
    f = Fetch()
    v = run("ftp://app.example.com/", fetch=f)
    assert v["outcome"] == "blocked" and results(v) == {"url": "fail", **{k: "skip" for k in (
        "dns", "addresses", "redirects", "ports", "rules", "environment")}}
    assert all(c["detail"] == "Not evaluated after a blocking result" for c in v["checks"][1:]) and not f.urls


def test_dns_failure():
    assert results(run("https://nx.example.com/"))["dns"] == "fail"


def test_mixed_public_and_private_answers_fail():
    f = Fetch()
    v = run(table={"app.example.com": [PUB, "10.0.0.5"]}, fetch=f)
    assert v["outcome"] == "blocked" and results(v)["addresses"] == "fail" and not f.urls


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "::ffff:10.0.0.1"])
def test_forbidden_never_allowed_even_by_internal_rule(ip):
    v = run("http://testtarget/", table={"testtarget": [ip]}, ports="80")
    assert v["outcome"] == "blocked" and results(v)["addresses"] == "fail"


def test_internal_rule_only_in_dev():
    t = {"testtarget": ["10.0.0.5"]}
    v = run("http://testtarget/", table=t, ports="80", app_env="dev")
    assert v["outcome"] == "allowed" and results(v)["addresses"] == "warn"
    assert v["checks"][2]["detail"] == "Internal target allowed by rule R-01"
    assert run("http://testtarget/", table=t, ports="80", app_env="prod")["outcome"] == "blocked"
    assert run("http://testtarget/", table=t, ports="80", app_env="")["outcome"] == "blocked"


def test_private_without_rule_blocked():
    assert run(table={"app.example.com": ["192.168.1.1"]})["outcome"] == "blocked"


def test_redirect_to_private_or_out_of_scope_fails():
    t = {"app.example.com": [PUB], "int.example.com": ["10.0.0.9"], "evil.test": [PUB]}
    v = run(table=t, hosts="int.example.com", fetch=Fetch((302, "https://int.example.com/")))
    assert results(v)["redirects"] == "fail" and v["outcome"] == "blocked" and "private" in v["checks"][3]["detail"]
    v = run(table=t, fetch=Fetch((301, "https://evil.test/x")))
    assert v["checks"][3]["detail"] == "Redirect leaves the approved scope: evil.test"
    v = run(table=t, fetch=Fetch(*[(302, "/again")] * 7))
    assert results(v)["redirects"] == "fail"  # more than 5 hops


def test_redirect_within_scope_passes_and_network_error_warns():
    f = Fetch((302, "/login"), (200, None))
    assert results(run(fetch=f))["redirects"] == "pass" and f.urls[-1] == "https://app.example.com/login"
    v = run(fetch=Fetch(OSError("down")))
    assert results(v)["redirects"] == "warn" and v["outcome"] == "allowed"
    assert v["checks"][3]["detail"] == "Target did not respond; redirects not checked"


def test_ports():
    assert results(run(ports="443, 22"))["ports"] == "fail"
    assert results(run("https://app.example.com:9000/"))["ports"] == "fail"
    assert results(run(ports="abc"))["ports"] == "fail"


def test_deny_rule_blocks_without_any_request():
    f = Fetch()
    v = run("https://bad.example.com/", table={"bad.example.com": [PUB]}, fetch=f)
    assert v["outcome"] == "blocked" and results(v)["rules"] == "fail" and not f.urls
    v = run("https://app.example.com/", ports="22", fetch=f)  # blocked port: still no request
    assert v["outcome"] == "blocked" and not f.urls


def test_no_match_and_approval_rule_need_approval():
    v = run("https://other.test/", table={"other.test": [PUB]})
    assert v["outcome"] == "approval" and results(v)["rules"] == "warn"
    assert run("https://other2.test/", table={"other2.test": ["8.8.8.8"]})["outcome"] == "approval"


def test_production_warns_but_stays_allowed():
    v = run(env="Production")
    assert results(v)["environment"] == "warn" and v["outcome"] == "allowed"
