from app.targets.policy import check_policy, content_hash, evaluate_outcome, schema_errors

BASE = {"rules": [], "permitted_ports": [80, 443], "no_match": "approval"}
def doc(*rules, **kw): return {**BASE, "rules": list(rules), **kw}
def r(i, outcome="allow", match="suffix", value="example.com", **kw): return {"id": i, "outcome": outcome, "match": match, "value": value, "note": "", **kw}
def fails(d): return [c["detail"] for c in check_policy(d) if c["result"] == "fail"]
def warns(d): return [c["detail"] for c in check_policy(d) if c["result"] == "warn"]

def test_clean_policy_passes_all_groups():
    out = check_policy(doc(r("R-01")))
    assert {c["key"] for c in out} == {"schema", "conflicts", "invariants", "ports"} and all(c["result"] == "pass" for c in out)

def test_schema_messages_name_the_rule():
    d = doc(r("R-01"), r("R-02"), r("R-07", match="cidr", value="10.0.0/33"))
    assert "rules[2] (R-07): CIDR must look like 203.0.113.0/24" in fails(d)
    assert any("rules[0] (R-01)" in e and "outcome" in e for e in schema_errors(doc(r("R-01", outcome="maybe"))))
    assert any("IP" in e for e in schema_errors(doc(r("R-01", match="ip", value="1.2.3"))))
    assert any("environment" in e.lower() for e in schema_errors(doc(r("R-01", match="env", value="Prod"))))
    assert any("Duplicate rule ID" in e for e in schema_errors(doc(r("R-01"), r("R-01", value="b.com"))))
    assert any("no_match" in e for e in schema_errors(doc(no_match="maybe")))
    assert schema_errors([]) and schema_errors({"rules": "x", "permitted_ports": [80], "no_match": "approval"})

def test_conflicts_and_shadowing():
    assert fails(doc(r("R-01"), r("R-02", outcome="deny")))
    assert warns(doc(r("R-01"), r("R-02")))
    assert any("R-02" in w and "R-01" in w for w in warns(doc(r("R-01", value="example.com"), r("R-02", match="domain", value="a.example.com"))))

def test_invariant_overrides():
    assert fails(doc(r("R-01", match="cidr", value="127.0.0.0/8")))
    assert fails(doc(r("R-01", match="cidr", value="0.0.0.0/0")))
    assert fails(doc(r("R-01", match="ip", value="169.254.169.254")))
    assert warns(doc(r("R-01", match="cidr", value="10.20.0.0/16")))
    assert not warns(doc(r("R-01", match="cidr", value="10.20.0.0/16", internal=True)))
    assert warns(doc(no_match="allow"))
    assert fails(doc(r("R-01", outcome="deny", match="env", value="Staging", internal=True)))

def test_ports():
    assert fails(doc(permitted_ports=[])) and fails(doc(permitted_ports=[0])) and fails(doc(permitted_ports=[80, 80]))

def test_content_hash_is_order_stable():
    assert content_hash({"a": 1, "b": [1]}) == content_hash({"b": [1], "a": 1})

def test_evaluate_outcome():
    pol = doc(r("R-01", outcome="deny", value="bad.com"), r("R-02", match="cidr", value="10.0.0.0/8", internal=True))
    assert evaluate_outcome("https://x.bad.com/", "Staging", "", pol, ["93.184.216.34"], "prod") == "blocked"
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, ["93.184.216.34"], "prod") == "approval"
    assert evaluate_outcome("https://in.corp/", "Staging", "", pol, ["10.1.2.3"], "prod") == "allowed"
    assert evaluate_outcome("https://ok.com:9999/", "Staging", "", pol, ["93.184.216.34"], "prod") == "blocked"
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, ["127.0.0.1"], "prod") == "blocked"
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, None, "prod") == "unresolved"  # R-02 (cidr) could match

def test_non_string_rule_id_is_a_schema_error():
    for bad in ([], {}):
        assert any("ID" in e for e in schema_errors(doc({**r("R-01"), "id": bad})))

def test_evaluate_outcome_ports_field_matches_validator():
    pol = doc(r("R-01"), permitted_ports=[80, 443, 8443])
    ev = lambda f: evaluate_outcome("https://x.example.com/", "Staging", f, pol, ["93.184.216.34"], "prod")
    assert ev("8443") == "allowed" and ev("9999") == "blocked" and ev("abc") == "blocked"

def test_dns_failure_still_applies_deny_and_ports():
    ev = lambda u, pol: evaluate_outcome(u, "Staging", "", pol, None, "prod")
    assert ev("https://app.example.com/", doc(r("R-01", "deny"))) == "blocked"
    assert ev("https://app.example.com/", doc(r("R-01", "deny", "cidr", "10.0.0.0/8"))) == "unresolved"
    assert ev("https://app.example.com:9999/", doc()) == "blocked"
    assert ev("https://app.example.com/", doc(r("R-01"))) == "allowed"

def test_dns_failure_is_exact_unless_an_ip_rule_could_come_first():
    ev = lambda pol, **kw: evaluate_outcome("https://app.example.com/", "Staging", "", pol, None, kw.get("app", "prod"))
    assert ev(doc(r("R-01", "allow", "domain", "app.example.com"))) == "allowed"
    assert ev(doc(r("R-01", "allow", "domain", "app.example.com", internal=True), r("R-02", "deny", "cidr", "10.0.0.0/8"))) == "allowed"
    assert ev(doc(r("R-01", "allow", "cidr", "10.0.0.0/8", internal=True), r("R-02", "allow", "domain", "app.example.com"))) == "unresolved"
    assert ev(doc(r("R-01", "allow", "domain", "other.com"))) == "approval"  # no match, no ip/cidr rule
    assert ev(doc(r("R-01", "allow", "domain", "other.com"), r("R-02", "allow", "cidr", "10.0.0.0/8", internal=True))) == "unresolved"
    dev = r("R-01", "allow", "cidr", "10.0.0.0/8", internal=True, dev_only=True)
    assert ev(doc(dev, r("R-02", "allow", "domain", "app.example.com"))) == "allowed"
    assert ev(doc(dev, r("R-02", "allow", "domain", "app.example.com")), app="dev") == "unresolved"

def test_schema_field_types():
    for bad, msg in [(r("R-01", note={"a": 1}), "note must be text"), (r("R-01", value=5), "value must be text"),
                     (r("R-01", internal="yes"), "internal must be true or false")]:
        assert any(msg in e for e in schema_errors(doc(bad))), msg
    ok = r("R-01"); del ok["note"]
    assert schema_errors(doc(ok, r("R-02", value="b.example.com", note="", internal=True, dev_only=False))) == []


def test_dev_only_rules_ignored_outside_dev():
    pol = doc(r("R-01", match="domain", value="testtarget", dev_only=True))
    assert evaluate_outcome("http://testtarget/", "Development", "", pol, ["93.184.216.34"], "prod") == "approval"
    assert evaluate_outcome("http://testtarget/", "Development", "", pol, ["93.184.216.34"], "dev") == "allowed"
