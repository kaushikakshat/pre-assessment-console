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
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, None, "prod") == "unresolved"
