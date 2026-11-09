"""Phase 3 end-to-end check against the real stack (dev profile: testportal). Run inside the worker container:
   docker-compose exec -T worker python /app/scripts/e2e_phase3.py
(the worker is used because it alone reaches the egress control API and holds the database URL.)
Creates its own admin/owner (forced password change + TOTP enrolment), never touches existing data."""
import os
import re
import subprocess
import sys
import time
import uuid

import httpx
import pyotp
from sqlalchemy import create_engine, text

BASE = "http://web/api"
HOST = "testportal"
SECRETS = ["citizen-pass", "officer-pass"]
CODE = "444444"
CEILING = 3 * 3600
FAILS: list[str] = []
START = time.monotonic()


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" -- {detail}" if detail and not ok else ""), flush=True)
    if not ok:
        FAILS.append(name)


def log(msg):
    print(f"[{int(time.monotonic() - START):5d}s] {msg}", flush=True)


class Api:
    """Own cookie jar: the stack may set Secure cookies and this runs over plain http."""
    def __init__(self):
        self.c, self.jar = httpx.Client(base_url=BASE, timeout=60), {}

    def req(self, method, path, **kw):
        h = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.jar.items())}
        if method != "GET" and "pa_csrf" in self.jar:
            h["X-CSRF-Token"] = self.jar["pa_csrf"]
        r = self.c.request(method, path, headers=h, **kw)
        for sc in r.headers.get_list("set-cookie"):
            n, _, v = sc.split(";")[0].partition("=")
            self.jar[n.strip()] = v.strip()
        return r

    def ok(self, method, path, want=(200, 201, 202, 204), **kw):
        r = self.req(method, path, **kw)
        if r.status_code not in want:
            raise SystemExit(f"FATAL {method} {path} -> {r.status_code} {r.text[:300]}")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else r

    def sign_in(self, email, temp):
        self.req("GET", "/auth/csrf")
        r = self.ok("POST", "/auth/login", json={"email": email, "password": temp})
        assert r["next"] == "enrol", r
        self.ok("POST", "/auth/mfa", json={"code": pyotp.TOTP(r["secret"]).now()})
        me = self.ok("GET", "/auth/me")
        assert me["must_change_password"], me
        new = "E2e-" + uuid.uuid4().hex + "!"
        self.ok("POST", "/auth/password", json={"current_password": temp, "new_password": new})
        assert not self.ok("GET", "/auth/me")["must_change_password"]


def poll(fn, done, what, ceiling=CEILING, every=15, progress=60):
    t0, last = time.monotonic(), 0
    while True:
        v = fn()
        if done(v):
            return v
        if time.monotonic() - t0 > ceiling:
            raise SystemExit(f"FATAL timed out waiting for {what}")
        if time.monotonic() - last >= progress:
            last = time.monotonic()
            log(f"waiting for {what}: {v if isinstance(v, str) else ''}")
        time.sleep(every)


def egress_stats():
    return httpx.get(os.environ["EGRESS_CONTROL"] + "/stats", headers={"X-Egress-Token": os.environ["EGRESS_TOKEN"]}, timeout=10).json()


def main():
    tag = uuid.uuid4().hex[:8]
    admin_email, owner_email = f"e2e-admin-{tag}@example.com", f"e2e-owner-{tag}@example.com"
    out = subprocess.run([sys.executable, "-m", "app.cli", "create-admin", "--email", admin_email, "--name", "E2E Admin"],
                         capture_output=True, text=True, check=True).stdout
    admin_pw = re.search(r"Temporary password for \S+: (\S+)", out).group(1)
    admin, owner = Api(), Api()
    admin.sign_in(admin_email, admin_pw)
    u = admin.ok("POST", "/admin/users", json={"name": "E2E Owner", "email": owner_email, "role": "owner", "team": "QA"})
    owner.sign_in(owner_email, u["temporary_password"])
    log("admin and owner ready")

    cap = admin.ok("GET", "/admin/capacity")["config"]
    old_deep = cap["profile_limits"]["deep"]
    put = lambda deep: admin.ok("PUT", "/admin/capacity", json={  # noqa: E731
        **{k: cap[k] for k in ("limit", "aging_enabled", "aging_minutes", "queue_cap", "per_user_quota", "engine_slots")},
        "profile_limits": {"deep": deep}, "reason": "e2e run: shorter Deep budget"})
    put({**old_deep, "budget_min": 20})
    try:
        run(owner, admin_email)
    finally:
        put(old_deep)
        log(f"Deep budget restored to {old_deep['budget_min']} min")


def sql_hits(eng, secret):
    """Rows (whole-row text) in every table that could carry a value, matching a secret."""
    pat = rf"(?<![0-9]){secret}(?![0-9])" if secret.isdigit() else re.escape(secret)
    bad = {}
    with eng.connect() as c:
        for t in ("findings", "audit_events", "jobs", "module_runs", "reports", "credentials", "login_setups", "assessments"):
            n = c.execute(text(f"SELECT count(*) FROM {t} WHERE {t}::text ~* :p"), {"p": pat}).scalar()
            if n and t not in ("credentials", "login_setups"):
                bad[t] = n
    return bad


def run(o, admin_email):
    a = o.ok("POST", "/assessments", json={"name": "E2E Portal", "target": f"http://{HOST}/", "env": "Development", "hosts": HOST,
                                            "paths": "", "ports": "80", "exclusions": "", "notes": "Phase 3 e2e"})
    aid = a["id"]
    v = o.ok("POST", f"/assessments/{aid}/validate")
    check("assessment validates (allowed)", v["outcome"] == "allowed", str(v["outcome"]))
    if v["outcome"] != "allowed":
        raise SystemExit("FATAL validation did not allow the dev portal")

    single = {"style": "single", "login_url": f"http://{HOST}/login", "username_field": "username", "password_field": "password",
              "code_field": "code", "logged_in_indicator": "Sign out", "logged_out_indicator": "Sign in to continue", "bypass_code": CODE}
    o.ok("PUT", f"/assessments/{aid}/signin", json=single)
    ids = {}
    for i, (role, user, pw) in enumerate([("Citizen", "citizen", "citizen-pass"), ("Officer", "officer", "officer-pass")]):
        if i:
            time.sleep(31)  # one sign-in test per 30 s
        r = o.ok("POST", f"/assessments/{aid}/accounts", json={"role_label": role, "username": user, "password": pw, "test": True,
                                                                "authorized": True, "bypass_code": CODE})
        ids[role] = r["id"]
        check(f"single-form test login works ({role})", r["last_test"] == "ok", f"{r['last_test']} {r['test_result']}")
    sig = o.ok("GET", f"/assessments/{aid}/signin")
    check("sign-in setup response holds no secrets", not any(s in str(sig) for s in SECRETS + [CODE]))

    cat = o.ok("GET", "/catalog")
    wl = cat["wordlists"]
    disc = next((w for w in wl if w["key"] == "Discovery/Web-Content/quickhits.txt"),
                None) or min((w for w in wl if w["category"] == "discovery" and w["lines"] >= 20), key=lambda w: w["lines"])
    fz = [w for w in wl if w["category"] == "fuzzing"]
    fuzz = min((w for w in fz if "xss" in w["key"].lower()), key=lambda w: w["lines"], default=None) or min(fz, key=lambda w: w["lines"])
    log(f"wordlists: {disc['key']} ({disc['lines']}), {fuzz['key']} ({fuzz['lines']})")
    job = o.ok("POST", "/jobs", json={"assessment_id": aid, "profile": "deep", "modules": None, "authorized": True,
                                      "idempotency_key": uuid.uuid4().hex, "wordlists": [disc["key"], fuzz["key"]],
                                      "credential_ids": list(ids.values())})
    jid = job["id"]
    log(f"Deep Scan submitted: {jid}")
    final = poll(lambda: o.ok("GET", f"/jobs/{jid}"), lambda j: j["state"] in ("completed", "completed-warnings", "failed", "cancelled", "blocked", "interrupted"),
                 f"{jid}")
    for m in final["modules"]:
        log(f"  module {m['key']}: {m['state']} {m['detail'] or ''}")
    check("deep scan finished", final["state"] in ("completed", "completed-warnings"), final["state"])
    es = egress_stats()
    log(f"egress after deep scan: connections={es['connections']} refused={es['refused']} recent_refused={es['recent_refused']}")
    check("egress: no refusal for the portal host (deep)", not [r for r in es["recent_refused"] if r["host"] == HOST])
    check("egress: portal traffic went through the guard", es["connections"] > 0)

    fs = o.ok("GET", f"/assessments/{aid}/findings")
    for f in fs:
        log(f"  {f['id']} {f['severity']}/{f['confidence']} {f['state']} {f['module']}: {f['title']}")
    det = {f["id"]: o.ok("GET", f"/findings/{f['id']}") for f in fs}
    acc = [f for f in fs if "can open a page meant for" in f["title"] and f["severity"] == "high"]
    check("high 'can open a page meant for' finding", bool(acc) and any("officer" in f["title"].lower() for f in acc), str([f["title"] for f in fs]))
    xss = [f for f in fs if re.search(r"(?i)cross[- ]site scripting|xss", f["title"]) and "/search" in str(det[f["id"]]["location"]) + f["title"] + f["asset"]]
    check("suspected XSS on /search", bool(xss) and any(f["confidence"] == "suspected" for f in xss), str([f["title"] for f in fs]))
    check("jQuery advisory", any(re.search(r"(?i)jquery", f["title"]) for f in fs), str([f["title"] for f in fs]))
    mods = {m["key"]: m for m in final["modules"]}
    for k in ("auth", "crawl", "dast", "access"):
        check(f"module {k} ran (not unavailable/failed)", mods[k]["state"] in ("completed", "completed-warnings"), f"{mods[k]['state']} {mods[k]['detail']}")

    # retest the XSS finding (prefer the wordlist/fuzz one on /search)
    if xss:
        tgt = xss[0]
        rj = o.ok("POST", f"/assessments/{aid}/retest", json={"finding_ids": [tgt["id"]], "authorized": True, "idempotency_key": uuid.uuid4().hex})
        check("retest queued", rj["type"] == "retest" and rj["retest_of"] == [tgt["id"]], str(rj["type"]))
        rfin = poll(lambda: o.ok("GET", f"/jobs/{rj['id']}"), lambda j: j["state"] in ("completed", "completed-warnings", "failed", "cancelled", "blocked", "interrupted"),
                    f"retest {rj['id']}", every=10)
        check("retest ran", rfin["state"] in ("completed", "completed-warnings"), f"{rfin['state']} {[(m['key'], m['state'], m['detail']) for m in rfin['modules']]}")
        after = o.ok("GET", f"/findings/{tgt['id']}")
        check("retest leaves XSS finding present (new/reopened)", after["state"] in ("new", "reopened"), f"{after['state']} {after['history'][-1:]}")
        es2 = egress_stats()
        check("egress: no refusal for the portal host (retest)", not [r for r in es2["recent_refused"] if r["host"] == HOST], str(es2["recent_refused"]))
    else:
        check("retest of XSS finding", False, "no XSS finding to retest")

    rep = o.ok("POST", f"/assessments/{aid}/reports", json={"type": "technical", "job_id": jid})
    rd = poll(lambda: o.ok("GET", f"/reports/{rep['id']}"), lambda r: r["state"] in ("ready", "failed"), "report", ceiling=300, every=3)
    check("technical report ready", rd["state"] == "ready", str(rd.get("error")))
    pdf = o.req("GET", f"/reports/{rep['id']}/pdf")
    check("report PDF downloads (%PDF)", pdf.status_code == 200 and pdf.content[:4] == b"%PDF", f"{pdf.status_code} {pdf.content[:8]!r}")

    # two-step sign-in
    time.sleep(31)
    o.ok("PUT", f"/assessments/{aid}/signin", json={"style": "two-step", "login_url": f"http://{HOST}/login2", "username_field": "username",
                                                    "password_field": "password", "otp_url": f"http://{HOST}/otp", "otp_field": "code",
                                                    "logged_in_indicator": "Sign out", "logged_out_indicator": "Sign in to continue", "bypass_code": CODE})
    r = o.ok("POST", f"/assessments/{aid}/accounts", json={"role_label": "Officer two-step", "username": "officer", "password": "officer-pass",
                                                            "test": True, "authorized": True, "bypass_code": CODE})
    check("two-step test login works", r["last_test"] == "ok", f"{r['last_test']} {r['test_result']}")

    # no-secret-leak sweep
    eng = create_engine(os.environ["DATABASE_URL"])
    for s in SECRETS + [CODE]:
        bad = sql_hits(eng, s)
        check(f"no stored row contains {'the bypass code' if s == CODE else s}", not bad, str(bad))
    blob = str([det[k] for k in det]) + str(o.ok("GET", f"/assessments/{aid}/activity")) + str(o.ok("GET", f"/assessments/{aid}/jobs")) + str(rd)
    check("API findings/activity/jobs/report hold no secret", not any(s in blob for s in SECRETS) and not re.search(rf"(?<![0-9]){CODE}(?![0-9])", blob))

    print("RESULT ALL PASS" if not FAILS else f"RESULT FAIL ({len(FAILS)}): " + "; ".join(FAILS), flush=True)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
