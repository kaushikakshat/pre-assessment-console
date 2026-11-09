import logging
import time
from dataclasses import asdict

import pytest

from app.core import crypto
from app.worker import main as wm
from app.models import Credential, LoginSetup
from app.db import SessionLocal
from app.targets.safe_http import SafeClient
from app.targets.safe_http import SafeClient as _SC  # noqa: F401
from app.worker.modules import access, auth, cval
from app.worker.modules.base import Ctx
from app.worker.similarity import SAME, same_page
from stub_portal import serve
from test_scheduler import make_assessment, sched  # noqa: F401

allow_all = lambda ip, allow_private: None  # noqa: E731
local = lambda host, port, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))]  # noqa: E731
ACCTS = {"C-0001": ("User", "alice"), "C-0002": ("Admin", "boss")}


@pytest.fixture(autouse=True)
def opened(monkeypatch):
    monkeypatch.setattr(crypto, "_ENABLED", True)


@pytest.fixture
def portal():
    srv, h = serve()
    yield srv, h
    srv.shutdown()


def mk(srv, accts=ACCTS, **rc):
    base = f"http://portal.test:{srv.server_port}"
    login = dict(style="single", login_url=base + "/login", username_field="u", password_field="p", logged_in_indicator="Sign out",
                 code_field=None, otp_url=None, otp_field=None, logged_out_indicator="Please sign in", bypass_code_enc=None)
    run_ctx = {"exclude": [], **rc}
    if accts:
        run_ctx["accounts"] = [(i, r, crypto.seal(u), crypto.seal("Secret!pw")) for i, (r, u) in accts.items()]
        run_ctx["login"] = login
    c = SafeClient({"portal.test"}, max_requests=200, guard=allow_all, resolver=local)
    return Ctx(url=base + "/", scheme="http", host="portal.test", port=srv.server_port, permitted_ports={srv.server_port},
               client=c, deadline=time.monotonic() + 30, run_ctx=run_ctx), base


def test_auth_no_accounts_skipped(portal):
    ctx, _ = mk(portal[0], accts=None)
    r = auth.run(ctx)
    assert (r.state, r.detail, r.findings) == ("skipped", "No test accounts were configured", [])


def test_auth_lockout_excludes_account_continues_others(portal):
    ctx, _ = mk(portal[0], {"C-0001": ("Locked user", "locked"), "C-0002": ("Admin", "boss"), "C-0003": ("User", "alice")})
    r = auth.run(ctx)
    assert r.state == "completed-warnings" and r.detail == "Locked user could not sign in: Account appears locked"
    assert ctx.run_ctx["sessions"] == {"C-0002": "sid=admin", "C-0003": "sid=good"} and r.findings == []
    assert sum(1 for s in portal[1].seen if s["u"] == "locked") == 1  # a lockout is not retried


def pages(base):
    return {None: {base + "/", base + "/shared"}, "C-0001": {base + "/", base + "/shared"},
            "C-0002": {base + "/", base + "/shared", base + "/admin/panel", base + "/leaky"}}


def signed(srv, **rc):
    ctx, base = mk(srv, **rc)
    auth.run(ctx)
    ctx.run_ctx["pages"] = pages(base)
    return ctx, base


def test_access_flags_lower_role_reaching_admin_page(portal):
    ctx, base = signed(portal[0])
    r = access.run(ctx)
    assert sorted(f.title for f in r.findings) == ["Page reachable without signing in", "User can open a page meant for Admin"]
    assert {f.asset for f in r.findings} == {base + "/leaky"} and all(f.severity == "high" and f.confidence == "suspected" for f in r.findings)
    assert "GET " + base + "/leaky" in r.findings[0].evidence and r.state == "completed"


def test_access_ignores_shared_pages_and_login_redirect(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["pages"][None] |= {base + "/leaky"}  # now shared with visitors
    ctx.run_ctx["pages"]["C-0001"] |= {base + "/leaky"}
    r = access.run(ctx)
    assert r.findings == []  # /admin/panel answers lower roles with the login page; /shared and /leaky are shared


def test_access_never_replays_excluded_urls(portal):
    ctx, base = signed(portal[0], exclude=[".*admin/panel.*"])
    ctx.run_ctx["pages"]["C-0002"] |= {base + "/user/delete/5"}
    access.run(ctx)
    assert "/user/delete/5" not in portal[1].hits
    assert "/admin/panel" not in portal[1].hits


def test_access_replays_post_but_not_excluded(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["pages"] = {None: set(), "C-0001": set(), "C-0002": set()}
    ctx.run_ctx["requests"] = {"C-0002": [("POST", base + "/admin/lax", {"to": "x"}), ("POST", base + "/admin/strict", {"to": "x"}),
                                          ("POST", base + "/user/delete/5", {"a": "1"}),
                                          ("POST", base + "/admin/lax", {"token": "[REDACTED]"}), ("POST", base + "/admin/lax", "[REDACTED BODY]")]}
    r = access.run(ctx)
    h = portal[1].hits
    assert sorted(f.title for f in r.findings) == ["Action reachable without signing in", "User can repeat an action meant for Admin"]
    assert all(f.severity == "medium" and f.confidence == "suspected" for f in r.findings)
    assert {f.location["method"] for f in r.findings} == {"POST"} and all(f.asset.endswith("/admin/lax") for f in r.findings)
    assert h.count("POST /admin/lax") == 2 and h.count("POST /admin/strict") == 2  # redacted bodies are never sent
    assert not any("delete" in x for x in h) and r.untested == 2 and r.state == "completed-warnings"


def test_cval_confirms_reproduced(portal):
    ctx, base = signed(portal[0])
    found = access.run(ctx).findings
    assert cval.run(ctx).state == "completed"
    assert not any(f.fingerprint_key is None or not f.fingerprint_key.startswith("GET|") for f in found)
    assert [d for _, d in ctx.run_ctx["confirmed"]] == found and all(f.confidence == "confirmed" for f in found)
    # a page that stopped being reachable stays suspected
    ctx.run_ctx["suspects"][0]["url"] = base + "/admin/panel"
    ctx.run_ctx["suspects"][0]["draft"].confidence = "suspected"
    cval.run(ctx)
    assert len(ctx.run_ctx["confirmed"]) == len(found) - 1


def test_credentials_absent_from_findings_and_logs(portal, caplog):
    caplog.set_level(logging.DEBUG)
    ctx, base = signed(portal[0])
    r = access.run(ctx)
    cval.run(ctx)
    assert r.findings
    blob = " ".join(str(asdict(f)) for f in r.findings) + caplog.text + repr(ctx.run_ctx.get("sessions")) + repr(r)
    blob += repr({k: v for k, v in ctx.run_ctx.items() if k not in ("suspects", "confirmed", "accounts")})
    for secret in ("Secret!pw", "alice", "boss"):
        assert secret not in blob
    assert any("[REDACTED]" in f.evidence for f in r.findings)


def test_same_page():
    a = b"<html><body><input type=hidden name=csrf value=abcdef0123456789abcdef> Orders 12 for 3f2b1c9a-1111-2222-3333-444455556666 total list of items here</body></html>"
    b = a.replace(b"abcdef0123456789abcdef", b"zzzzzz0123456789zzzzzz").replace(b"12", b"97")
    assert same_page(a, b) >= SAME
    assert same_page(a, b"<p>Please sign in to continue to the portal</p>") < SAME


def test_load_accounts_keeps_only_sealed_blobs(sched):  # noqa: F811
    aid, _ = make_assessment()
    with SessionLocal() as db:
        db.add(Credential(assessment_id=aid, role_label="User", username_enc=crypto.seal("alice"), password_enc=crypto.seal("Secret!pw")))
        db.add(LoginSetup(assessment_id=aid, style="single", login_url="http://x/login", username_field="u", password_field="p",
                          logged_in_indicator="ok", bypass_code_enc=crypto.seal("123456")))
        db.commit()
        rc = {}
        wm.load_accounts(db, db.get(wm.Assessment, aid), rc)
    assert rc["accounts"][0][1] == "User" and rc["login"]["style"] == "single"
    assert not any(x in repr(rc) for x in ("alice", "Secret!pw", "123456"))


def test_access_skips_urls_the_other_account_already_reaches(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["pages"]["C-0001"] |= {base + "/leaky"}  # the user crawl saw it; visitors did not
    r = access.run(ctx)
    assert [f.title for f in r.findings] == ["Page reachable without signing in"]


def test_access_rejects_denial_page_in_app_shell_and_error_posts(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["pages"]["C-0002"] |= {base + "/shell"}
    ctx.run_ctx["requests"] = {"C-0002": [("POST", base + "/admin/csrf", {"to": "x"}), ("POST", base + "/admin/lax", {"to": "x"})]}
    r = access.run(ctx)
    assert not any(f.asset.endswith(("/shell", "/admin/csrf")) for f in r.findings) and any(f.asset.endswith("/admin/lax") for f in r.findings)
    # state-changing findings are never re-checked or confirmed
    cval.run(ctx)
    assert all(d.location["method"] == "GET" for _, d in ctx.run_ctx["confirmed"])
    assert not any(d.confidence == "confirmed" for d in (s["draft"] for s in ctx.run_ctx["suspects"] if s["method"] == "POST"))


def test_cval_does_not_relogin_excluded_accounts(portal):
    ctx, base = signed(portal[0], accts={**ACCTS, "C-0003": ("Locked user", "locked")})
    assert ctx.run_ctx["excluded"] == {"C-0003"}
    access.run(ctx)
    cval.run(ctx)
    assert sum(1 for s in portal[1].seen if s["u"] == "locked") == 1


def test_access_session_lost_is_untested_and_relogged(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["sessions"]["C-0002"] = "sid=stale"
    r = access.run(ctx)
    assert r.state == "completed-warnings" and "session(s) ended" in r.detail and r.untested >= 1
    assert ctx.run_ctx["sessions"]["C-0002"] == "sid=admin"


def test_access_deadline_is_warning_with_untested(portal):
    ctx, base = signed(portal[0])
    ctx.deadline = time.monotonic() - 1
    r = access.run(ctx)
    assert r.state == "completed-warnings" and r.untested > 0 and "time limit" in r.detail


def test_redacted_substring_and_scrub():
    assert access.scrub("User ALICE paid; ab x", {"alice", "ab"}) == "User [REDACTED] paid; [REDACTED] x"
    assert access.scrub("cab", {"ab"}) == "cab"


def test_redacted_in_url_or_value_not_replayed(portal):
    ctx, base = signed(portal[0])
    ctx.run_ctx["pages"] = {None: set(), "C-0001": set(), "C-0002": set()}
    ctx.run_ctx["requests"] = {"C-0002": [("POST", base + "/admin/lax?token=[REDACTED]", {}), ("POST", base + "/admin/lax", {"a": "x[REDACTED]"})]}
    assert access.run(ctx).untested == 2 and "POST /admin/lax" not in portal[1].hits


def test_safe_client_keeps_no_cookies(portal):
    base = f"http://portal.test:{portal[0].server_port}"
    with SafeClient({"portal.test"}, guard=allow_all, resolver=local) as c:
        r = c.request("POST", base + "/login", data=b"csrf=tok-123&u=boss&p=Secret%21pw")
        assert "sid=admin" in r.headers["set-cookie"]
        assert c.get(base + "/admin/panel").text == "Please sign in"
