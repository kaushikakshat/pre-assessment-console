import time

import pytest

from app.targets.login import LoginSetup, perform_login
from app.targets.safe_http import SafeClient
from stub_portal import CODE, serve

allow_all = lambda ip, allow_private: None  # noqa: E731


def client():
    return SafeClient({"portal.test"}, max_requests=10, guard=allow_all,
                      resolver=lambda host, port, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))])


def setup(srv, **kw):
    base = f"http://portal.test:{srv.server_port}"
    d = dict(style="single", login_url=base + "/login", username_field="u", password_field="p",
             logged_in_indicator="Sign out", code_field="code", otp_url=base + "/otp", otp_field="code", bypass_code=CODE)
    return LoginSetup(**{**d, **kw})


def run(srv, s, user="alice", pw="Secret!pw"):
    with client() as c:
        return perform_login(c, s, user, pw, time.monotonic() + 20)


@pytest.fixture
def single():
    srv, h = serve()
    yield srv, h
    srv.shutdown()


def test_login_single_ok(single):
    srv, h = single
    r = run(srv, setup(srv))
    assert (r.ok, r.reason, r.cookies) == (True, "Signed in", {"sid": "good"})
    assert h.seen[0]["code"] == CODE


def test_login_two_step_ok():
    srv, h = serve(two_step=True)
    assert run(srv, setup(srv, style="two-step")).reason == "Signed in"
    assert run(srv, setup(srv, style="two-step", bypass_code="000000")).reason == "The OTP step did not accept the code"
    assert run(srv, setup(srv, style="two-step", bypass_code=None)).reason == "The OTP step did not accept the code"
    srv.shutdown()


def test_login_200_without_indicator_fails(single):
    r = run(single[0], setup(single[0]), pw="wrong")
    assert (r.ok, r.reason, r.cookies) == (False, "The login page did not show the signed-in marker", {})
    assert not run(single[0], setup(single[0], logged_in_indicator="url:/nowhere")).ok
    assert run(single[0], setup(single[0], logged_in_indicator="url:/home$")).ok


def test_login_locked_reason(single):
    assert run(single[0], setup(single[0]), user="locked").reason == "Account appears locked"


def test_login_carries_hidden_csrf_field(single):
    run(single[0], setup(single[0]))
    assert single[1].seen[0]["csrf"] == "tok-123"


def test_login_unreachable(single):
    srv, _ = single
    assert run(srv, setup(srv, login_url="http://other.test/login")).reason == "Could not reach the login page"


def test_login_page_echoing_marker_is_not_success(single):
    assert not run(single[0], setup(single[0]), user="echo").ok


def test_logged_out_indicator_fails(single):
    assert not run(single[0], setup(single[0], logged_out_indicator="Welcome")).ok


def test_url_indicator_matches_path_not_host(single):
    srv, _ = single
    assert not run(srv, setup(srv, logged_in_indicator="url:portal")).ok
    assert not run(srv, setup(srv, logged_in_indicator="url:")).ok


def test_two_step_wrong_password_sends_nothing_to_otp():
    srv, h = serve(two_step=True)
    r = run(srv, setup(srv, style="two-step"), pw="wrong")
    assert r.reason == "The password step was not accepted"
    assert all(f["_path"] != "/otp" for f in h.seen)
    srv.shutdown()


def test_lock_wording_and_bad_location():
    from app.targets.login import LOCKED
    assert not LOCKED.search("unlocked blocked clocked") and LOCKED.search("Your account is locked")


def test_login_hides_secrets_in_repr(single):
    r = run(single[0], setup(single[0]))
    assert "good" not in repr(r) and CODE not in repr(setup(single[0]))


def test_login_never_logs_values(single, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    run(single[0], setup(single[0]))
    assert "Secret!pw" not in caplog.text and CODE not in caplog.text and "alice" not in caplog.text
