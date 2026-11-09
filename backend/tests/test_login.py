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
