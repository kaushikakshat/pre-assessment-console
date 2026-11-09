"""Form-login engine (single form, or password form then OTP page). All traffic goes through SafeClient.
Never logs or returns submitted values."""
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlencode

import httpx

from app.targets.safe_http import BlockedAddress, RequestCapExceeded, SafeClient, ScopeError

LOCKED = re.compile(r"(?i)\b(account|user)\s+(is\s+)?locked\b|too many (failed )?attempts")
MAX_HOPS = 4


@dataclass
class LoginSetup:
    style: str
    login_url: str
    username_field: str
    password_field: str
    logged_in_indicator: str
    code_field: str | None = None
    otp_url: str | None = None
    otp_field: str | None = None
    logged_out_indicator: str | None = None
    bypass_code: str | None = field(default=None, repr=False)


@dataclass
class LoginResult:
    ok: bool
    reason: str
    cookies: dict[str, str] = field(repr=False)


class _Hidden(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "input" and (d.get("type") or "").lower() == "hidden" and d.get("name"):
            self.fields[d["name"]] = d.get("value") or ""


def _hidden(html: str) -> dict[str, str]:
    p = _Hidden()
    p.feed(html)
    return p.fields


def _fetch(client, method, url, jar, deadline, form=None):
    """Follows redirects by hand (the client does not), carrying cookies; every hop is scope-checked."""
    for _ in range(MAX_HOPS + 1):
        h = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} if jar else {}
        body = urlencode(form).encode() if form is not None else None
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        r = client.request(method, url, headers=h, deadline=deadline, data=body)
        for sc in r.headers.get_list("set-cookie"):
            n, _, v = sc.split(";")[0].partition("=")
            jar[n.strip()] = v.strip()
        loc = r.headers.get("location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url, method, form = str(httpx.URL(url).join(loc)), "GET", None
            continue
        return r, url
    raise OSError("too many redirects")


def _same(a: str, b: str | None) -> bool:
    return bool(b) and httpx.URL(a).copy_with(fragment=None) == httpx.URL(b).copy_with(fragment=None)


def _signed_in(setup, r, url, entry) -> bool:
    """Never a false success: a good status, off the form page, no logged-out marker, and the marker present."""
    if r.status_code >= 400 or _same(url, entry):
        return False
    if setup.logged_out_indicator and setup.logged_out_indicator in r.text:
        return False
    ind = setup.logged_in_indicator
    try:
        if ind.startswith("url:"):
            u = httpx.URL(url)  # path and query only, never the host
            return bool(ind[4:]) and bool(re.search(ind[4:], u.raw_path.decode("ascii", "replace")))
        return bool(ind) and ind in r.text
    except re.error:
        return False


def _rejected(setup, r, url, entry) -> bool:
    return r.status_code >= 400 or _same(url, entry) or bool(setup.logged_out_indicator and setup.logged_out_indicator in r.text)


def _locked(r) -> bool:
    return r.status_code == 423 or bool(LOCKED.search(r.text))


def perform_login(client: SafeClient, setup: LoginSetup, username: str, password: str, deadline: float) -> LoginResult:
    jar: dict[str, str] = {}
    fail = lambda why: LoginResult(False, why, {})  # noqa: E731
    two = setup.style == "two-step"
    try:
        r, _ = _fetch(client, "GET", setup.login_url, jar, deadline)
        if r.status_code >= 400:
            return fail("Could not reach the login page")
        form = {**_hidden(r.text), setup.username_field: username, setup.password_field: password}
        if not two and setup.code_field and setup.bypass_code:
            form[setup.code_field] = setup.bypass_code
        r, url = _fetch(client, "POST", setup.login_url, jar, deadline, form)
        if not two:
            if _signed_in(setup, r, url, setup.login_url):
                return LoginResult(True, "Signed in", jar)
            return fail("Account appears locked" if _locked(r) else "The login page did not show the signed-in marker")
        if _locked(r):
            return fail("Account appears locked")
        if _rejected(setup, r, url, setup.login_url):
            return fail("The password step was not accepted")
        if not (setup.bypass_code and setup.otp_url and setup.otp_field):
            return fail("The OTP step did not accept the code")
        r, _ = _fetch(client, "GET", setup.otp_url, jar, deadline)
        form = {**_hidden(r.text), setup.otp_field: setup.bypass_code}
        r, url = _fetch(client, "POST", setup.otp_url, jar, deadline, form)
        if _signed_in(setup, r, url, setup.otp_url):
            return LoginResult(True, "Signed in", jar)
        return fail("Account appears locked" if _locked(r) else "The OTP step did not accept the code")
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, OSError, BlockedAddress, ScopeError, TimeoutError, RequestCapExceeded):
        return fail("Could not reach the login page")
