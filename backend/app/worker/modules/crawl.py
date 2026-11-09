"""Spider the target unauthenticated and once per signed-in account (inventory only, no findings).
run_ctx contract (shared with the access module): sessions {credential display id: Cookie header value} comes from
the login step; this module writes pages {id|None: set of URLs} and requests {id|None: [(method, url, form dict)]}."""
import logging
import re
import time
from urllib.parse import parse_qsl, urlsplit

from app.engine import zap as _zap  # module import: zap imports modules.base, so names are read at call time

from .base import ModuleResult

log = logging.getLogger("worker")
SENSITIVE_URL = re.compile(r"(?i)log(in|out)|sign-?in|auth|otp|password")
SECRET_FIELD = re.compile(r"(?i)pass|token|otp|csrf|secret|code")
_QS_SECRET = re.compile(r"(?i)([?&;][^=&#]*(?:pass|token|otp|csrf|secret|code)[^=&#]*=)[^&#]*")


def accounts(rc) -> list:
    return [(None, None), *(rc.get("sessions") or {}).items()]


def context(ctx, cred) -> int:
    """One ZAP context per account, created once; limited to the target origin and the run's exclusions."""
    rc = ctx.run_ctx
    ids = rc.setdefault("contexts", {})
    if cred not in ids:
        origin = f"{ctx.scheme}://{ctx.host}" + ("" if ctx.port in (80, 443) else f":{ctx.port}")
        ids[cred] = rc["zap"].setup_context(f"acct-{cred or 'anonymous'}", [re.escape(origin) + ".*"], rc.get("exclude", []))
    return ids[cred]


def as_account(zap, cookie):
    zap.clear_headers()  # replacer rules are global: only this account's cookie may be on
    if cookie:
        zap.set_header("Cookie", cookie)


def clear_quiet(zap):
    """For finally blocks: a failed cleanup must not replace the error being raised (no values in the log)."""
    try:
        zap.clear_headers()
    except Exception:
        log.warning("could not clear the scan engine's injected headers")


def akey(a):
    return a.get("id") or (a.get("pluginId"), a.get("url"), a.get("param"), a.get("method"))


def harvest(ctx, cred):
    """The ZAP alert store is shared by every account: each alert belongs to the account active when it first appeared."""
    rc = ctx.run_ctx
    store = rc.setdefault("alerts", {})
    for a in rc["zap"].alerts(ctx.url):
        store.setdefault(akey(a), (cred, a))


def safe_request(rc, method, url, form):
    """Replay data for the access checks must never hold credentials: drop login/OTP requests, mask secret fields."""
    if SENSITIVE_URL.search(url) or any(re.fullmatch(x, url) for x in rc.get("exclude", [])):
        return None
    return (method, _QS_SECRET.sub(lambda m: m.group(1) + "[REDACTED]", url),
            {k: "[REDACTED]" if SECRET_FIELD.search(k) else v for k, v in form.items()})


def run(ctx) -> ModuleResult:
    rc, zap = ctx.run_ctx, ctx.run_ctx["zap"]
    pages, reqs, other, partial = rc.setdefault("pages", {}), rc.setdefault("requests", {}), set(), False
    accts = accounts(rc)
    try:
        for i, (cred, cookie) in enumerate(accts):
            as_account(zap, cookie)
            before = zap.message_count(ctx.url)
            dl = time.monotonic() + max(0.0, ctx.remaining()) / (len(accts) - i)
            urls, out, pct = zap.spider(ctx.url, context(ctx, cred), 0, dl)
            partial |= pct < 100
            pages[cred] = {u for u in urls if urlsplit(u).hostname == ctx.host}
            other |= {u for u in urls + out if urlsplit(u).hostname not in (None, ctx.host)}
            reqs[cred] = []
            for m in zap.messages(ctx.url, before):
                line = (m.get("requestHeader") or "").split("\r\n", 1)[0].split(" ")
                if len(line) >= 2 and line[0].upper() != "GET":
                    r = safe_request(rc, line[0].upper(), line[1], dict(parse_qsl(m.get("requestBody") or "")))
                    if r:
                        reqs[cred].append(r)
            harvest(ctx, cred)  # passive alerts raised while crawling as this account
    finally:
        clear_quiet(zap)
    n = len(set().union(*pages.values())) if pages else 0
    detail = f"{n} pages found" + (f"; {len(other)} links to other hosts not tested" if other else "")
    if partial:
        return ModuleResult("completed-warnings", "Stopped at the time limit; " + detail, untested=len(other))
    return ModuleResult("completed", detail, untested=len(other))
