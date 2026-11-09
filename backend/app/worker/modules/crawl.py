"""Spider the target unauthenticated and once per signed-in account (inventory only, no findings).
run_ctx contract (shared with the access module): sessions {credential display id: Cookie header value} comes from
the login step; this module writes pages {id|None: set of URLs} and requests {id|None: [(method, url, form dict)]}."""
import re
import time
from urllib.parse import parse_qsl, urlsplit

from app.engine import zap as _zap  # module import: zap imports modules.base, so names are read at call time

from .base import ModuleResult


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
                    reqs[cred].append((line[0].upper(), line[1], dict(parse_qsl(m.get("requestBody") or ""))))
    finally:
        zap.clear_headers()
    n = len(set().union(*pages.values())) if pages else 0
    detail = f"{n} pages found" + (f"; {len(other)} links to other hosts not tested" if other else "")
    if partial:
        return ModuleResult("completed-warnings", "Stopped at the time limit; " + detail, untested=len(other))
    return ModuleResult("completed", detail, untested=len(other))
