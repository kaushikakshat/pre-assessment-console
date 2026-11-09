"""Active testing with the guarded ZAP engine, once per account context (policy pa-safe in Pre-Assessment, pa-deep in Deep)."""
import math
import time

from app.engine import zap as _zap

from .base import ModuleResult
from .crawl import accounts, as_account, clear_quiet, context, harvest

R = "[REDACTED]"


def emit(ctx) -> list:
    """Drafts for every harvested alert not yet reported; session cookie values are masked first."""
    rc, out = ctx.run_ctx, []
    secrets = {v.strip().partition("=")[2] for c in (rc.get("sessions") or {}).values() for v in c.split(";")}
    secrets = sorted((x for x in secrets if len(x) >= 4), key=len, reverse=True)
    for key, (cred, a) in rc.get("alerts", {}).items():
        if key in rc.setdefault("seen_alerts", set()):
            continue
        rc["seen_alerts"].add(key)
        a = dict(a)
        for k, v in a.items():
            for x in secrets:
                if isinstance(v, str):
                    v = v.replace(x, R)
            a[k] = v
        d = _zap.alert_to_draft(a, ctx)
        if cred:  # the same issue seen with another account is a separate finding
            d.credential_id, d.fingerprint_key = cred, f"{d.fingerprint_key}:{cred}"
        out.append(d)
    return out


def run(ctx) -> ModuleResult:
    rc, zap = ctx.run_ctx, ctx.run_ctx["zap"]
    policy = "pa-deep" if rc.get("profile") == "deep" else "pa-safe"
    drafts, untested, stopped, accts = [], 0, False, accounts(rc)
    try:
        for i, (cred, cookie) in enumerate(accts):
            n = len(rc.get("pages", {}).get(cred) or ()) or 1
            left = ctx.remaining()
            if left <= 0:
                stopped, untested = True, untested + n
                continue
            as_account(zap, cookie)
            pct = zap.active_scan(ctx.url, context(ctx, cred), policy, time.monotonic() + left / (len(accts) - i))
            if pct < 100:
                stopped, untested = True, untested + math.ceil(n * (100 - pct) / 100)
            harvest(ctx, cred)
    finally:
        clear_quiet(zap)
    drafts = emit(ctx)
    if stopped:
        return ModuleResult("completed-warnings", f"Stopped at the time limit; {untested} URLs not tested", drafts, untested=untested)
    return ModuleResult("completed", f"Active tests finished; {len(drafts)} issues reported", drafts)
