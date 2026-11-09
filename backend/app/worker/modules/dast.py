"""Active testing with the guarded ZAP engine, once per account context (policy pa-safe in Pre-Assessment, pa-deep in Deep)."""
import math
import time

from app.engine import zap as _zap

from .base import ModuleResult
from .crawl import accounts, as_account, context


def run(ctx) -> ModuleResult:
    rc, zap = ctx.run_ctx, ctx.run_ctx["zap"]
    policy, seen = ("pa-deep" if rc.get("profile") == "deep" else "pa-safe"), rc.setdefault("seen_alerts", set())
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
            for a in zap.alerts(ctx.url):
                key = a.get("id") or (a.get("pluginId"), a.get("url"), a.get("param"), a.get("method"))
                if key in seen:
                    continue
                seen.add(key)
                d = _zap.alert_to_draft(a, ctx)
                if cred:  # the same issue seen with another account is a separate finding
                    d.credential_id, d.fingerprint_key = cred, f"{d.fingerprint_key}:{cred}"
                drafts.append(d)
    finally:
        zap.clear_headers()
    if stopped:
        return ModuleResult("completed-warnings", f"Stopped at the time limit; {untested} URLs not tested", drafts, untested=untested)
    return ModuleResult("completed", f"Active tests finished; {len(drafts)} issues reported", drafts)
