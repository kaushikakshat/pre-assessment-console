"""Deep only: imports the target's OpenAPI description into ZAP and actively scans the imported endpoints."""
import re
from urllib.parse import urljoin, urlsplit

from app.engine import zap as _zap

from .base import ModuleResult
from .crawl import context

COMMON = ("/openapi.json", "/swagger.json", "/v3/api-docs")


def _in_scope(ctx, url) -> bool:
    u = urlsplit(url)
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and u.hostname == ctx.host and port in ctx.permitted_ports


def run(ctx) -> ModuleResult:
    rc, zap = ctx.run_ctx, ctx.run_ctx["zap"]
    if rc.get("profile") != "deep":
        return ModuleResult("skipped", "API checks run in Deep Scan only")
    m = re.search(r"(?im)^\s*openapi:\s*(\S+)", rc.get("notes") or "")
    # shortcut: an explicit description outside the target is ignored (not an error); the common paths are then tried
    cands = [m.group(1)] if m and _in_scope(ctx, m.group(1)) else [urljoin(ctx.url, p) for p in COMMON]
    cid, found = context(ctx, None), None
    for url in cands:
        try:
            if zap.import_openapi(url, cid) > 0:
                found = url
                break
        except _zap.EngineError:  # this URL is not a readable description; try the next
            continue
    if not found:
        return ModuleResult("skipped", "No API description found")
    pct = zap.active_scan(ctx.url, cid, "pa-deep", ctx.deadline)
    seen, drafts = rc.setdefault("seen_alerts", set()), []
    for a in zap.alerts(ctx.url):
        key = a.get("id") or (a.get("pluginId"), a.get("url"), a.get("param"), a.get("method"))
        if key not in seen:
            seen.add(key)
            drafts.append(_zap.alert_to_draft(a, ctx))
    if pct < 100:
        return ModuleResult("completed-warnings", "Stopped at the time limit; some API endpoints were not tested", drafts, untested=1)
    return ModuleResult("completed", f"API endpoints tested; {len(drafts)} issues reported", drafts)
