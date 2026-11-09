"""Control validation: re-requests each suspected finding from access and exposed with fresh sessions.
Reproduced -> run_ctx['confirmed'] gets (module, draft); the worker then marks the stored finding confirmed."""
from urllib.parse import urlsplit

from app.targets.safe_http import RequestCapExceeded

from . import access, auth, exposed
from .base import ModuleResult


def _repro(ctx, s, sessions) -> bool:
    rc, m, url = ctx.run_ctx, s["method"], s["url"]
    if s["module"] == "exposed":
        sig = exposed.SIGNATURES.get(urlsplit(url).path)
        r = access.probe(ctx, "GET", url, None)
        return bool(sig) and r.status_code == 200 and sig[0](r.content)
    base = access.probe(ctx, "GET", url, sessions[s["owner"]]) if m == "GET" else None
    return access.reached(rc, access.probe(ctx, m, url, sessions.get(s["who"]), s["form"]), base, url=url)


def run(ctx) -> ModuleResult:
    rc = ctx.run_ctx
    todo = rc.get("suspects") or []
    if not [s for s in todo if s.get("recheck", True)]:
        return ModuleResult("completed", "No suspected findings to re-check")
    sessions, _, _ = auth.login_all(ctx, ctx.deadline) if rc.get("accounts") and rc.get("login") else ({}, [], set())
    done, untested = [], 0
    todo = [s for s in todo if s.get("recheck", True)]  # state-changing replays are never re-fired or auto-confirmed
    for s in todo:
        need = [x for x in (s.get("owner"), s.get("who")) if x]
        if any(x not in sessions for x in need):
            untested += 1  # the account could not sign in again
            continue
        try:
            if _repro(ctx, s, sessions):
                s["draft"].confidence = "confirmed"
                done.append((s["module"], s["draft"]))
        except (TimeoutError, RequestCapExceeded):
            untested += len(todo) - todo.index(s)
            break
        except access.FAILS:
            untested += 1
    rc["confirmed"] = done
    detail = f"{len(done)} of {len(todo)} suspected finding(s) confirmed"
    return ModuleResult("completed-warnings" if untested else "completed", detail, untested=untested)
