"""Cross-account and unauthenticated replays (own requests only, through SafeClient, never ZAP).
A page or action only one account could reach is requested as every other account and as a visitor; a 2xx that is
not the login page and (for pages) looks like the owner's copy is a suspected finding.
shortcut: recorded state-changing requests have no stored owner response, so they are judged on 2xx + not login/denied."""
import re
from urllib.parse import urlencode

import httpx

from app.engine import stages  # module import: read at call time (zap -> modules.base cycle)
from app.targets.safe_http import BlockedAddress, RequestCapExceeded
from app.worker.redact import build_evidence, redact
from app.worker.similarity import SAME, same_page

from . import auth
from .base import REFS, FindingDraft, ModuleResult, location, looks_blocked

_LOGIN_FORM = re.compile(r"(?i)<input[^>]+type\s*=\s*[\"']?password")
_DENIED = re.compile(r"(?i)forbidden|access denied|not authori[sz]ed|permission denied|not allowed")
REDACTED = "[REDACTED]"
FAILS = (httpx.HTTPError, OSError, BlockedAddress)


def excluded(rc, url) -> bool:
    return any(re.fullmatch(x, url) for x in [stages.NEVER, *rc.get("exclude", [])])


def probe(ctx, method, url, cookie, form=None):
    h = {"Cookie": cookie} if cookie else {}
    body = None
    if form is not None:
        body, h["Content-Type"] = urlencode(form).encode(), "application/x-www-form-urlencoded"
    r = ctx.client.request(method, url, headers=h, deadline=ctx.deadline, data=body)
    if looks_blocked(r):
        raise OSError("blocked")
    return r


def reached(rc, r, base=None) -> bool:
    """2xx, not the logged-out page, and (with a baseline) the same content the owner sees."""
    if not 200 <= r.status_code < 300 or (base is not None and not base.content.strip()):
        return False
    lo = rc.get("logged_out")
    if (lo and lo in r.text) or _LOGIN_FORM.search(r.text):
        return False
    if base is None:
        return not _DENIED.search(r.text)
    return same_page(base.content, r.content) >= SAME


def _scrub(text, secret):
    for s in secret:
        text = text.replace(s, REDACTED)
    return text


def run(ctx) -> ModuleResult:
    rc = ctx.run_ctx
    sessions, pages, reqs, roles = rc.get("sessions") or {}, rc.get("pages") or {}, rc.get("requests") or {}, rc.get("roles") or {}
    if len(sessions) < 1:
        return ModuleResult("skipped", "No signed-in accounts to compare")
    secret = auth.secrets(rc)
    role = lambda c: roles.get(c, c) if c else None  # noqa: E731
    shared = set.intersection(*(set(pages.get(k, ())) for k in [None, *sessions])) if pages else set()
    tasks, untested = [], 0  # (owner, method, url, form)
    for a in sessions:
        tasks += [(a, "GET", u, None) for u in sorted(set(pages.get(a, ())) - shared) if not excluded(rc, u)]
        for m, u, form in reqs.get(a, []):
            if excluded(rc, u):
                continue
            if form == "[REDACTED BODY]" or (isinstance(form, dict) and REDACTED in form.values()):
                untested += 1  # replaying it would send masked values
            else:
                tasks.append((a, m, u, form))
    out, seen, state, detail, left = [], set(), "completed", "", 0
    for n, (a, m, url, form) in enumerate(tasks):
        try:
            base = probe(ctx, "GET", url, sessions[a]) if m == "GET" else None
            if m == "GET" and not reached(rc, base):
                continue  # the owner's own copy is not a page worth comparing
            for b in [c for c in sessions if c != a] + [None]:
                if m != "GET" and (m, url) in {(x, y) for x, y, _ in reqs.get(b, [])}:
                    continue  # B legitimately makes this request too
                r = probe(ctx, m, url, sessions.get(b), form)
                if not reached(rc, r, base) or (b, url, m) in seen:
                    continue
                seen.add((b, url, m))
                title = f"{role(b)} can open a page meant for {role(a)}" if b else "Page reachable without signing in"
                ev = "\n\n".join(_scrub(build_evidence(m, url, x.status_code, x.headers, x.content, ("content-type",), 10), secret)
                                 for x in ((base, r) if base else (r,)))
                if not base:
                    ev = redact(f"{m} {url}\nrecorded as {role(a)}; replayed as {role(b) or 'a visitor'}\n\n" + ev)
                out.append(FindingDraft(
                    "high", "suspected", title, url, location(ctx, "Page" if m == "GET" else "Action", method=m, url=url),
                    f"{url} was opened by {'a visitor' if b is None else role(b)} although only {role(a)} reaches it in the crawl.",
                    "Someone without the right role may read data or perform actions meant for another role.",
                    ev, f"Sign in as {role(b) or 'no one'} and {m} {url}", "Check the access rule on the server for this page or action.",
                    [REFS["info"]]))
                rc.setdefault("suspects", []).append({"module": "access", "draft": out[-1], "method": m, "url": url,
                                                      "form": form, "owner": a, "who": b})
        except TimeoutError:
            state, detail, left = "completed-warnings", "Stopped at the time limit", len(tasks) - n
            break
        except RequestCapExceeded:
            state, detail, left = "completed-warnings", "Stopped at the request limit", len(tasks) - n
            break
        except FAILS:
            untested += 1
    untested += left
    if state == "completed" and untested:
        state, detail = "completed-warnings", f"{untested} replay(s) could not be tested"
    return ModuleResult(state, f"{detail}; {len(out)} suspected finding(s)" if detail else f"Replayed {len(tasks)} item(s); {len(out)} suspected finding(s)",
                        out, untested=untested)
