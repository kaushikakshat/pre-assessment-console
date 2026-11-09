"""Cross-account and unauthenticated replays (own requests only, through SafeClient, never ZAP).
A page or action only one account could reach is requested as every other account and as a visitor; a 2xx that is
not the login page and (for pages) looks like the owner's copy is a suspected finding.
shortcut: recorded state-changing requests have no stored owner response, so they are judged on the response alone
(no error marker, or a redirect away from login), reported medium/suspected and never auto-confirmed by cval."""
import re
from urllib.parse import unquote, urlencode, urljoin, urlsplit

import httpx

from app.engine import stages  # module import: read at call time (zap -> modules.base cycle)
from app.targets.safe_http import BlockedAddress, RequestCapExceeded
from app.worker.redact import build_evidence, redact
from app.worker.similarity import SAME, same_page

from . import auth
from .base import REFS, FindingDraft, ModuleResult, location, looks_blocked

_LOGIN_FORM = re.compile(r"(?i)<input[^>]+type\s*=\s*[\"']?password")
_DENIED = re.compile(r"(?i)forbidden|not allowed|no permission|access denied|unauthori[sz]ed|invalid (csrf|token|request)"
                     r"|csrf token|session (has )?expired|please log ?in|is required")
_HIDDEN = re.compile(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->|<input[^>]*type\s*=\s*[\"']?hidden[^>]*>")
_FORM = re.compile(r"(?is)<form\b([^>]*)>")
_LOGIN_LOC = re.compile(r"(?i)log-?in|sign-?in|/auth")
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


def visible(text) -> str:
    """What a person sees first: the title plus the first 1,500 characters of text (no tags, attributes, scripts, hidden inputs)."""
    t = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    body = re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", _HIDDEN.sub(" ", text)))
    return (t.group(1) if t else "") + " " + body[:1500]


def denied(text) -> bool:
    return bool(_DENIED.search(visible(text)))


def logged_out(rc, r, url=None) -> bool:
    """The login page: the logged-out marker, or a password form that posts to the login URL (a change-password page is not it)."""
    lo, login = rc.get("logged_out"), (rc.get("login") or {}).get("login_url")
    if lo and lo in r.text:
        return True
    if not _LOGIN_FORM.search(r.text) or not login:
        return False
    for attrs in _FORM.findall(r.text):
        m = re.search(r"""(?i)action\s*=\s*["']?([^"'\s>]*)""", attrs)
        target = urljoin(url or login, m.group(1)) if m and m.group(1) else (url or "")
        if urlsplit(target).path == urlsplit(login).path:
            return True
    return False


def reached(rc, r, base=None, method="GET", url=None) -> bool:
    """GET: 2xx, not the login page, no denial the owner's copy lacks, similar size and content.
    Other methods (no owner copy): a redirect away from login, or a 2xx without any error marker."""
    if method != "GET":
        if 300 <= r.status_code < 400:
            return not _LOGIN_LOC.search(r.headers.get("location", ""))
        return 200 <= r.status_code < 300 and not logged_out(rc, r, url) and not denied(r.text)
    if not 200 <= r.status_code < 300 or logged_out(rc, r, url):
        return False
    if base is None:
        return not denied(r.text)
    if not base.content.strip() or len(r.content) < 0.5 * len(base.content):
        return False
    if denied(r.text) and not denied(base.text):
        return False
    return same_page(base.content, r.content) >= SAME


def scrub(text, secret):
    """Account secrets out of echoed page content: case-insensitive; values under 3 chars only as whole tokens."""
    for v in sorted(secret, key=len, reverse=True):
        rx = re.escape(v) if len(v) >= 3 else rf"(?<![\w]){re.escape(v)}(?![\w])"
        text = re.sub(rx, REDACTED, text, flags=re.I)
    return text


_KEEP = re.compile(r"[A-Z]+ https?://|recorded as ")  # request lines carry the URL, not page content


def scrub_evidence(ev, secret):
    return "\n".join(ln if _KEEP.match(ln) else scrub(ln, secret) for ln in ev.split("\n"))


def run(ctx) -> ModuleResult:
    rc = ctx.run_ctx
    sessions, pages, reqs, roles = rc.get("sessions") or {}, rc.get("pages") or {}, rc.get("requests") or {}, rc.get("roles") or {}
    if not sessions:
        return ModuleResult("skipped", "No signed-in accounts to compare")
    secret = auth.secrets(rc)
    role = lambda c: roles.get(c, c) if c else None  # noqa: E731
    shared = set.intersection(*(set(pages.get(k, ())) for k in [None, *sessions])) if pages else set()
    tasks, untested, lost = [], 0, 0  # (owner, method, url, form)
    for a in list(sessions):
        tasks += [(a, "GET", u, None) for u in sorted(set(pages.get(a, ())) - shared) if not excluded(rc, u)]
        for m, u, form in reqs.get(a, []):
            if excluded(rc, u):
                continue
            if REDACTED in unquote(u) or "%5BREDACTED%5D" in u.upper() or form == "[REDACTED BODY]" or (
                    isinstance(form, dict) and any(REDACTED in str(v) for v in form.values())):
                untested += 1  # replaying it would send masked values
            else:
                tasks.append((a, m, u, form))
    out, seen, state, detail, left = [], set(), "completed", "", 0
    for n, (a, m, url, form) in enumerate(tasks):
        if a not in sessions or a in rc.get("excluded", ()):
            untested += 1
            continue
        bs = [c for c in sessions if c != a and c not in rc.get("excluded", ())] + [None]
        bs = [b for b in bs if url not in set(pages.get(b, ())) and not (m != "GET" and (m, url) in {(x, y) for x, y, _ in reqs.get(b, [])})]
        i = 0
        try:
            base = probe(ctx, "GET", url, sessions[a]) if m == "GET" else None
            if m == "GET" and not reached(rc, base, url=url):
                if logged_out(rc, base, url):  # the owner's session ended: this task is untested, try one fresh sign-in
                    untested, lost = untested + max(1, len(bs)), lost + 1
                    if auth.relogin(ctx, a):
                        sessions[a] = rc["sessions"][a]
                    else:
                        sessions.pop(a, None)
                continue
            for i, b in enumerate(bs):
                r = probe(ctx, m, url, sessions.get(b), form)
                if not reached(rc, r, base, m, url) or (b, url, m) in seen:
                    continue
                seen.add((b, url, m))
                title = f"{role(b)} can open a page meant for {role(a)}" if b else "Page reachable without signing in"
                if m != "GET":
                    title = f"{role(b)} can repeat an action meant for {role(a)}" if b else "Action reachable without signing in"
                ev = "\n\n".join(build_evidence(m, url, x.status_code, x.headers, x.content, ("content-type",), 10)
                                 for x in ((base, r) if base else (r,)))
                if not base:
                    ev = redact(f"{m} {url}\nrecorded as {role(a)}; replayed as {role(b) or 'a visitor'}\n\n" + ev)
                d = FindingDraft(
                    "high" if m == "GET" else "medium", "suspected", title, url,
                    location(ctx, "Page" if m == "GET" else "Action", method=m, url=url),
                    f"{url} was opened by {'a visitor' if b is None else role(b)} although only {role(a)} reaches it in the crawl.",
                    "Someone without the right role may read data or perform actions meant for another role.",
                    ev, f"Sign in as {role(b) or 'no one'} and {m} {url}", "Check the access rule on the server for this page or action.",
                    [REFS["info"]], fingerprint_key=f"{m}|{url}|{b}")
                d.evidence = scrub_evidence(d.evidence, secret)  # description/impact are generated from URL and role only
                out.append(d)
                rc.setdefault("suspects", []).append({"module": "access", "draft": d, "method": m, "url": url, "form": form,
                                                      "owner": a, "who": b, "recheck": m == "GET"})
        except TimeoutError:
            state, detail, left = "completed-warnings", "Stopped at the time limit", len(tasks) - n
            break
        except RequestCapExceeded:
            state, detail, left = "completed-warnings", "Stopped at the request limit", len(tasks) - n
            break
        except FAILS:
            untested += max(1, len(bs) - i)  # this and every later replay of the task
    untested += left
    if lost:
        state, detail = "completed-warnings", (detail + "; " if detail else "") + f"{lost} session(s) ended mid-run"
    if state == "completed" and untested:
        state, detail = "completed-warnings", f"{untested} replay(s) could not be tested"
    return ModuleResult(state, f"{detail}; {len(out)} suspected finding(s)" if detail else f"Replayed {len(tasks)} item(s); {len(out)} suspected finding(s)",
                        out, untested=untested)
