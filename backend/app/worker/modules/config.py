"""Configuration checks: CORS, cookie flags on crawled responses, directory listing, TRACE and mixed content."""
import re
from urllib.parse import urlsplit

import httpx

from app.targets.safe_http import BlockedAddress, RequestCapExceeded
from app.worker.redact import build_evidence, redact

from .access import excluded
from .base import REFS, Blocked, FindingDraft, ModuleResult, location, looks_blocked
from .headers import cookie_findings

EVIL = "https://evil.example"
MAX_PAGES = 30
_MIXED = re.compile(r"(?is)<(?:(?:script|img|iframe|audio|video|source)\b[^>]*?\bsrc|link\b(?=[^>]*\brel\s*=\s*[\"']?(?:stylesheet|icon|preload))[^>]*?\bhref)\s*=\s*[\"']?(http://[^\"'\s>]+)")
FAILS = (httpx.HTTPError, OSError, BlockedAddress)
CORS_REF = "https://developer.mozilla.org/docs/Web/HTTP/CORS"


def _draft(ctx, sev, title, kind, url, desc, impact, evidence, how, fix, ref, component=None, method="GET", confidence="confirmed"):
    return FindingDraft(sev, confidence, title, urlsplit(url).netloc + urlsplit(url).path if kind == "Web page" else ctx.host,
                        location(ctx, kind, url=url, path=urlsplit(url).path, component=component, method=method),
                        desc, impact, evidence, how, fix, [ref])


def _fetch(ctx, url, cookie=None, method="GET", headers=None):
    h = {**({"Cookie": cookie} if cookie else {}), **(headers or {})}
    r = ctx.client.request(method, url, headers=h, deadline=ctx.deadline)
    if looks_blocked(r):
        raise Blocked
    return r


def _cors(ctx):
    r = _fetch(ctx, ctx.url, headers={"Origin": EVIL})
    acao, acac = r.headers.get("access-control-allow-origin", ""), r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acac and acao == EVIL:
        sev, title, why = "high", "CORS reflects any origin and allows credentials", \
            "The site copies any requesting origin into Access-Control-Allow-Origin and allows credentials."
        impact = "A malicious site could read signed-in users' data from this site in their browsers."
    elif acac and acao == "*":
        sev, title, why = "medium", "CORS allows every origin together with credentials", \
            "The site answers Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true."
        impact = ("Browsers refuse credentialed requests to a wildcard origin, so this is not directly exploitable, "
                  "but it shows an unsafe policy that becomes serious if the site later reflects origins.")
    else:
        return []
    return [_draft(ctx, sev, title, "Response header", ctx.url, why,
                   impact,
                   build_evidence("GET", ctx.url, r.status_code, r.headers, None,
                                  ("access-control-allow-origin", "access-control-allow-credentials")) + f"\nRequest Origin: {EVIL}",
                   f"Run: curl -sI -H 'Origin: {EVIL}' {ctx.url} and read the Access-Control headers.",
                   "Allow only a fixed list of trusted origins and never combine credentials with a reflected or wildcard origin.",
                   CORS_REF, component="access-control-allow-origin")]


def run(ctx) -> ModuleResult:
    out, seen, blocked, partial, failed = [], set(), False, False, 0
    rc = ctx.run_ctx
    # (url, cookie) for every crawled page, anonymous first; sessions are Cookie header values and never reach evidence
    targets = [(ctx.url, None)]
    for cred, urls in (rc.get("pages") or {}).items():
        targets += [(u, (rc.get("sessions") or {}).get(cred)) for u in sorted(urls) if u != ctx.url and not excluded(rc, u)]
    try:
        out += _cors(ctx)
        for url, cookie in targets[:MAX_PAGES]:
            try:
                r = _fetch(ctx, url, cookie)
            except FAILS:
                failed += 1
                continue
            for d in cookie_findings(ctx, r, url):
                if d.title not in seen:
                    seen.add(d.title)
                    out.append(d)
            if r.status_code != 200:
                continue
            text = r.text
            if re.search(r"(?i)<title>\s*Index of\b", text) and ("dir", url) not in seen:
                seen.add(("dir", url))
                out.append(_draft(ctx, "medium", f"Directory listing is enabled: {urlsplit(url).path or '/'}", "Web page", url,
                                  "The server shows the list of files in this folder.", "Visitors can find files that were never meant to be linked, such as backups.",
                                  build_evidence("GET", url, 200, r.headers, r.content, ("content-type",), max_lines=6),
                                  f"Open {url} and note the file list.", "Turn off automatic directory indexes in the web server.", REFS["exposed"]))
            if urlsplit(url).scheme == "https" and (m := _MIXED.search(text)) and ("mixed", url) not in seen:
                seen.add(("mixed", url))
                out.append(_draft(ctx, "low", f"Page loads content over plain HTTP: {urlsplit(url).path or '/'}", "Web page", url,
                                  "This HTTPS page loads a resource from an http address.", "Anyone on the network can change that resource and so alter the page.",
                                  redact(f"GET {url}\nHTTP 200\nInsecure resource: {m.group(1)}"), f"Open {url} and look for http:// addresses in the page source.",
                                  "Load every resource over HTTPS.", REFS["hsts"], confidence="suspected"))  # the resource itself is not requested
        try:
            t = _fetch(ctx, ctx.url, method="TRACE")
            if t.status_code == 200 and b"TRACE" in t.content[:200]:
                out.append(_draft(ctx, "low", "HTTP TRACE method is enabled", "Network service", ctx.url,
                                  "The server answers TRACE requests by echoing them back.",
                                  "Echoed requests can help attackers read headers that scripts should not see.",
                                  build_evidence("TRACE", ctx.url, 200, t.headers, None, ("content-type",)),
                                  f"Run: curl -X TRACE -i {ctx.url}", "Disable the TRACE method in the web server.", CORS_REF, method="TRACE"))
        except (Blocked, *FAILS):
            pass  # a WAF or error on TRACE says nothing about the other checks
    except Blocked:
        blocked = True
    except RequestCapExceeded:
        partial = True
    if blocked:
        return ModuleResult("inconclusive", "Target rate-limited or blocked the requests", out)
    if partial:
        return ModuleResult("completed-warnings", "Stopped at the request limit", out)
    if failed:
        return ModuleResult("completed-warnings", f"{failed} page request(s) failed and were not checked.", out)
    return ModuleResult("completed", f"Checked {min(len(targets), MAX_PAGES)} page(s); {len(out)} issue(s) found.", out)
