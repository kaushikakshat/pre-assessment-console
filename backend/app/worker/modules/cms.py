"""WordPress, Drupal and Joomla detection, end-of-life core versions, WordPress plugins and vulnerable JS libraries."""
import re
from urllib.parse import urlsplit

import httpx

from app.targets.safe_http import BlockedAddress, RequestCapExceeded
from app.worker import advisories
from app.worker.redact import build_evidence

from .base import REFS, Blocked, FindingDraft, ModuleResult, location

_GEN = re.compile(r"""(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""")
_PLUGIN = re.compile(r"/wp-content/plugins/([A-Za-z0-9_-]+)/")
MAX_PAGES, MAX_PLUGINS = 15, 10
FAILS = (httpx.HTTPError, OSError, BlockedAddress)


def _try(ctx, path):
    try:
        r = ctx.get(path)
        return r if r.status_code == 200 else None
    except FAILS:
        return None


def _detect(ctx, home) -> tuple[str | None, str | None]:
    """-> (cms, version or None)."""
    text = home.text
    g = _GEN.search(text)
    gen = g.group(1) if g else ""
    if m := re.match(r"(?i)WordPress\s+([\d.]+)", gen):
        return "wordpress", m.group(1)
    if m := re.match(r"(?i)Drupal\s+([\d.]+)", gen):
        return "drupal", m.group(1)
    if gen.lower().startswith("joomla"):
        r = _try(ctx, "/administrator/manifests/files/joomla.xml")
        v = re.search(r"<version>([\d.]+)</version>", r.text) if r else None
        return "joomla", v.group(1) if v else None
    if (r := _try(ctx, "/readme.html")) and (m := re.search(r"(?is)WordPress.*?Version\s+([\d.]+)", r.text[:6000])):
        return "wordpress", m.group(1)
    if (r := _try(ctx, "/wp-json/")) and '"namespaces"' in r.text:
        return "wordpress", None
    if (r := _try(ctx, "/CHANGELOG.txt")) and (m := re.match(r"(?s)\s*Drupal\s+([\d.]+)", r.text)):
        return "drupal", m.group(1)
    return None, None


def run(ctx) -> ModuleResult:
    out, partial, blocked = [], False, False
    try:
        home = ctx.get()
        cms, ver = _detect(ctx, home)
        if cms:
            out.append(FindingDraft(
                "info", "confirmed", f"{cms.capitalize()} detected" + (f" (version {ver})" if ver else ""), ctx.host,
                location(ctx, "Software", component=cms), f"The site runs {cms.capitalize()}" + (f" {ver}." if ver else "."),
                "Attackers target the known weaknesses of widely used content management systems.",
                build_evidence("GET", ctx.url, home.status_code, home.headers, None), f"Run: curl -s {ctx.url} and look for the generator tag.",
                "Keep the CMS, themes and plugins updated and hide version details where possible.", [REFS["info"]]))
            if ver:
                for d in advisories.eol_findings(cms, ver):
                    d.asset, d.location = ctx.host, location(ctx, "Software", component=cms)
                    out.append(d)
        pages = [ctx.url, *sorted((ctx.run_ctx.get("pages") or {}).get(None, ()))][:MAX_PAGES + 1]
        bodies = {ctx.url: home}
        slugs = set(_PLUGIN.findall(home.text))
        for u in pages[1:]:
            try:
                r = ctx.client.get(u, deadline=ctx.deadline)
            except FAILS:
                continue
            if r.status_code == 200 and "html" in r.headers.get("content-type", "html").lower():
                bodies[u] = r
                slugs |= set(_PLUGIN.findall(r.text))
        for u, r in bodies.items():
            for d in advisories.js_library_findings(u, r.content):
                d.location.update(host=ctx.host, port=ctx.port, path=urlsplit(u).path)
                out.append(d)
        if cms == "wordpress":
            for slug in sorted(slugs)[:MAX_PLUGINS]:
                r = _try(ctx, f"/wp-content/plugins/{slug}/readme.txt")
                v = re.search(r"(?im)^Stable tag:\s*([\w.]+)", r.text) if r else None
                if v:
                    out.append(FindingDraft(
                        "info", "confirmed", f"WordPress plugin {slug} {v.group(1)} is installed", f"{ctx.host} plugin {slug}",
                        location(ctx, "Software", component=slug, path=f"/wp-content/plugins/{slug}/readme.txt"),
                        f"The plugin {slug} (version {v.group(1)}) is installed and its readme is public.",
                        "Plugins are a common entry point; the public readme tells attackers the exact version.",
                        build_evidence("GET", ctx.url.rstrip("/") + f"/wp-content/plugins/{slug}/readme.txt", 200, r.headers, None),
                        f"Run: curl -s {ctx.url.rstrip('/')}/wp-content/plugins/{slug}/readme.txt",
                        "Keep plugins updated, remove unused ones and block direct access to readme files.", [REFS["info"]]))
    except Blocked:
        blocked = True
    except RequestCapExceeded:
        partial = True
    note = f"Advisory data as of {advisories.AS_OF}"
    if blocked:
        return ModuleResult("inconclusive", f"Target rate-limited or blocked the requests. {note}", out)
    if partial:
        return ModuleResult("completed-warnings", f"Stopped at the request limit. {note}", out)
    return ModuleResult("completed", f"{len(out)} finding(s). {note}", out)
