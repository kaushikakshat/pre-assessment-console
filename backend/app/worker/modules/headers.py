from urllib.parse import urlsplit

from app.worker.redact import build_evidence

from .base import REFS, FindingDraft, ModuleResult, location

SHOW = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
        "referrer-policy", "set-cookie")
# (header, severity, title, why it matters, fix, ref)
CHECKS = [
    ("strict-transport-security", "medium", "Strict-Transport-Security header is missing",
     "Browsers are not told to always use HTTPS for this site.",
     "Attackers on the network can downgrade a visit to plain HTTP and read or change it.",
     "Send Strict-Transport-Security with a long max-age, for example max-age=31536000; includeSubDomains.", "hsts"),
    ("content-security-policy", "medium", "Content-Security-Policy header is missing",
     "The site does not restrict where scripts and other content can load from.",
     "A cross-site scripting flaw is easier to exploit and harder to contain.",
     "Add a Content-Security-Policy that allows only the sources the site needs.", "csp"),
    ("x-frame-options", "low", "Clickjacking protection is missing",
     "Neither X-Frame-Options nor a CSP frame-ancestors rule stops other sites from framing these pages.",
     "Another site could embed the page and trick users into clicking hidden controls.",
     "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.", "xfo"),
    ("x-content-type-options", "low", "X-Content-Type-Options header is missing",
     "Browsers may guess a response's content type instead of trusting the declared one.",
     "Uploaded or reflected content could be run as a script.",
     "Send X-Content-Type-Options: nosniff.", "xcto"),
    ("referrer-policy", "info", "Referrer-Policy header is missing",
     "The browser decides how much of the page address to send to other sites.",
     "Internal paths or identifiers in URLs can leak to third parties.",
     "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.", "referrer"),
]


def _missing(h, name, csp):
    if name == "strict-transport-security":
        return name not in h
    if name == "x-frame-options":
        return name not in h and "frame-ancestors" not in csp
    if name == "x-content-type-options":
        return h.get(name, "").lower() != "nosniff"
    return name not in h


def cookie_findings(ctx, r, url) -> list:
    """Cookie flag findings for one response (also used by config on every crawled page)."""
    h, https, out = r.headers, urlsplit(url).scheme == "https", []
    for raw in h.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name, attrs = parts[0].split("=", 1)[0].strip(), {p.split("=", 1)[0].lower() for p in parts[1:]}
        miss = [f for f, bad in (("Secure", https and "secure" not in attrs), ("HttpOnly", "httponly" not in attrs),
                                 ("SameSite", "samesite" not in attrs)) if bad]
        if miss:
            sev = "medium" if set(miss) & {"Secure", "HttpOnly"} else "low"
            out.append(FindingDraft(sev, "confirmed", f"Cookie {name} is missing security flags",
                                    f"{ctx.host} cookie {name}", location(ctx, "Cookie", component=name, method="GET"),
                                    f"The cookie {name} is set without: {', '.join(miss)}.",
                                    "The cookie can be read by scripts, sent over plain HTTP or sent with cross-site requests.",
                                    build_evidence("GET", url, r.status_code, h, None, ()) + f"\nSet-Cookie: {name}=[REDACTED]; flags missing: {', '.join(miss)}",
                                    f"Run: curl -sI {url} and inspect the Set-Cookie headers.",
                                    "Set Secure (HTTPS only), HttpOnly and SameSite=Lax or Strict on the cookie.",
                                    [REFS["cookies"]]))
    return out


def run(ctx) -> ModuleResult:
    r = ctx.get()
    h, csp, https = r.headers, r.headers.get("content-security-policy", "").lower(), ctx.scheme == "https"
    out = []
    for name, sev, title, desc, impact, fix, ref in CHECKS:
        if (name == "strict-transport-security" and not https) or not _missing(h, name, csp):
            continue
        out.append(FindingDraft(sev, "confirmed", title, ctx.host, location(ctx, "Response header", component=name,
                                method="GET"), desc, impact, build_evidence("GET", ctx.url, r.status_code, h, None, SHOW),
                                f"Run: curl -sI {ctx.url} and look for the {name} header.", fix, [REFS[ref]]))
    out += cookie_findings(ctx, r, ctx.url)
    return ModuleResult("completed", f"Checked response headers and cookies; {len(out)} issue(s) found.", out)
