import re

import httpx

from app.targets.safe_http import BlockedAddress
from app.worker.redact import build_evidence, redact

from .base import REFS, FindingDraft, ModuleResult, location

_ENV = re.compile(rb"(?m)^[A-Z_]+=")
_HTPASSWD = re.compile(rb":\$apr1\$|:\{SHA\}")
# path: (matcher on bytes, severity, what it is, show body?)
SIGNATURES = {
    "/.git/HEAD": (lambda b: b.startswith(b"ref:"), "high", "Git repository metadata", True),
    "/.env": (lambda b: bool(_ENV.search(b)), "high", "Environment file", True),
    "/server-status": (lambda b: b"Apache Server Status" in b, "medium", "Apache status page", False),
    "/phpinfo.php": (lambda b: b"phpinfo()" in b, "medium", "PHP information page", False),
    "/.DS_Store": (lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), "low", "macOS directory listing file", False),
    "/backup.zip": (lambda b: b.startswith(b"PK\x03\x04"), "high", "Backup archive", False),
    "/backup.sql": (lambda b: b"CREATE TABLE" in b, "high", "Database backup", False),
    "/config.php.bak": (lambda b: b"<?php" in b, "high", "Configuration backup", False),
    "/.svn/entries": (lambda b: len(b) > 0 and b[:1].isdigit(), "medium", "Subversion metadata", True),
    "/wp-config.php.bak": (lambda b: b"DB_PASSWORD" in b or b"<?php" in b, "high", "WordPress configuration backup", False),
    "/.htpasswd": (lambda b: bool(_HTPASSWD.search(b)), "high", "Password file", False),
    "/web.config": (lambda b: b"<configuration" in b, "medium", "Web server configuration", False),
    "/composer.json": (lambda b: b'"require"' in b, "low", "PHP dependency list", True),
    "/package.json": (lambda b: b'"dependencies"' in b, "low", "JavaScript dependency list", True),
}
SECURITY_TXT = "/.well-known/security.txt"


def run(ctx) -> ModuleResult:
    out, errors = [], 0
    for path, (match, sev, what, show) in SIGNATURES.items():
        try:
            r = ctx.get(path)
        except (httpx.HTTPError, OSError, TimeoutError, BlockedAddress):
            errors += 1
            continue
        if r.status_code != 200 or not match(r.content):  # 200 without the signature is a soft-404
            continue
        body = r.content if show else None
        ev = build_evidence("GET", ctx.url.rstrip("/") + path, 200, r.headers, body, ("content-type", "content-length"))
        if path == "/.env":  # values are secrets whatever their key name
            ev = re.sub(r"(?m)^([A-Z_]+)=.*$", r"\1=[REDACTED]", ev)
        if not show:
            ev += "\n\nResponse body not stored, to avoid keeping sensitive content."
        out.append(FindingDraft(
            sev, "confirmed", f"{what} is publicly readable: {path}", f"{ctx.host}{path}",
            location(ctx, "File", path=path, method="GET", url=ctx.url.rstrip("/") + path),
            f"The file {path} ({what.lower()}) can be downloaded without signing in.",
            "Anyone can read it. It may reveal source code, credentials or internal structure.",
            redact(ev), f"Run: curl -s {ctx.url.rstrip('/')}{path}",
            "Remove the file from the web root or block access to it, then rotate any secrets it contained.",
            [REFS["exposed"]]))
    try:
        r = ctx.get(SECURITY_TXT)
        has = r.status_code == 200 and b"Contact:" in r.content
    except (httpx.HTTPError, OSError, TimeoutError, BlockedAddress):
        errors, has = errors + 1, True  # unknown: do not claim it is missing
    if not has:
        out.append(FindingDraft(
            "info", "confirmed", "No security.txt file is published", f"{ctx.host}{SECURITY_TXT}",
            location(ctx, "File", path=SECURITY_TXT, method="GET", url=ctx.url.rstrip("/") + SECURITY_TXT),
            "The site does not publish a security.txt file saying how to report vulnerabilities.",
            "Researchers and colleagues may not know whom to tell about a problem.",
            f"GET {ctx.url.rstrip('/')}{SECURITY_TXT}\nHTTP {r.status_code}", f"Run: curl -sI {ctx.url.rstrip('/')}{SECURITY_TXT}",
            "Publish /.well-known/security.txt with a Contact line (RFC 9116).", ["https://www.rfc-editor.org/rfc/rfc9116"]))
    n = len(SIGNATURES) + 1
    if errors >= n:
        raise OSError("every request failed")
    if errors:
        return ModuleResult("completed-warnings", f"{errors} of {n} checks could not be completed.", out)
    return ModuleResult("completed", f"Checked {n} common paths; {len(out)} finding(s).", out)
