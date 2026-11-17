"""Vendored SecLists catalog (Discovery/ and Fuzzing/ only) and the request-count estimate."""
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.engine import stages
from app.models import Wordlist
from app.targets.safe_http import BlockedAddress, RequestCapExceeded
from app.worker.redact import build_evidence, redact
from app.worker.similarity import SAME, same_page

from .access import excluded
from .base import REFS, Blocked, FindingDraft, location, looks_blocked
from .crawl import SECRET_FIELD, SENSITIVE_PATH

ROOT = Path(os.environ.get("SECLISTS_DIR", "/opt/vendor/seclists"))


def seed(db, root: Path = ROOT) -> int:
    """Upsert one row per vendored file; keeps an admin's enabled flag. No tree (dev/test) -> no rows."""
    files = [p for p in sorted(root.rglob("*")) if root.is_dir() and p.is_file()
             and p.relative_to(root).parts[0] in ("Discovery", "Fuzzing")]
    # shortcut: the tree is immutable per image, so a matching row count means already seeded (no line counting
    # at startup); a changed SecLists commit changes the file set. Upgrade to a stored commit marker if that stops holding.
    if len(files) == db.scalar(select(func.count()).select_from(Wordlist).where(Wordlist.key.in_(
            [p.relative_to(root).as_posix() for p in files]))) and db.scalar(select(func.count()).select_from(Wordlist)) == len(files):
        return 0
    n = 0
    for p in files:
        rel = p.relative_to(root)
        with p.open("rb") as f:
            lines = sum(1 for _ in f)
        db.execute(insert(Wordlist).values(key=rel.as_posix(), category=rel.parts[0].lower(), label=p.stem, lines=lines)
                   .on_conflict_do_update(index_elements=["key"], set_={"lines": lines, "label": p.stem}))
        n += 1
    db.commit()
    return n


def estimate(db, keys, forms=10) -> int:
    """Requests a selection needs: discovery lists once, fuzzing lists once per form."""
    rows = db.scalars(select(Wordlist).where(Wordlist.key.in_(list(keys)))).all()
    return sum(w.lines * (forms if w.category == "fuzzing" else 1) for w in rows)


def read(key: str, root: Path = None) -> list[str]:
    """Entries of one vendored list by catalogue key. Never leaves the vendored Discovery/ and Fuzzing/ trees."""
    root = (root or ROOT).resolve()
    p = (root / key).resolve()
    if ".." in key.split("/") or key.startswith("/") or "\\" in key or root not in p.parents \
            or p.relative_to(root).parts[0] not in ("Discovery", "Fuzzing") or not p.is_file():
        raise ValueError("Unknown wordlist")
    return [ln for ln in p.read_text("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("#")]


class Throttle:
    def __init__(self, rate_per_s):
        self.gap, self.next = 1 / max(1, rate_per_s or 10), 0.0

    def wait(self, deadline):
        now = time.monotonic()
        if self.next > now:
            if self.next > deadline:
                raise TimeoutError("Time budget exhausted")
            time.sleep(self.next - now)
        self.next = max(now, self.next) + self.gap


def _rate(ctx) -> int:
    return ctx.run_ctx.get("rate_per_s") or 10


def discover(ctx, keys):
    """Paths from Discovery/ lists. -> (drafts, status, untested) with status 'ok' | 'blocked' | 'stopped'."""
    paths = list(dict.fromkeys("/" + ln.strip().lstrip("/") for k in keys if k.startswith("Discovery/") for ln in read(k)))
    paths = [p for p in paths if not excluded(ctx.run_ctx, urljoin(ctx.url, p))]  # excluded: not requested, not untested
    base_path = "/" + secrets.token_hex(8)
    try:
        baseline = ctx.get(base_path)
    except Blocked:
        return [], "blocked", len(paths)
    except (httpx.HTTPError, OSError, BlockedAddress, TimeoutError, RequestCapExceeded):
        return [], "stopped", len(paths)
    out, th, errors = [], Throttle(_rate(ctx)), 0
    for i, path in enumerate(paths):
        try:
            th.wait(ctx.deadline)
            r = ctx.get(path)
        except Blocked:
            return out, "blocked", len(paths) - i
        except (TimeoutError, RequestCapExceeded):
            return out, "stopped", len(paths) - i
        except (httpx.HTTPError, OSError, BlockedAddress):
            errors += 1
            continue
        if r.status_code not in (200, 401, 403):
            continue
        if r.status_code == baseline.status_code and same_page(baseline.content, r.content) >= SAME:
            continue  # soft 404: the site answers unknown paths like this
        url = ctx.url.rstrip("/") + path
        sev = "low" if r.status_code == 200 else "info"
        out.append(FindingDraft(
            sev, "suspected", f"Path found by wordlist: {path} (HTTP {r.status_code})", f"{ctx.host}{path}",
            location(ctx, "File", path=path, method="GET", url=url),
            f"The path {path} answers with HTTP {r.status_code} while an unknown path does not.",
            "Unlinked pages and files may expose administration tools or internal content.",
            build_evidence("GET", url, r.status_code, r.headers, None, ("content-type", "content-length")),
            f"Run: curl -sI {url}", "Remove the path from the web root or restrict access to it.", [REFS["exposed"]]))
    return out, "ok", 0


SQL_ERR = re.compile(r"(?i)you have an error in your sql syntax|warning: mysqli?_|ORA-\d{5}|unclosed quotation mark|"
                     r"pg_query\(\)|psycopg2?\.errors|sqlite3?\.operationalerror|SQLSTATE\[|syntax error at or near|"
                     r"unterminated quoted string")


def _inputs(rc):
    """(cred, cookie, method, base url, params dict, is_form). Query parameters and recorded forms, one entry per shape."""
    seen, out = set(), []
    sessions = rc.get("sessions") or {}

    def ok(url):
        return not SENSITIVE_PATH.search(urlsplit(url).path) and not any(
            re.fullmatch(x, url) for x in [stages.NEVER, *rc.get("exclude", [])])
    for cred, urls in (rc.get("pages") or {}).items():
        for u in sorted(urls):
            q = dict(parse_qsl(urlsplit(u).query, keep_blank_values=True))
            sig = (cred, "GET", urlsplit(u)._replace(query="", fragment="").geturl(), tuple(sorted(q)))
            if q and ok(u) and not any(SECRET_FIELD.search(k) for k in q) and sig not in seen:
                seen.add(sig)
                out.append((cred, sessions.get(cred), "GET", u, q, False))
    for cred, reqs in (rc.get("requests") or {}).items():
        for method, u, form in reqs:
            if method != "POST" or not isinstance(form, dict) or not form or not ok(u):
                continue
            if any("[REDACTED" in str(v) for v in form.values()) or any(SECRET_FIELD.search(k) for k in form):
                continue  # login/OTP-like or secret-bearing forms are never fuzzed
            sig = (cred, method, u, tuple(sorted(form)))
            if sig not in seen:
                seen.add(sig)
                out.append((cred, sessions.get(cred), method, u, form, True))
    return out


def _send(ctx, cookie, method, url, params, is_form):
    h = {"Cookie": cookie} if cookie else {}
    if method == "GET":
        r = ctx.client.get(urlunsplit(urlsplit(url)._replace(query=urlencode(params))), headers=h, deadline=ctx.deadline)
    else:
        h["Content-Type"] = "application/x-www-form-urlencoded"
        r = ctx.client.request("POST", url, headers=h, deadline=ctx.deadline, data=urlencode(params).encode())
    if looks_blocked(r):
        raise Blocked
    return r


def fuzz(ctx, keys):
    """Payloads from Fuzzing/ lists into each crawled query parameter and form field, one at a time.
    -> (drafts, status, untested) with status 'ok' | 'blocked' | 'stopped'."""
    payloads = list(dict.fromkeys(ln for k in keys if k.startswith("Fuzzing/") for ln in read(k)))
    targets, out, th = _inputs(ctx.run_ctx), [], Throttle(_rate(ctx))
    total = len(payloads) * sum(len(t[4]) for t in targets)
    done = 0
    for cred, cookie, method, url, params, is_form in targets:
        try:
            th.wait(ctx.deadline)
            base = _send(ctx, cookie, method, url, params, is_form)
        except Blocked:
            return out, "blocked", total - done
        except (TimeoutError, RequestCapExceeded):
            return out, "stopped", total - done
        except (httpx.HTTPError, OSError, BlockedAddress):
            done += len(payloads) * len(params)  # no baseline, so none of this input's payloads were tested
            continue
        for field in params:
            found = set()
            for i, payload in enumerate(payloads):
                if len(found) == 3:
                    done += len(payloads) - i
                    break
                try:
                    th.wait(ctx.deadline)
                    r = _send(ctx, cookie, method, url, {**params, field: payload}, is_form)
                except Blocked:
                    return out, "blocked", total - done
                except (TimeoutError, RequestCapExceeded):
                    return out, "stopped", total - done
                except (httpx.HTTPError, OSError, BlockedAddress):
                    done += 1
                    continue
                done += 1
                kind = None
                if "<" in payload and "html" in r.headers.get("content-type", "").lower() and payload in r.text \
                        and payload not in base.text and "xss" not in found:
                    kind = "xss"
                elif SQL_ERR.search(r.text) and not SQL_ERR.search(base.text) and "sql" not in found:
                    kind = "sql"
                elif r.status_code >= 500 and base.status_code < 500 and "5xx" not in found:
                    kind = "5xx"
                if kind:
                    found.add(kind)
                    out.append(_fuzz_draft(ctx, kind, cred, method, url, field, payload, r))
    return out, "ok", 0


_COPY = {
    "xss": ("high", "Suspected cross-site scripting", "A value sent in the parameter {p} is returned in the page without encoding.",
            "A script placed in this parameter could run in other users' browsers."),
    "sql": ("high", "Suspected SQL injection", "A value sent in the parameter {p} made the page show a database error.",
            "Attackers may read or change the database through this parameter."),
    "5xx": ("low", "Suspected input-handling error", "A value sent in the parameter {p} made the server answer with an error.",
            "Unexpected input crashes the page, which can hide deeper flaws and be used to disrupt the site."),
}


def _fuzz_draft(ctx, kind, cred, method, url, field, payload, r):
    sev, title, desc, impact = _COPY[kind]
    page = urlsplit(url)._replace(query="", fragment="").geturl()
    snippet = next((ln for ln in r.text.splitlines() if payload in ln or SQL_ERR.search(ln)), "")[:200] if kind != "5xx" else ""
    ev = redact(f"{method} {page}\nParameter: {field}\nPayload: {payload[:200]}\nHTTP {r.status_code}" + (f"\n\n{snippet}" if snippet else ""))
    d = FindingDraft(sev, "suspected", f"{title} in {field} at {page}", f"{ctx.host}{urlsplit(page).path}",
                     location(ctx, "Parameter", path=urlsplit(page).path, param=field, method=method, url=page),
                     desc.format(p=field), impact, ev, f"Send the payload shown above in {field} to {page} and read the response.",
                     "Validate input and encode output for the context it is used in; use parameterised database queries.",
                     [REFS["exposed"]], fingerprint_key=f"fuzz:{kind}:{method}:{page}:{field}")
    if cred:
        d.credential_id, d.fingerprint_key = cred, f"{d.fingerprint_key}:{cred}"
    return d
