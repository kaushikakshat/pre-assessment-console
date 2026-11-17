"""Owner-only sign-in setup and test accounts. Passwords and the bypass code are sealed with the public key
and are write-only: no response, audit row or log ever carries them (the API cannot decrypt)."""
from datetime import datetime, timedelta, timezone
import os
import re
import socket
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from app.core import crypto
from app.core import security as sec
from app.core.audit import record
from app.db import get_db
from app.api.jobs import BLOCKED
from app.models import AuditEvent, Credential, LoginSetup as SetupRow, PolicyVersion, SchedulerConfig
from app.targets import ipguard
from app.targets.login import LoginSetup, perform_login
from app.targets.safe_http import SafeClient
from app.targets.validate import _internal, first_rule, parse_ports, parse_target

router = APIRouter(prefix="/assessments")
MAX_ACCOUNTS = 10
TEST_SECONDS = 20
TEST_GAP = timedelta(seconds=30)
STYLES = ("single", "two-step")
LOCKED_REASON = "Account appears locked"
OUT_OF_SCOPE = "The sign-in page must be on the target host."


class SetupIn(BaseModel):
    style: str = ""
    login_url: str = ""
    username_field: str = ""
    password_field: str = ""
    code_field: str | None = None
    otp_url: str | None = None
    otp_field: str | None = None
    bypass_code: str | None = None  # omitted keeps; "" clears
    logged_in_indicator: str = ""
    logged_out_indicator: str | None = None


class AccountIn(BaseModel):
    role_label: str = ""
    username: str = ""
    password: str = ""
    test: bool = False
    authorized: bool = False
    bypass_code: str | None = None  # used for this test only, never stored


def target_host(a) -> str:
    return parse_target(a.target).host


def make_client(db, a, hosts: set[str]) -> SafeClient:
    """Same private-address allowance the validation used; tests replace this to reach a local stub."""
    pv = db.scalar(select(PolicyVersion).where(PolicyVersion.status == "published")
                   .order_by(PolicyVersion.published_at.desc()).limit(1))
    internal = {}
    for h in hosts:
        try:
            addrs = ipguard.resolve(h, socket.getaddrinfo)
        except (OSError, ValueError):
            continue
        app_env = os.environ.get("APP_ENV", "prod")
        net = _internal(first_rule(pv.rules if pv else {}, h, addrs, a.env, app_env), app_env, addrs)
        if net is not False and any(ipguard.classify(x)[0] for x in addrs):
            internal[h] = net
    return SafeClient(hosts, internal, max_requests=10, verify=not a.allow_untrusted_cert)


def _url_ok(a, u: str) -> str | None:
    """None when the URL is on the target host and permitted port and not an excluded path, else the message."""
    try:
        x = httpx.URL(u)
        if x.scheme not in ("http", "https") or not x.host or len(u) > 2000:
            return "Enter a full http or https URL."
        if ipguard.normalize_host(x.host) != target_host(a):
            return OUT_OF_SCOPE
        if (x.port or (443 if x.scheme == "https" else 80)) not in parse_ports(a.ports):
            return "The login page must use a permitted port."
        path = x.path or "/"
        if any(path.startswith(p.rstrip("*")) for p in re.split(r"[,\s]+", a.exclusions) if p.startswith("/")):
            return "The login page is in an excluded path."
    except Exception:
        return "Enter a full http or https URL."
    return None


def _hint(u: str) -> str:
    return "•••" if len(u) <= 4 else u[:2] + "•••"


def _acct(c: Credential) -> dict:
    return {"id": c.display_id, "role_label": c.role_label, "username_hint": c.username_hint,
            "last_test": c.last_test, "last_tested_at": c.last_tested_at}


def _setup(s: SetupRow | None) -> dict | None:
    if not s:
        return None
    return {"style": s.style, "login_url": s.login_url, "username_field": s.username_field,
            "password_field": s.password_field, "code_field": s.code_field, "otp_url": s.otp_url,
            "otp_field": s.otp_field, "logged_in_indicator": s.logged_in_indicator,
            "logged_out_indicator": s.logged_out_indicator, "bypass_code_set": s.bypass_code_enc is not None,
            "updated_at": s.updated_at}


def _owned(db, aid, user):
    return sec.get_assessment_or_404(db, aid, user, "scan")


def _live(db, a):
    return db.scalars(select(Credential).where(Credential.assessment_id == a.id, Credential.deleted_at.is_(None))
                      .order_by(Credential.id)).all()


@router.get("/{aid}/signin")
def get_signin(aid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = _owned(db, aid, user)
    return {"setup": _setup(db.get(SetupRow, a.id)), "accounts": [_acct(c) for c in _live(db, a)]}


@router.put("/{aid}/signin")
def put_signin(aid: str, body: SetupIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = _owned(db, aid, user)
    err = {}
    if body.style not in STYLES:
        err["style"] = "Choose a sign-in style."
    for f, msg in (("username_field", "Enter the username field name."), ("password_field", "Enter the password field name."),
                   ("logged_in_indicator", "Enter text or a url: pattern that shows you are signed in.")):
        if not 1 <= len(getattr(body, f).strip()) <= 300:
            err[f] = msg
    urls = [("login_url", body.login_url)] + ([("otp_url", body.otp_url or "")] if body.style == "two-step" else [])
    for f, u in urls:
        if (msg := _url_ok(a, u)):
            err[f] = msg
    if body.style == "two-step" and not (body.otp_field or "").strip():
        err["otp_field"] = "Enter the code field name."
    if body.logged_in_indicator.startswith("url:"):
        try:
            if not body.logged_in_indicator[4:].strip():
                raise re.error("empty")
            re.compile(body.logged_in_indicator[4:])
        except re.error:
            err["logged_in_indicator"] = "Enter a pattern after url:, such as /dashboard."
    if len(body.bypass_code or "") > 64:
        err["bypass_code"] = "Too long."
    if err:
        raise HTTPException(422, {"fields": err})
    two = body.style == "two-step"
    vals = {"style": body.style, "login_url": body.login_url, "username_field": body.username_field.strip(),
            "password_field": body.password_field.strip(), "code_field": (body.code_field or "").strip() or None,
            "otp_url": body.otp_url if two else None, "otp_field": body.otp_field.strip() if two else None,
            "logged_in_indicator": body.logged_in_indicator,
            "logged_out_indicator": (body.logged_out_indicator or "").strip() or None, "updated_at": func.now()}
    row = db.get(SetupRow, a.id)
    if row is None:
        row = SetupRow(assessment_id=a.id, **vals)
        db.add(row)
    else:
        for k, v in vals.items():
            setattr(row, k, v)
    if "bypass_code" in body.model_fields_set and body.bypass_code is not None:
        row.bypass_code_enc = crypto.seal(body.bypass_code) if body.bypass_code else None
    record(db, user.email, "signin", "save-setup", a.display_id, "success", "Sign-in setup saved")
    db.flush()
    db.refresh(row)
    out = _setup(row)
    db.commit()
    return out


def _check_account(b: AccountIn, replacing: bool):
    err = {}
    if not (replacing and not b.role_label.strip()) and not 1 <= len(b.role_label.strip()) <= 60:
        err["role_label"] = "Enter a role label of 1 to 60 characters."
    if not 1 <= len(b.username) <= 200:
        err["username"] = "Enter the username."
    if not 1 <= len(b.password) <= 200:
        err["password"] = "Enter the password."
    if len(b.bypass_code or "") > 64:
        err["bypass_code"] = "Too long."
    if b.test and not b.authorized:
        err["authorized"] = "Confirm you are authorized to test this target."
    if err:
        raise HTTPException(422, {"fields": err})


def _begin_test(db, user, a, b: AccountIn, c: Credential | None):
    """Gates and rate limits, then records the attempt and commits so no transaction is held during network I/O."""
    cfg = db.get(SchedulerConfig, 1)
    if cfg and (cfg.emergency or cfg.paused):
        raise HTTPException(503, BLOCKED["emergency" if cfg.emergency else "paused"])
    v = a.validation or {}
    if not (v.get("outcome") == "allowed" or (v.get("outcome") == "approval" and (a.approval or {}).get("state") == "approved")):
        raise HTTPException(409, "Validate this target, and get approval if it needs it, before testing a sign-in.")
    s = db.get(SetupRow, a.id)
    if not s:
        raise HTTPException(409, "Save the sign-in setup before testing an account.")
    if c is not None and db.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.object == a.display_id, AuditEvent.action == "test-locked",
            AuditEvent.detail.like(f"%[{c.display_id}]"), AuditEvent.at >= c.updated_at)):
        raise HTTPException(409, "This account appears locked. Replace it after it is unlocked.")
    now = datetime.now(timezone.utc)
    n = lambda since: db.scalar(select(func.count()).select_from(AuditEvent).where(  # noqa: E731
        AuditEvent.object == a.display_id, AuditEvent.action == "test-login", AuditEvent.at > now - since))
    if n(TEST_GAP) >= 1 or n(timedelta(hours=1)) >= 5:
        raise HTTPException(429, "Wait before testing sign-in again.")
    record(db, user.email, "signin", "test-login", a.display_id, "success", "Sign-in test started")
    db.commit()
    return LoginSetup(s.style, s.login_url, s.username_field, s.password_field, s.logged_in_indicator,
                      s.code_field, s.otp_url, s.otp_field, s.logged_out_indicator, b.bypass_code or None)


def _run_test(db, a, setup, b: AccountIn) -> str:
    hosts = {target_host(a)}
    client = make_client(db, a, hosts)  # DB reads done; end the transaction before network I/O
    db.commit()
    with client:
        return perform_login(client, setup, b.username, b.password, time.monotonic() + TEST_SECONDS, target_host(a)).reason


def _store(c: Credential, b: AccountIn, reason: str | None):
    c.username_enc, c.password_enc, c.username_hint = crypto.seal(b.username), crypto.seal(b.password), _hint(b.username)
    c.updated_at = func.now()
    if reason is not None:
        c.last_test, c.last_tested_at = ("ok" if reason == "Signed in" else "failed"), func.now()


def _tested(reason):
    return "not tested" if reason is None else "test: ok" if reason == "Signed in" else "test: failed"


@router.post("/{aid}/accounts", status_code=201)
def add_account(aid: str, body: AccountIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = _owned(db, aid, user)
    _check_account(body, False)
    db.execute(select(func.pg_advisory_xact_lock(a.id)))
    if len(_live(db, a)) >= MAX_ACCOUNTS:
        raise HTTPException(409, f"You can add up to {MAX_ACCOUNTS} test accounts.")
    reason = None
    if body.test:
        setup = _begin_test(db, user, a, body, None)  # commits, releasing the lock
        reason = _run_test(db, a, setup, body)
        db.execute(select(func.pg_advisory_xact_lock(a.id)))
        if len(_live(db, a)) >= MAX_ACCOUNTS:
            raise HTTPException(409, f"You can add up to {MAX_ACCOUNTS} test accounts.")
    c = Credential(assessment_id=a.id, role_label=body.role_label.strip(), username_enc=b"", password_enc=b"")
    _store(c, body, reason)
    db.add(c)
    db.flush()
    db.refresh(c)
    if reason == LOCKED_REASON:
        record(db, user.email, "signin", "test-locked", a.display_id, "blocked", f"Account appears locked [{c.display_id}]")
    record(db, user.email, "signin", "add-account", a.display_id, "success",
           f"Test account added: {c.role_label} ({_tested(reason)})")
    out = {**_acct(c), "test_result": reason}
    db.commit()
    return out


def _get_account(db, a, cid) -> Credential:
    c = db.scalar(select(Credential).where(Credential.assessment_id == a.id, Credential.display_id == cid,
                                           Credential.deleted_at.is_(None)))
    if not c:
        raise HTTPException(404, "Not found.")
    return c


@router.put("/{aid}/accounts/{cid}")
def replace_account(aid: str, cid: str, body: AccountIn, user=Depends(sec.current_user), db=Depends(get_db)):
    a = _owned(db, aid, user)
    db.execute(select(func.pg_advisory_xact_lock(a.id)))
    c = _get_account(db, a, cid)
    _check_account(body, True)
    reason = None
    if body.test:
        setup = _begin_test(db, user, a, body, c)
        reason = _run_test(db, a, setup, body)
        db.execute(select(func.pg_advisory_xact_lock(a.id)))
        c = _get_account(db, a, cid)
    if body.role_label.strip():
        c.role_label = body.role_label.strip()
    _store(c, body, reason)
    db.flush()
    db.refresh(c)
    if reason == LOCKED_REASON:
        record(db, user.email, "signin", "test-locked", a.display_id, "blocked", f"Account appears locked [{c.display_id}]")
    record(db, user.email, "signin", "update-account", a.display_id, "success",
           f"Test account updated: {c.role_label} ({_tested(reason)})")
    out = {**_acct(c), "test_result": reason}
    db.commit()
    return out


@router.delete("/{aid}/accounts/{cid}", status_code=204)
def delete_account(aid: str, cid: str, user=Depends(sec.current_user), db=Depends(get_db)):
    a = _owned(db, aid, user)
    c = _get_account(db, a, cid)
    c.deleted_at, c.username_enc, c.password_enc, c.username_hint = func.now(), b"", b"", ""
    record(db, user.email, "signin", "remove-account", a.display_id, "success", f"Test account removed: {c.role_label}")
    db.commit()
