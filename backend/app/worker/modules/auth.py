"""Signs in each configured test account. Plaintext credentials exist only in locals of open_accounts()/login_all():
run_ctx holds sealed blobs in, Cookie header values out ({credential display id: Cookie header})."""
import logging

from app.core import crypto
from app.targets.login import LoginSetup, perform_login

from .base import ModuleResult

log = logging.getLogger("worker")
ATTEMPTS = 3  # only for a transient failure; a wrong password or a lockout is never retried
TRANSIENT = "Could not reach the login page"


def open_accounts(rc) -> list:
    """-> [(display id, role, username, password)] decrypted. Callers keep the result in locals only."""
    return [(i, role, crypto.open_sealed(u), crypto.open_sealed(p)) for i, role, u, p in rc.get("accounts") or []]


def secrets(rc) -> set:
    """Plaintext values to scrub from anything stored. Local use only."""
    try:
        return {v for _, _, u, p in open_accounts(rc) for v in (u, p) if v}
    except Exception:
        return set()


def login_all(ctx, deadline, ids=None, attempts=ATTEMPTS) -> tuple[dict, list, set]:
    """-> (sessions, ["{role} could not sign in: {reason}"], ids that failed). Skips accounts in run_ctx['excluded'].
    Reasons come from the login engine and hold no values."""
    rc, sessions, failed, bad = ctx.run_ctx, {}, [], set()
    s = rc["login"]
    code = crypto.open_sealed(s["bypass_code_enc"]) if s.get("bypass_code_enc") else None
    setup = LoginSetup(**{k: v for k, v in s.items() if k != "bypass_code_enc"}, bypass_code=code)
    roles = {i: role for i, role, *_ in rc["accounts"]}
    skip = rc.get("excluded", set())
    for cid, user, pw in _each(rc):
        if cid in skip or (ids is not None and cid not in ids):
            continue
        why = "The credentials could not be read" if user is None else ""
        for _ in range(attempts if user is not None else 0):
            res = perform_login(ctx.client, setup, user, pw, deadline)
            if res.ok:
                sessions[cid], why = "; ".join(f"{k}={v}" for k, v in res.cookies.items()), ""
                break
            why = res.reason
            if why != TRANSIENT:
                break
        if why:
            failed.append(f"{roles[cid]} could not sign in: {why}")
            bad.add(cid)
            if "locked" in why:
                skip.add(cid)
    rc["excluded"] = skip
    return sessions, failed, bad


def relogin(ctx, cid) -> bool:
    """One fresh sign-in for an account whose session was lost; the third failure (or a lockout) excludes it."""
    rc = ctx.run_ctx
    got, _, bad = login_all(ctx, ctx.deadline, ids={cid}, attempts=1)
    if cid in got:
        rc.setdefault("sessions", {})[cid] = got[cid]
        return True
    rc.setdefault("sessions", {}).pop(cid, None)
    n = rc.setdefault("relogin_failures", {})
    n[cid] = n.get(cid, 0) + 1
    if n[cid] >= ATTEMPTS:
        rc.setdefault("excluded", set()).add(cid)
    return False


def _each(rc):
    for i, _, u, p in rc["accounts"]:
        try:
            yield i, crypto.open_sealed(u), crypto.open_sealed(p)
        except Exception:  # never include the exception: it can carry nothing useful and must carry no values
            yield i, None, None


def run(ctx) -> ModuleResult:
    rc = ctx.run_ctx
    if not rc.get("accounts") or not rc.get("login"):
        return ModuleResult("skipped", "No test accounts were configured")
    rc["roles"] = {i: role for i, role, *_ in rc["accounts"]}
    rc["logged_out"] = rc["login"].get("logged_out_indicator")
    sessions, failed, bad = login_all(ctx, ctx.deadline)
    rc["sessions"] = sessions
    rc["excluded"] = rc.get("excluded", set()) | bad
    if failed:
        return ModuleResult("completed-warnings", "; ".join(failed))
    return ModuleResult("completed", f"Signed in {len(sessions)} account(s)")
