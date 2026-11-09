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
        return {v for _, _, u, p in open_accounts(rc) for v in (u, p) if len(v) >= 3}
    except Exception:
        return set()


def login_all(ctx, deadline) -> tuple[dict, list]:
    """-> (sessions, ["{role} could not sign in: {reason}"]). Reasons come from the login engine and hold no values."""
    rc, sessions, failed = ctx.run_ctx, {}, []
    s = rc["login"]
    code = crypto.open_sealed(s["bypass_code_enc"]) if s.get("bypass_code_enc") else None
    setup = LoginSetup(**{k: v for k, v in s.items() if k != "bypass_code_enc"}, bypass_code=code)
    roles = {i: role for i, role, *_ in rc["accounts"]}
    for cid, user, pw in _each(rc):
        why = "The credentials could not be read" if user is None else ""
        for _ in range(ATTEMPTS if user is not None else 0):
            res = perform_login(ctx.client, setup, user, pw, deadline)
            if res.ok:
                sessions[cid], why = "; ".join(f"{k}={v}" for k, v in res.cookies.items()), ""
                break
            why = res.reason
            if why != TRANSIENT:
                break
        if why:
            failed.append(f"{roles[cid]} could not sign in: {why}")
    return sessions, failed


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
    sessions, failed = login_all(ctx, ctx.deadline)
    rc["sessions"] = sessions
    if failed:
        return ModuleResult("completed-warnings", "; ".join(failed))
    return ModuleResult("completed", f"Signed in {len(sessions)} account(s)")
