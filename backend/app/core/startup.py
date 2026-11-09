import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def pem_from_env(value):
    """.env holds PEMs on one line with literal \\n; accept real newlines too."""
    return value.replace("\\n", "\n").encode()


def _check_key(name, loader, kind):
    try:
        ok = isinstance(loader(pem_from_env(os.environ.get(name, ""))), kind)
    except Exception:
        ok = False
    if not ok:
        raise SystemExit(f"{name} must be an X25519 PEM key; run `python -m app.cli gen-credential-keys` and set it in .env.")


def validate_env(role="api"):
    """Refuse to start with a missing, short or placeholder secret. role: api, worker or egress."""
    if role == "egress":
        tok = os.environ.get("EGRESS_TOKEN", "")
        if len(tok) < 32 or "change-me" in tok:
            raise SystemExit("EGRESS_TOKEN must be set to a random value of at least 32 characters (not a change-me placeholder).")
        return
    key = os.environ.get("SECRET_KEY", "")
    if len(key) < 32 or "change-me" in key:
        raise SystemExit("SECRET_KEY must be set to a random value of at least 32 characters (not a change-me placeholder).")
    if "change-me" in os.environ.get("DATABASE_URL", ""):
        raise SystemExit("APP_DB_PASSWORD is still a change-me placeholder; set a real password in .env.")
    if role == "api":
        _check_key("CREDENTIALS_PUBLIC_KEY", lambda b: load_pem_public_key(b), X25519PublicKey)
    elif role == "worker":
        _check_key("CREDENTIALS_PRIVATE_KEY", lambda b: load_pem_private_key(b, None), X25519PrivateKey)
        for n in ("EGRESS_TOKEN", "ZAP_API_KEY"):
            v = os.environ.get(n, "")
            if len(v) < 32 or "change-me" in v:
                raise SystemExit(f"{n} must be set to a random value of at least 32 characters (not a change-me placeholder).")
