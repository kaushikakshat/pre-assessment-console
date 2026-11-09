import argparse
import secrets

from argon2 import PasswordHasher
from sqlalchemy import func, select

from app.core.audit import record
from app.db import SessionLocal
from app.models import User


def gen_credential_keys():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    k = X25519PrivateKey.generate()
    one = lambda b: b.decode().strip().replace("\n", "\\n")  # single line for .env
    print(f'CREDENTIALS_PUBLIC_KEY="{one(k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))}"')
    print(f'CREDENTIALS_PRIVATE_KEY="{one(k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))}"')


def create_admin(email, name):
    email = email.strip().lower()
    temp = secrets.token_urlsafe(12)
    with SessionLocal() as db, db.begin():
        if db.scalar(select(User).where(func.lower(User.email) == email)):
            raise SystemExit("A user with that email already exists.")
        db.add(User(email=email, name=name, role="admin", status="active",
                    password_hash=PasswordHasher().hash(temp), must_change_password=True))
        record(db, "cli", "users", "create-admin", email, "success", "Administrator created via CLI")
    print(f"Temporary password for {email}: {temp}\nMFA enrolment is required on first sign-in.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    sub.add_parser("gen-credential-keys")
    a = p.parse_args()
    if a.cmd == "gen-credential-keys":
        raise SystemExit(gen_credential_keys())
    create_admin(a.email, a.name)
