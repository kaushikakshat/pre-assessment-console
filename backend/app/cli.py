import argparse
import secrets

from argon2 import PasswordHasher
from sqlalchemy import func, select

from app.core.audit import record
from app.db import SessionLocal
from app.models import User


def create_admin(email, name):
    email = email.strip().lower()
    temp = secrets.token_urlsafe(12)
    with SessionLocal() as db, db.begin():
        if db.scalar(select(User).where(func.lower(User.email) == email)):
            raise SystemExit("A user with that email already exists.")
        db.add(User(email=email, name=name, role="admin", status="active",
                    password_hash=PasswordHasher().hash(temp)))
        record(db, "cli", "users", "create-admin", email, "success", "Administrator created via CLI")
    print(f"Temporary password for {email}: {temp}\nMFA enrolment is required on first sign-in.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    a = p.parse_args()
    create_admin(a.email, a.name)
