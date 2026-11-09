import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, make_url

APP_URL = os.environ["TEST_DATABASE_URL"]
OWNER_URL = os.environ["TEST_MIGRATION_DATABASE_URL"]
os.environ.setdefault("DATABASE_URL", APP_URL)  # app.db reads this at import
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat  # noqa: E402

_k = X25519PrivateKey.generate()  # test-only keypair so startup validation passes
os.environ.setdefault("CREDENTIALS_PUBLIC_KEY", _k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
os.environ.setdefault("CREDENTIALS_PRIVATE_KEY", _k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
os.environ.setdefault("EGRESS_TOKEN", "t" * 40)
os.environ.setdefault("ZAP_API_KEY", "z" * 40)
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-0123456789abcdef")


@pytest.fixture(scope="session", autouse=True)
def fresh_schema():
    """Drop/create a dedicated test database and migrate it to head with the owner role."""
    url = make_url(OWNER_URL)
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.exec_driver_sql(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
        c.exec_driver_sql(f'CREATE DATABASE "{url.database}"')
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True,
                   env={**os.environ, "MIGRATION_DATABASE_URL": OWNER_URL})
    yield
    admin.dispose()


@pytest.fixture
def app_conn():
    engine = create_engine(APP_URL)
    with engine.connect() as c:
        yield c
        c.rollback()
    engine.dispose()
