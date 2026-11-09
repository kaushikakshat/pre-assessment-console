import json
import pathlib

import pytest

from app.core.startup import validate_env


def test_validate_env_requires_credential_key_for_role(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "k" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://app_user:s3cret@db/x")
    validate_env("api")
    validate_env("worker")
    monkeypatch.delenv("CREDENTIALS_PUBLIC_KEY")
    with pytest.raises(SystemExit, match="CREDENTIALS_PUBLIC_KEY"):
        validate_env("api")
    monkeypatch.delenv("CREDENTIALS_PRIVATE_KEY")
    with pytest.raises(SystemExit, match="CREDENTIALS_PRIVATE_KEY"):
        validate_env("worker")


def test_validate_env_egress_token(monkeypatch):
    for bad in ("", "short", "change-me-" + "x" * 40):
        monkeypatch.setenv("EGRESS_TOKEN", bad)
        with pytest.raises(SystemExit, match="EGRESS_TOKEN"):
            validate_env("egress")
    monkeypatch.setenv("EGRESS_TOKEN", "t" * 32)
    validate_env("egress")


def test_gen_credential_keys_roundtrip(monkeypatch, capsys):
    from app import cli
    cli.gen_credential_keys()
    for line in capsys.readouterr().out.splitlines():
        k, v = line.split("=", 1)
        monkeypatch.setenv(k, v.strip('"'))
    monkeypatch.setenv("SECRET_KEY", "k" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://app_user:s3cret@db/x")
    validate_env("api")
    validate_env("worker")


def test_vendor_manifest_excludes_passwords():
    m = json.loads((pathlib.Path(__file__).parents[1] / "vendor" / "manifest.json").read_text())
    paths = m["seclists"]["paths"]
    assert paths == ["Discovery", "Fuzzing"]
    assert not [p for p in paths if p.startswith(("Passwords/", "Usernames/"))]
