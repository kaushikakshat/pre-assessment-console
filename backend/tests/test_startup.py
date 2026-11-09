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
    import re
    m = json.loads((pathlib.Path(__file__).parents[1] / "vendor" / "manifest.json").read_text())
    assert m["seclists"]["paths"] == ["Discovery", "Fuzzing"]
    bad = re.compile(m["seclists"]["exclude"])  # same regex fetch.sh applies to every relative path
    for p in ("Passwords/x", "Usernames/x", "Discovery/Web-Content/default-passwords.txt", "Fuzzing/user-agents.txt", "Fuzzing/Credentials/a.txt"):
        assert bad.search(p), p
    for p in ("Discovery/Web-Content/common.txt", "Fuzzing/XSS/xss.txt"):
        assert not bad.search(p), p


def test_clean_env_drops_secrets(monkeypatch):
    from app.worker.subproc import clean_env
    for k in ("CREDENTIALS_PRIVATE_KEY", "ZAP_API_KEY", "EGRESS_TOKEN", "SECRET_KEY", "DATABASE_URL"):
        monkeypatch.setenv(k, "x" * 40)
    monkeypatch.setenv("PATH_MARK", "keep")
    env = clean_env()
    assert env["PATH_MARK"] == "keep" and "PATH" in env
    assert not {"CREDENTIALS_PRIVATE_KEY", "CREDENTIALS_PUBLIC_KEY", "ZAP_API_KEY", "EGRESS_TOKEN", "SECRET_KEY", "DATABASE_URL"} & env.keys()
