import pytest

from app.core import crypto


def test_seal_open_roundtrip():
    a, b = crypto.seal("p@ss"), crypto.seal("p@ss")
    assert a != b and b"p@ss" not in a
    assert crypto.open_sealed(a) == "p@ss"


def test_api_process_cannot_open(monkeypatch):
    blob = crypto.seal("x")
    monkeypatch.delenv("CREDENTIALS_PRIVATE_KEY")
    with pytest.raises(RuntimeError):
        crypto.open_sealed(blob)
    monkeypatch.setenv("CREDENTIALS_PRIVATE_KEY", "present")
    monkeypatch.setattr(crypto, "API_PROCESS", True)
    with pytest.raises(RuntimeError):
        crypto.open_sealed(blob)
