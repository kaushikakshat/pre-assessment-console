"""Sealed credentials: ephemeral X25519 + HKDF-SHA256 + AES-GCM. The API holds only the public key; the
private key is read lazily and only in the worker (API_PROCESS is set by the API lifespan)."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat, load_pem_private_key,
                                                          load_pem_public_key)

from app.core.startup import pem_from_env

API_PROCESS = False
_INFO = b"pa-credential-v1"


def _key(shared: bytes, eph: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=eph, info=_INFO).derive(shared)


def seal(plaintext: str) -> bytes:
    pub = load_pem_public_key(pem_from_env(os.environ["CREDENTIALS_PUBLIC_KEY"]))
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = os.urandom(12)
    ct = AESGCM(_key(eph.exchange(pub), eph_pub)).encrypt(nonce, plaintext.encode(), eph_pub)
    return eph_pub + nonce + ct


def open_sealed(blob: bytes) -> str:
    raw = os.environ.get("CREDENTIALS_PRIVATE_KEY")
    if API_PROCESS or not raw:
        raise RuntimeError("This process cannot open sealed credentials.")
    priv = load_pem_private_key(pem_from_env(raw), None)
    eph_pub, nonce, ct = bytes(blob[:32]), bytes(blob[32:44]), bytes(blob[44:])
    key = _key(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub)
    return AESGCM(key).decrypt(nonce, ct, eph_pub).decode()
