"""Ed25519 signing and verification for proposals and attestations."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from kahu_tuning.config import canonical_json


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_payload(payload: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign the canonical JSON of a payload, return hex-encoded signature."""
    data = canonical_json(payload).encode()
    sig = private_key.sign(data)
    return sig.hex()


def verify_signature(payload: dict, signature_hex: str, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature over canonical JSON of payload.

    Returns True if valid, False if invalid or any error.
    """
    try:
        data = canonical_json(payload).encode()
        sig = bytes.fromhex(signature_hex)
        public_key.verify(sig, data)
        return True
    except Exception:
        return False


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    """Save private key to PEM file."""
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    Path(path).write_bytes(pem)


def save_public_key(key: Ed25519PublicKey, path: str | Path) -> None:
    """Save public key to PEM file."""
    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    Path(path).write_bytes(pem)


def load_private(path: str | Path) -> Ed25519PrivateKey:
    """Load private key from PEM file."""
    data = Path(path).read_bytes()
    key = load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return key


def load_public(path: str | Path) -> Ed25519PublicKey:
    """Load public key from PEM file."""
    data = Path(path).read_bytes()
    key = load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Expected Ed25519 public key")
    return key
