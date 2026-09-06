"""Minimal Ed25519 helpers. No TPM, no X.509, no network."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mcp_atsa_admission.canon import canonical_dumps

ALG_ED25519 = "Ed25519"
RAW_KEY_LEN = 32
SIG_LEN = 64


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, base64url raw public key)."""
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, b64url_encode(public_raw)


def private_from_raw_b64(text: str) -> Ed25519PrivateKey:
    raw = b64url_decode(text)
    if len(raw) != RAW_KEY_LEN:
        raise ValueError(f"Ed25519 private key must be {RAW_KEY_LEN} bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_from_raw_b64(text: str) -> Ed25519PublicKey:
    raw = b64url_decode(text)
    if len(raw) != RAW_KEY_LEN:
        raise ValueError(f"Ed25519 public key must be {RAW_KEY_LEN} bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def signing_body(clearance: dict) -> dict:
    """Clearance fields that are covered by the signature."""
    return {k: v for k, v in clearance.items() if k != "signature"}


def sign_clearance(clearance: dict, private: Ed25519PrivateKey) -> str:
    """Return a base64url signature over the canonical clearance body."""
    message = canonical_dumps(signing_body(clearance))
    return b64url_encode(private.sign(message))


def verify_clearance_signature(clearance: dict, public_key_b64: str) -> bool:
    """True iff ``signature`` verifies under the pinned public key."""
    signature = clearance.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        public = public_from_raw_b64(public_key_b64)
        sig = b64url_decode(signature)
        if len(sig) != SIG_LEN:
            return False
        public.verify(sig, canonical_dumps(signing_body(clearance)))
    except (ValueError, InvalidSignature):
        return False
    return True
