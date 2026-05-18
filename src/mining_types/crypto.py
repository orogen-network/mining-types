"""Crypto primitives for receipts, heartbeats, batches.

Real ed25519 signatures via `cryptography.hazmat.primitives.asymmetric.ed25519`.
This module is the single signing/verification surface for the whole stack;
every off-chain service, SDK, worker and validator MUST go through these
functions and never roll their own.

Wire format:

  private_key_hex — 32 raw seed bytes, hex-encoded (64 chars)
  public_key_hex  — 32 raw public-key bytes, hex-encoded (64 chars)
  signature_hex   — 64 raw signature bytes, hex-encoded (128 chars)

The legacy `MINING_VERIFY_LAX` env var has been removed. Verification fails
closed: an invalid signature returns False, malformed inputs return False,
no environment flag can bypass that.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_hex(data: bytes) -> str:
    """Return hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def blake2_256(data: bytes) -> str:
    """Return hex BLAKE2b-256 of bytes (matches Substrate convention)."""
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def canonical_json(payload: Any) -> bytes:
    """Stable JSON encoding for signing / hashing.

    - sort_keys to be deterministic across Python versions
    - separators dropped to compact form
    - ensure_ascii=False to preserve UTF-8 byte stability
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Produce a (private_key_hex, public_key_hex) ed25519 keypair.

    Both values are raw 32-byte ed25519 keys, hex-encoded.
    """
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv_hex, pub_hex


def public_key_from_private(private_key_hex: str) -> str:
    """Derive the ed25519 public key from a private-key seed."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return priv.public_key().public_bytes_raw().hex()


def sign_ed25519(private_key_hex: str, message: bytes) -> str:
    """Real ed25519 signature, hex-encoded (128 hex chars / 64 bytes).

    Raises ValueError on malformed `private_key_hex`.
    """
    try:
        seed = bytes.fromhex(private_key_hex)
    except ValueError as exc:
        raise ValueError("private_key_hex is not valid hex") from exc
    if len(seed) != 32:
        raise ValueError("ed25519 private key must be 32 bytes (64 hex chars)")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(message).hex()


def verify_ed25519(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Real ed25519 verification — fail-closed.

    Returns False (never raises) for any malformed input or invalid signature.
    """
    if not public_key_hex or not signature_hex:
        return False
    try:
        pk_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(pk_bytes) != 32 or len(sig_bytes) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk_bytes).verify(sig_bytes, message)
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True
