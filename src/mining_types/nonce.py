"""RFC-0007 (proposed) — customer nonce protocol.

Minimal skeleton: gateway hands the customer a `NonceChallenge` keyed to the
gateway+epoch; the customer claims a `NonceClaim` that the operator embeds in
the receipt. Prevents response-replay against the same gateway view.
"""

from __future__ import annotations

import secrets
import time

from pydantic import BaseModel, Field


def fresh_nonce() -> str:
    return secrets.token_hex(32)


class NonceChallenge(BaseModel):
    nonce: str = Field(default_factory=fresh_nonce)
    gateway_id: str
    issued_at_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    ttl_ms: int = 120_000


class NonceClaim(BaseModel):
    nonce: str
    gateway_id: str
    customer_id: str
