"""RFC-0001 — Signed Response Receipt."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mining_types.crypto import blake2_256, canonical_json, sign_ed25519


class KvMetadata(BaseModel):
    """KV-cache metadata (RFC-0001 §KvMetadata)."""

    prefix_hint: str | None = None
    cache_hit: bool = False
    kv_blocks_used: int = 0


class TokenEvidence(BaseModel):
    """Optional tolerant-replay evidence (RFC-0001 §TokenEvidence, additive).

    Real (GPU/CPU) inference is not bit-reproducible, so an exact
    `sha256(response_text)` comparison would slash an honest operator the moment
    floating-point or kernel non-determinism nudges a single token. This block
    carries the extra signal a validator needs to run a *tolerant* comparison
    instead — token-id overlap and top-logprob agreement — without leaking the
    response text itself.

    Every field is optional so the receipt remains wire-compatible: a mock or
    exact-replay deployment simply omits the block and existing serialization /
    signing is unchanged.
    """

    # Hex digest (sha256) over the emitted token-id sequence. Lets a validator
    # cheaply detect "same tokens" without transporting the full id list.
    token_ids_digest: str | None = None
    # The emitted token ids, when the operator chooses to publish them for a
    # full token-overlap comparison. May be omitted to save bandwidth.
    token_ids: list[int] | None = None
    # Per-position top log-probability the engine assigned to its chosen token.
    # Used for top-logprob agreement scoring under tolerant replay.
    top_logprobs: list[float] | None = None


class Receipt(BaseModel):
    """Signed response receipt per RFC-0001.

    Hashes/IDs are hex-encoded strings (32 byte H256 → 64 hex chars) instead of raw
    bytes — easier across Python+JSON+JS+Rust.
    """

    version: int = 1
    job_id: str
    operator_id: str
    model_id: str
    model_weight_hash: str
    adapter_id: str | None = None
    customer_nonce: str
    request_hash: str
    response_hash: str
    log_probs_sample: list[float] = Field(default_factory=list)
    # Optional tolerant-replay evidence (additive; None when not published).
    token_evidence: TokenEvidence | None = None
    kv_metadata: KvMetadata = Field(default_factory=KvMetadata)
    kernel_pack_hash: str
    gpu_model: str = "mock-H100"
    driver_version: str = "550.54.15"
    cuda_version: str = "12.4"
    attestation_report_hash: str
    batch_invariant_proof: str | None = None
    timestamp_ms: int
    gateway_id: str
    operator_signature: str = ""

    def signing_payload(self) -> bytes:
        """Canonical bytes used as the signing target (everything except the signature)."""
        d = self.model_dump(mode="json")
        d.pop("operator_signature", None)
        return canonical_json(d)

    def sign(self, operator_private_key_hex: str) -> Receipt:
        """Return a copy with `operator_signature` set."""
        sig = sign_ed25519(operator_private_key_hex, self.signing_payload())
        return self.model_copy(update={"operator_signature": sig})

    def content_hash(self) -> str:
        """BLAKE2-256 of the SCALE-equivalent canonical encoding."""
        return blake2_256(self.signing_payload())
