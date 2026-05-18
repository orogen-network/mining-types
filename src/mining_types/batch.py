"""RFC-0004 — Batch Settlement format."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mining_types.crypto import blake2_256, canonical_json, sign_ed25519
from mining_types.receipt import Receipt


class OperatorSummary(BaseModel):
    operator_id: str
    receipts_count: int
    aggregate_tokens_served: int
    aggregate_mint_useful: int
    merkle_subroot: str


class SettlementBatch(BaseModel):
    version: int = 1
    batch_id: str
    epoch_number: int
    gateway_id: str
    receipt_count: int
    merkle_root: str
    aggregate_burn_cuc: int = 0
    aggregate_mint_useful: int = 0
    per_operator_summary: list[OperatorSummary] = Field(default_factory=list)
    gateway_signature: str = ""

    def signing_payload(self) -> bytes:
        d = self.model_dump(mode="json")
        d.pop("gateway_signature", None)
        return canonical_json(d)

    def sign(self, gateway_private_key_hex: str) -> SettlementBatch:
        sig = sign_ed25519(gateway_private_key_hex, self.signing_payload())
        return self.model_copy(update={"gateway_signature": sig})

    @staticmethod
    def merkle_root_of(receipts: list[Receipt]) -> str:
        """Compute a simple BLAKE2-256 Merkle root.

        Implementation: pairwise BLAKE2 hash of leaves; if odd, last is duplicated.
        Returns empty hash for empty input.
        """
        if not receipts:
            return blake2_256(b"")
        leaves = [blake2_256(canonical_json(r.model_dump(mode="json")).strip()).encode("ascii") for r in receipts]
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [
                blake2_256(leaves[i] + leaves[i + 1]).encode("ascii")
                for i in range(0, len(leaves), 2)
            ]
        return leaves[0].decode("ascii")
