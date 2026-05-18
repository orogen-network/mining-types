"""RFC-0005 — Slashing extrinsic ABI shapes (subset used by validator-replay)."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class FaultCode(str, Enum):
    WRONG_MODEL = "WrongModel"
    WRONG_RESPONSE = "WrongResponse"
    LOG_PROB_DRIFT = "LogProbDrift"
    CACHE_REPLAY = "CacheReplay"
    QUANTIZATION_SWAP = "QuantizationSwap"
    KERNEL_PACK_MISMATCH = "KernelPackMismatch"
    DEVICE_CERT_COLLISION = "DeviceCertCollision"
    HEARTBEAT_MISS = "HeartbeatMiss"
    ATTESTATION_STALE = "AttestationStale"
    SANCTIONS_HIT = "SanctionsHit"
    VALIDATOR_COLLUSION = "ValidatorCollusion"
    FAKE_BURN = "FakeBurn"
    BATCH_OVERCOMMIT = "BatchOvercommit"

    def base_severity_bps(self) -> int:
        return {
            FaultCode.WRONG_MODEL: 1000,
            FaultCode.QUANTIZATION_SWAP: 1000,
            FaultCode.VALIDATOR_COLLUSION: 1000,
            FaultCode.BATCH_OVERCOMMIT: 1000,
            FaultCode.WRONG_RESPONSE: 500,
            FaultCode.CACHE_REPLAY: 500,
            FaultCode.LOG_PROB_DRIFT: 200,
            FaultCode.ATTESTATION_STALE: 200,
            FaultCode.KERNEL_PACK_MISMATCH: 50,
            FaultCode.DEVICE_CERT_COLLISION: 10000,
            FaultCode.SANCTIONS_HIT: 10000,
            FaultCode.FAKE_BURN: 5000,
            FaultCode.HEARTBEAT_MISS: 0,
        }[self]


class SlashingEvidence(BaseModel):
    operator_id: str
    fault_code: FaultCode
    evidence_hash: str
    related_job_id: str | None = None
    related_receipt_hash: str | None = None
    validator_signatures: list[tuple[str, str]] = []
