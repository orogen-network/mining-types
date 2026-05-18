"""RFC-0003 — Off-chain Heartbeat schema."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from mining_types.crypto import canonical_json, sign_ed25519


class Quantization(str, Enum):
    FP16 = "FP16"
    FP8 = "FP8"
    INT8 = "INT8"
    INT4 = "INT4"


class Capability(BaseModel):
    base_model_id: str
    adapter_ids: list[str] = Field(default_factory=list)
    quantization: Quantization = Quantization.FP16
    max_context_tokens: int = 8192
    max_concurrent_requests: int = 16
    deterministic_mode: bool = False


class LoadSnapshot(BaseModel):
    active_requests: int = 0
    queue_depth: int = 0
    p50_ttft_ms: int = 0
    p99_ttft_ms: int = 0
    p50_itl_ms: int = 0
    p99_itl_ms: int = 0
    gpu_memory_used_gb: float = 0.0
    gpu_utilization_pct: float = 0.0


class AttestationFreshness(BaseModel):
    last_attested_at_ms: int = 0
    expires_at_ms: int = 0
    current_report_hash: str = ""


class WatchdogState(BaseModel):
    vllm_pid_alive: bool = True
    vllm_last_log_ms: int = 0
    last_restart_count_24h: int = 0


class OffChainHeartbeat(BaseModel):
    version: int = 1
    operator_id: str
    block_number: int = 0
    capabilities: list[Capability] = Field(default_factory=list)
    current_load: LoadSnapshot = Field(default_factory=LoadSnapshot)
    kv_cache_pressure: float = 0.0
    last_completed_job_id: str | None = None
    attestation_freshness: AttestationFreshness = Field(default_factory=AttestationFreshness)
    watchdog_state: WatchdogState = Field(default_factory=WatchdogState)
    price_per_million_tokens: int = 0
    geo_region: str = "US"
    endpoint_url: str = ""
    signature: str = ""

    def signing_payload(self) -> bytes:
        d = self.model_dump(mode="json")
        d.pop("signature", None)
        return canonical_json(d)

    def sign(self, operator_private_key_hex: str) -> OffChainHeartbeat:
        sig = sign_ed25519(operator_private_key_hex, self.signing_payload())
        return self.model_copy(update={"signature": sig})
