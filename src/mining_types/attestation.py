"""RFC-0002 — Combined Multi-Vendor Attestation Report."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from mining_types.crypto import blake2_256, canonical_json, sign_ed25519


class OperatorTier(str, Enum):
    DC_PREMIUM = "dc-premium"
    DC_STANDARD = "dc-standard"
    CLOUD_RENTED = "cloud-rented"
    PROSUMER = "prosumer"
    EDGE = "edge"
    EMBED_ONLY = "embed-only"
    COMPLIANCE = "compliance"


class NvidiaQuote(BaseModel):
    device_cert: str          # hex
    attestation_cert: str
    measurement: str
    nonce: str
    gpu_uuid: str


class IntelTdxQuote(BaseModel):
    quote_blob: str           # hex
    measurement: str
    fmspc: str


class AmdSevSnpReport(BaseModel):
    report_blob: str
    measurement: str
    chip_id: str


class NvtrustRimAttestation(BaseModel):
    rim_blob: str
    chain_hash: str


class AttestationReport(BaseModel):
    """RFC-0002 combined attestation."""

    version: int = 1
    operator_id: str
    tier: OperatorTier = OperatorTier.DC_STANDARD
    gpu_quote: NvidiaQuote | None = None
    tdx_quote: IntelTdxQuote | None = None
    sev_snp_report: AmdSevSnpReport | None = None
    rim_attestation: NvtrustRimAttestation | None = None
    firmware_hashes: list[str] = Field(default_factory=list)
    measured_vm_bundle: str
    timestamp_ms: int
    validity_window_ms: int = 7 * 86400 * 1000
    aggregator_signature: str = ""
    vendor_pki_chain_hashes: list[str] = Field(default_factory=list)

    def signing_payload(self) -> bytes:
        d = self.model_dump(mode="json")
        d.pop("aggregator_signature", None)
        return canonical_json(d)

    def report_hash(self) -> str:
        return blake2_256(self.signing_payload())

    def sign(self, aggregator_private_key_hex: str) -> AttestationReport:
        sig = sign_ed25519(aggregator_private_key_hex, self.signing_payload())
        return self.model_copy(update={"aggregator_signature": sig})
