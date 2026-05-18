"""Smoke tests for the shared models."""

from __future__ import annotations

import time

from mining_types import (
    AttestationReport,
    Capability,
    FaultCode,
    KvMetadata,
    OffChainHeartbeat,
    OperatorSummary,
    OperatorTier,
    Quantization,
    Receipt,
    SettlementBatch,
    blake2_256,
    canonical_json,
    generate_keypair,
    public_key_from_private,
    sign_ed25519,
    verify_ed25519,
)


def test_canonical_json_is_stable() -> None:
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b


def test_receipt_roundtrip_and_signature() -> None:
    priv, pub = generate_keypair()
    r = Receipt(
        job_id="0x" + "11" * 32,
        operator_id=pub,
        model_id="0x" + "22" * 32,
        model_weight_hash="0x" + "33" * 32,
        customer_nonce="0x" + "44" * 32,
        request_hash="0x" + "55" * 32,
        response_hash="0x" + "66" * 32,
        kernel_pack_hash="0x" + "77" * 32,
        attestation_report_hash="0x" + "88" * 32,
        timestamp_ms=int(time.time() * 1000),
        gateway_id="0x" + "99" * 32,
    )
    signed = r.sign(priv)
    assert signed.operator_signature
    assert signed.content_hash() == r.content_hash()
    assert signed.kv_metadata == KvMetadata()


def test_attestation_report_hash() -> None:
    priv, _ = generate_keypair()
    ar = AttestationReport(
        operator_id="op-1",
        tier=OperatorTier.DC_STANDARD,
        measured_vm_bundle=blake2_256(b"vm"),
        timestamp_ms=1,
    )
    signed = ar.sign(priv)
    assert signed.aggregator_signature
    assert len(signed.report_hash()) == 64


def test_heartbeat_signature() -> None:
    priv, _ = generate_keypair()
    hb = OffChainHeartbeat(
        operator_id="op-1",
        capabilities=[Capability(base_model_id="m-1", quantization=Quantization.FP16)],
    )
    signed = hb.sign(priv)
    assert signed.signature


def test_settlement_batch_merkle_root_changes_with_receipts() -> None:
    priv, _ = generate_keypair()
    r = Receipt(
        job_id="j", operator_id="o", model_id="m",
        model_weight_hash="w", customer_nonce="n", request_hash="rq",
        response_hash="rs", kernel_pack_hash="k", attestation_report_hash="a",
        timestamp_ms=1, gateway_id="g",
    )
    root_empty = SettlementBatch.merkle_root_of([])
    root_one = SettlementBatch.merkle_root_of([r])
    assert root_empty != root_one
    b = SettlementBatch(
        batch_id="b", epoch_number=1, gateway_id="g",
        receipt_count=1, merkle_root=root_one,
        per_operator_summary=[
            OperatorSummary(
                operator_id="o", receipts_count=1,
                aggregate_tokens_served=10, aggregate_mint_useful=5,
                merkle_subroot=root_one,
            ),
        ],
    )
    signed = b.sign(priv)
    assert signed.gateway_signature


def test_fault_code_severity() -> None:
    assert FaultCode.WRONG_MODEL.base_severity_bps() == 1000
    assert FaultCode.HEARTBEAT_MISS.base_severity_bps() == 0
    assert FaultCode.DEVICE_CERT_COLLISION.base_severity_bps() == 10000


def test_ed25519_sign_verify_roundtrip() -> None:
    priv, pub = generate_keypair()
    assert len(priv) == 64
    assert len(pub) == 64
    assert public_key_from_private(priv) == pub
    msg = b"hello orogen"
    sig = sign_ed25519(priv, msg)
    assert len(sig) == 128
    assert verify_ed25519(pub, msg, sig) is True


def test_ed25519_verify_rejects_wrong_message() -> None:
    priv, pub = generate_keypair()
    sig = sign_ed25519(priv, b"original")
    assert verify_ed25519(pub, b"tampered", sig) is False


def test_ed25519_verify_rejects_wrong_key() -> None:
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    sig = sign_ed25519(priv, b"msg")
    assert verify_ed25519(other_pub, b"msg", sig) is False


def test_ed25519_verify_fail_closed_on_garbage() -> None:
    # Any 128-char hex string MUST NOT verify (this was the original C-01 bug).
    _, pub = generate_keypair()
    assert verify_ed25519(pub, b"msg", "00" * 64) is False
    assert verify_ed25519(pub, b"msg", "ab" * 64) is False
    assert verify_ed25519(pub, b"msg", "") is False
    assert verify_ed25519(pub, b"msg", "not-hex") is False
    assert verify_ed25519("", b"msg", "00" * 64) is False
    # Wrong-length signatures rejected.
    assert verify_ed25519(pub, b"msg", "00" * 32) is False


def test_ed25519_verify_no_env_bypass(monkeypatch) -> None:
    # The legacy MINING_VERIFY_LAX env var must have no effect.
    monkeypatch.setenv("MINING_VERIFY_LAX", "1")
    _, pub = generate_keypair()
    assert verify_ed25519(pub, b"msg", "00" * 64) is False


def test_receipt_signature_verifies_against_operator_pubkey() -> None:
    priv, pub = generate_keypair()
    r = Receipt(
        job_id="0x" + "11" * 32,
        operator_id=pub,
        model_id="0x" + "22" * 32,
        model_weight_hash="0x" + "33" * 32,
        customer_nonce="0x" + "44" * 32,
        request_hash="0x" + "55" * 32,
        response_hash="0x" + "66" * 32,
        kernel_pack_hash="0x" + "77" * 32,
        attestation_report_hash="0x" + "88" * 32,
        timestamp_ms=1,
        gateway_id="0x" + "99" * 32,
    )
    signed = r.sign(priv)
    assert verify_ed25519(pub, signed.signing_payload(), signed.operator_signature) is True


def test_settlement_batch_signature_verifies_against_gateway_pubkey() -> None:
    priv, pub = generate_keypair()
    root = SettlementBatch.merkle_root_of([])
    b = SettlementBatch(
        batch_id="b", epoch_number=1, gateway_id=pub,
        receipt_count=0, merkle_root=root, per_operator_summary=[],
    )
    signed = b.sign(priv)
    assert verify_ed25519(pub, signed.signing_payload(), signed.gateway_signature) is True


def test_heartbeat_signature_verifies_against_operator_pubkey() -> None:
    priv, pub = generate_keypair()
    hb = OffChainHeartbeat(
        operator_id=pub,
        capabilities=[Capability(base_model_id="m-1", quantization=Quantization.FP16)],
    )
    signed = hb.sign(priv)
    assert verify_ed25519(pub, signed.signing_payload(), signed.signature) is True
