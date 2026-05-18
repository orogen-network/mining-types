# mining-types

Shared Pydantic v2 data models for the Orogen network. Encodes the wire/JSON shapes
described in `chain-tooling-rust/specs/RFC-0001` through `RFC-0005`.

This package is intentionally tiny: no I/O, no HTTP, no crypto beyond helpers around
ed25519 / SHA-256 utilities. Every service (worker, gateway, validator, attestation)
imports from here so cross-service contracts stay consistent.

Decision: a single shared package was chosen over per-service vendoring because the
four primary services all need byte-identical canonical encoding for receipts and
batch settlement (RFC-0001 / RFC-0004). Splitting the schema would have invited drift.
