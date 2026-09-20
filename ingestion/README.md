# ATLAS Ingestion Control Plane

The `ingestion/` tree contains the governed source-acquisition, parsing, normalization, mapping, inventory, and source-profile assets that feed ATLAS canonical knowledge.

Phase 5.3 is **complete and merged**. The control plane now includes reviewed implementations for ATT&CK, Windows Security documentation/provider metadata, Sysmon documentation/schema evidence, D3FEND, CAR, and the controlled DefenseOps boundary.

## Pipeline boundary

```text
Pinned / controlled source
        ↓
Acquisition + immutable evidence
        ↓
Parser → Parsed Source Representation (PSR)
        ↓
Normalizer + mapping profile
        ↓
Canonical candidate records + lineage
        ↓
Inventory diff / validation / human review
        ↓
PACK_READY eligibility
```

Ingestion artifacts are not themselves canonical `AtlasRecord` truth. Promotion requires validation, provenance, lifecycle/applicability handling, and the canonical contracts under `schemas/v1/`.

## Determinism and security

- deterministic parser/normalizer execution is offline and must not depend on AI;
- source content is treated as untrusted data and is never executed;
- mapping/profile versions and digests are explicit;
- unknown structured fields are preserved or reported rather than silently discarded;
- inventory completeness is measured against an explicit source/provider scope;
- source licensing and redistribution state remain explicit release controls;
- credentials and private acquisition secrets must never be committed.

## Coverage authority

This README describes the ingestion control plane and intentionally does not duplicate moving encyclopedia-coverage counters. Current accepted coverage is governed by:

- `content/encyclopedia/coverage-manifest.json` — family-level denominator and numerator authority;
- `content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json` — frozen Windows Security Auditing provider/channel/build scope;
- `content/encyclopedia/sysmon-15.22-coverage.snapshot.json` — frozen Sysmon 15.22 denominator and current accepted numerator.

Human-readable status is projected in `docs/current-status.md` and `README.md`. If a human-readable counter diverges, the machine-readable coverage state is authoritative and the documentation must be synchronized rather than the gate weakened.
