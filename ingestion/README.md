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
