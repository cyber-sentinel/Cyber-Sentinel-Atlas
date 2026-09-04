# ADR-0019 — Validation, Review and Pack-Ready Promotion

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Canonical candidates must not become releasable content merely because parsing and schema validation succeeded. Promotion requires deterministic validation, inventory safety and human review bound to exact immutable inputs.

## Decision

Phase 5.3 represents validation gates G1 through G15: Acquisition, Security/Integrity, Parser, Source Structure, Normalization, Canonical Schema, Registry, Referential Integrity, Provenance, Semantic Invariants, Inventory/Completeness, Determinism/Replay, Regression, License/Redistribution and Human Review.

`BuildValidationReport` is ingestion/build metadata and is not Canonical `ValidationRecord`.

`ReviewDecision` binds an outcome to the exact candidate build ID, candidate corpus digest, inventory diff ID/digest, policy version, review timestamp, actor, findings and exceptions. Outcomes are `approved`, `approved-with-exceptions`, `rejected`, and `needs-changes`. Candidate mutation after review invalidates the approval. Mandatory validation failures cannot be waived through ordinary review.

High-risk policy can require four-eyes/escalated review for bulk disappearance, major inventory/licensing/source-authority changes, canonical identity remapping, lifecycle/supersession changes, mass relationship changes and major mapping-profile changes. Reviewer identity-provider implementation remains open.

The successful state sequence ends at:

```text
DRAFT → ACQUIRED → PARSED → NORMALIZED → VALIDATING → VALIDATED
→ REVIEW_REQUIRED → APPROVED → PACK_READY
```

Failure states include `FAILED`, `QUARANTINED`, and `REJECTED`. Failed builds must preserve Last Known Good. `PACK_READY` does not mean `SIGNED`, `RELEASED`, or `INSTALLED`.

## Consequences

- promotion is digest-bound and review-bound;
- failed candidates cannot destroy prior good state;
- Phase 5.5 retains ownership of pack signing, installation and rollback runtime.
