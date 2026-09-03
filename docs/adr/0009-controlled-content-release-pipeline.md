# ADR-0009 — Controlled Content Release Pipeline

**Status:** Accepted
**Decision:** 2026-09-03

## Context

Atlas ingests external authoritative and engineering sources. Direct upstream-to-production mutation would make provenance, validation, rollback, and release integrity unreliable.

## Decision

All Atlas content publication must follow the controlled pipeline:

```text
Official Source
        ↓
Raw Snapshot
        ↓
Parser
        ↓
Normalizer
        ↓
Schema Validation
        ↓
Inventory Diff
        ↓
Tests
        ↓
Human Review
        ↓
Signed Content Pack
        ↓
Release
```

No upstream connector/source may directly mutate the production/public Atlas dataset.

Client installation/update follows:

```text
Released Pack
        ↓
Manifest Verification
        ↓
Signature Verification
        ↓
Checksum Verification
        ↓
Schema/Compatibility Check
        ↓
Preserve Last Known Good
        ↓
Atomic Install
        ↓
Index/Migration
        ↓
Health Check
        ↓
Activation
```

Failure requires rollback to Last Known Good.

## Security / Integrity Requirements

- raw source snapshots are distinguishable from normalized content;
- schema validation occurs before publication;
- inventory diff is reviewable;
- tests and human review are mandatory release gates;
- released packs are signed and checksummed;
- installation is compatibility-aware;
- activation occurs only after health validation;
- a failed update cannot corrupt the last-known-good active dataset.

## Consequences

Positive:

- prevents silent upstream drift;
- supports reproducible review;
- enables signed offline distribution;
- provides a clear rollback boundary.

Constraints:

- signing/key-management implementation remains an open decision;
- exact pack format/naming remains open.
