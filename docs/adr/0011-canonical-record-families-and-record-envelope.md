# ADR-0011 — Canonical Record Families and Record Envelope

**Status:** Accepted
**Decision:** 2026-09-04

## Context

The Phase 5.1 generic node/edge schemas are insufficient for production-grade provenance, validation, versioning, coverage and lifecycle semantics. Atlas needs explicit first-class record families without coupling the domain model to a storage engine.

## Decision

Atlas schema v1 uses seven first-class record families:

1. EntityRecord
2. ClaimRecord
3. RelationshipRecord
4. SourceRecord
5. ValidationRecord
6. VersionRecord
7. CoverageSnapshot

`AtlasRecord` is the root JSON Schema union that discriminates these families through `record_kind`.

All record families use a shared envelope where semantically applicable:

- `schema_version`
- `record_kind`
- `id`
- `record_revision`
- `created_at`
- `updated_at`
- `curation_status`
- optional namespaced `extensions`

`record_revision` is an integer >= 1.

Curation states are:

- draft
- review
- validated
- published
- withdrawn

Curation status is independent from technology/product lifecycle.

## Consequences

- content state and domain lifecycle cannot be conflated;
- records are portable JSON-compatible contracts;
- storage, graph and search implementations remain open;
- Phase 5.1 schemas remain preserved for compatibility/migration review.