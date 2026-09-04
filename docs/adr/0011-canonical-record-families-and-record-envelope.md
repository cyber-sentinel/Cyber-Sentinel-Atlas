# ADR-0011 — Canonical Record Families and Record Envelope

**Status:** Accepted
**Decision:** 2026-09-04

## Context

The provisional Phase 5.1 generic node/edge schemas are insufficient for production-grade provenance, validation, versioning, coverage and lifecycle semantics.

## Decision

Atlas schema v1 uses seven first-class record families: EntityRecord, ClaimRecord, RelationshipRecord, SourceRecord, ValidationRecord, VersionRecord and CoverageSnapshot, discriminated by AtlasRecord. All records use a common envelope with independent `schema_version`, `record_revision`, timestamps and `curation_status`. Curation status remains independent from technology lifecycle. Canonical roots remain strict and vendor-specific data is confined to explicit namespaced extensions.

### Revision 2 invariants

- Extension registry membership is enforced for every record family, not only EntityRecord.
- Duplicate extensions are rejected by `(namespace, schema_version)` identity.
- `created_at` / `updated_at` ordering is validated as offset-aware datetime semantics, never lexicographic string order.
- Schema `$id` values use the project-controlled GitHub raw path documented in `schemas/v1/README.md`.

## Consequences

The domain model stays JSON-compatible, portable and independent from storage/search/Desktop technology choices.
