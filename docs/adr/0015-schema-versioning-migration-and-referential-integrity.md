# ADR-0015 — Schema Versioning, Migration and Referential Integrity

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Phase 5.1 schemas and provisional IDs must be migrated explicitly without erasing history. Atlas also requires canonical references that cannot silently dangle.

## Decision

Canonical contracts continue to use JSON Schema Draft 2020-12 and remain JSON-compatible.

Schema contract version follows Semantic Versioning principles:

- MAJOR — breaking structural or semantic change;
- MINOR — backward-compatible additive contract change;
- PATCH — compatible validation/documentation correction.

Schema version is independent from record revision, product version and source version.

Phase 5.1 → v1 migration uses an explicit reviewed map containing old ID, new ID, migration type, reason and review status. Same-identity historical Atlas IDs may become `legacy-canonical-id` aliases. Distinct identities must never be collapsed.

Phase 5.1 `status=deprecated` is never automatically mapped because the old schema mixed curation and lifecycle semantics.

The Phase 5.1 schema files remain preserved until inventory, migration and compatibility review are complete.

Canonical references must resolve within the validated corpus or through a future explicitly declared pack/dependency boundary. Phase 5.2 fixtures require local referential integrity; broken endpoints/source/claim/version references are failures.

## Consequences

Migration is auditable and non-destructive. Canonical graph integrity is enforceable before storage technology is selected, and old foundation schemas remain available for compatibility decisions.