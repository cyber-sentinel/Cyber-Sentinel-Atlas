# Schema Versioning and Migration

## Independent versions

Atlas separates canonical `schema_version`, `record_revision`, registry version, product/source versions and future content-pack versions. Schema v1 uses Semantic Versioning principles; controlled registry additions follow their own `registry_version` lifecycle and do not imply a schema version change unless the schema contract itself changes.

## Canonical schema URI

Version 1 schema identifiers use `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`. The validator derives the expected `$id` from repository-relative schema paths and rejects non-canonical internal `$ref` values.

The repository path `/schemas/v1/` is stable for schema major v1. Breaking structural/semantic changes require a new major schema path/version, and changing this URI policy later requires an explicit migration/ADR decision.

## Phase 5.1 migration

The migration inventory explicitly maps provisional identifiers to v1 canonical identifiers and preserves same-identity old Atlas IDs as `legacy-canonical-id` aliases. Phase 5.1 `status=deprecated` is not auto-migrated because it mixed curation and lifecycle semantics.

The legacy `schemas/atlas-node.schema.json` and `schemas/atlas-edge.schema.json` remain preserved until migration/compatibility review is complete.

## Referential integrity

Canonical references must resolve in the validated corpus or a future explicit dependency boundary. For v1, semantically typed references are additionally checked against expected record families/entity types. Wrong-family references fail validation even when the target ID exists.
