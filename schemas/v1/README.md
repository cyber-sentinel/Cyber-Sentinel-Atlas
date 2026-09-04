# Atlas Canonical Schemas v1

Schema contract version: **1.0.0** (under Phase 5.2 architecture review).

Canonical schema URI base:

`https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`

This base is derived from the project-controlled GitHub repository path rather than the previously unverified `cyber-sentinel.dev` domain. `$id` values equal the canonical base plus repository-relative paths under `schemas/v1/`; internal `$ref` values use the same base.

The repository path `/schemas/v1/` is stable for schema major v1. Breaking schema changes require a new major schema path/version. This URI policy may change later only through an explicit migration/ADR decision.

The canonical domain model uses JSON Schema Draft 2020-12 and remains storage-engine independent. Schema version, registry version, record revision, product version and source version have independent lifecycles.

Record families:

- EntityRecord
- ClaimRecord
- RelationshipRecord
- SourceRecord
- ValidationRecord
- VersionRecord
- CoverageSnapshot

The root contract is `atlas-record.schema.json`. The legacy Phase 5.1 schemas remain outside this directory and are preserved during migration review.
