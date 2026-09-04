# ADR-0015 — Schema Versioning, Migration and Referential Integrity

**Status:** Accepted  
**Decision:** 2026-09-04

## Decision

Schema versioning follows Semantic Versioning principles and remains independent from product version, record revision, source version and registry version. Phase 5.1 schemas are preserved while explicit migration mappings are reviewed; ambiguous legacy `status=deprecated` is never auto-migrated.

Referential integrity is typed where the contract gives semantic target meaning, not merely existence-checked. Broken or wrong-family references are validation failures. Canonical SourceRecord URLs use HTTPS only and reject credentials and signed/temporary credential query parameters.

Canonical schema URI base for v1 is:

`https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`

The earlier `https://cyber-sentinel.dev/...` base was not retained because project control could not be verified at the v1 merge gate. All `$id` and internal `$ref` values are required to match the project-controlled repository URI policy. The `/schemas/v1/` repository path is stable for schema major v1; breaking schema changes require a new major schema path/version, and changing this URI policy later requires an explicit migration/ADR decision.
