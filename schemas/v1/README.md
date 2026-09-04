# Atlas Canonical Schema v1

Schema contract version: **1.0.0**

Machine validation uses JSON Schema Draft 2020-12.

## Record Families

- `atlas-record.schema.json` — root AtlasRecord union
- `entity.schema.json` — EntityRecord
- `claim.schema.json` — ClaimRecord
- `relationship.schema.json` — RelationshipRecord
- `source.schema.json` — SourceRecord
- `validation-record.schema.json` — ValidationRecord
- `version-record.schema.json` — VersionRecord
- `coverage-snapshot.schema.json` — CoverageSnapshot

## Shared Definitions

`defs/` contains strict reusable contracts for canonical IDs, common record metadata, native identifiers, aliases, lifecycle, applicability, evidence, namespaced extensions, and claim objects.

JSON Schema validates structure and syntax. Phase 5.2 deterministic validators additionally enforce registry membership, canonical ID/component consistency, deterministic semantic IDs, reference integrity, source URL secret hygiene, alias ambiguity/scoping, migration rules, coverage semantics, and exact resolution behavior.

The Phase 5.1 schemas remain preserved at `schemas/atlas-node.schema.json` and `schemas/atlas-edge.schema.json`; they are not the v1 production contracts.