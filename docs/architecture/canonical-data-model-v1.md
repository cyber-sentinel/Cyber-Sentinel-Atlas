# Canonical Data Model v1

Schema contract: **1.0.0**

This document describes the Phase 5.2 production canonical contract under architecture review. It implements ADR-0001 through ADR-0015 without selecting a database, graph engine, search engine, Desktop stack, Detection IR or content-pack format.

## AtlasRecord

`AtlasRecord` is the root union for seven first-class record families:

```text
AtlasRecord
├── EntityRecord
├── ClaimRecord
├── RelationshipRecord
├── SourceRecord
├── ValidationRecord
├── VersionRecord
└── CoverageSnapshot
```

The machine contract is `schemas/v1/atlas-record.schema.json` using JSON Schema Draft 2020-12.

## Common Envelope

All records use independent schema and record revision metadata:

- schema_version
- record_kind
- id
- record_revision
- created_at
- updated_at
- curation_status
- optional registered extensions

Curation status is not lifecycle.

## EntityRecord

EntityRecord carries canonical identity:

- entity_type
- namespace
- canonical_key
- title/localized titles
- native identifiers
- aliases
- lifecycle
- applicability
- extensions

Material technical descriptions belong in ClaimRecords where provenance matters.

### Universal telemetry spine

```text
Platform
  ↓ RUNS_ON / structural context
Product
  ↓ HAS_TELEMETRY_PROVIDER
TelemetryProvider
  ↓ HAS_TELEMETRY_SOURCE
TelemetrySource
  ↓ EMITS
TelemetryRecordType
  ├── Event
  ├── AuditRecord
  ├── AuditAction
  ├── Operation
  ├── Activity
  ├── Finding
  └── FlowRecord
```

`TelemetryRecordType` is conceptual; concrete EntityRecord `entity_type` values represent the specializations. No vendor-specific root property is required.

## Canonical IDs

Canonical entity IDs remain:

`atlas:<entity-type>:<namespace>:<canonical-key>`

JSON Schema enforces syntax. The deterministic validator additionally verifies that EntityRecord `id` equals the value reconstructed from `entity_type`, `namespace` and `canonical_key`.

Native identifiers are first-class structured data and remain lossless. Aliases improve resolution but never redefine identity.

## Claims and provenance

ClaimRecords carry a controlled predicate, typed object, confidence, applicability and evidence. Evidence requires source identity/version, retrieval timestamp, explicit locator, transformation class and reviewer status.

Claim IDs use a full SHA-256 semantic digest after canonical normalization. Evidence lists, timestamps and review state are excluded from semantic identity.

## Relationships

RelationshipRecords reference canonical endpoints and controlled relationship types. Semantic edges use supporting claims/provenance. Relationship IDs use a SHA-256 semantic digest of endpoint/type/optional qualifier, excluding evidence/confidence/review timestamps.

## Sources

SourceRecord is the canonical basis for the source registry. Canonical source URLs are credential-free and source class, licensing/redistribution, freshness and change-detection policies remain explicit.

## Version and applicability

VersionRecord represents platform/product/provider/source/schema versions without forcing one version scheme. Applicability may reference canonical subjects, VersionRecords, scheme-aware constraints and valid-from/to bounds.

## ValidationRecord

Validation is evidence, not a mutable boolean. ValidationRecord records target, validation type, validator type, ruleset/version, result, timestamp and findings.

## CoverageSnapshot

Coverage is a versioned snapshot with declared metric type, scope, denominator definition/count, state counts, source/inventory version, content/schema version, measurement time and validation state.

`coverage_percent` is intentionally absent; percentages are derived from explicit counts.

## Controlled registries

Syntax belongs in JSON Schema; controlled vocabulary membership belongs in versioned registries under `model/registries/` and deterministic validation.

## Extension boundary

Canonical root structures remain strict. Vendor-specific data is allowed only inside registered namespaced extensions or structured native-identifier components. Extensions cannot change canonical identity.

## Referential integrity

All references in the Phase 5.2 fixture corpus resolve locally. Future pack/dependency boundaries must be explicit before unresolved cross-pack references are allowed.

## Scope boundary

Cross-domain records in `fixtures/phase-5.2/` are sanitized architecture/schema fixtures only. They do not authorize Phase 5.3 ingestion.