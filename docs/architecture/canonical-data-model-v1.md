# Canonical Data Model v1

Schema contract: **1.0.0** — Phase 5.2 under architecture review.

AtlasRecord discriminates seven first-class record families: EntityRecord, ClaimRecord, RelationshipRecord, SourceRecord, ValidationRecord, VersionRecord, and CoverageSnapshot. The model implements ADR-0001 through ADR-0015 without selecting storage, graph, search, Desktop, Detection IR, pack-format or signing technology.

## Canonical schema URI policy

Canonical `$id` base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`

Each schema `$id` equals this base plus its path relative to `schemas/v1/`; internal `$ref` values use the same base.

## Common envelope and extensions

Every record carries `schema_version`, `record_kind`, canonical `id`, `record_revision`, offset-aware `created_at`/`updated_at`, and `curation_status`. Extensions are optional, but every extension namespace must be registered for every record family and `(namespace, schema_version)` must be unique per record.

## Entity identity, native identifiers and aliases

Canonical entity IDs remain `atlas:<entity-type>:<namespace>:<canonical-key>`. Native identifiers are structured/lossless. A non-empty native identifier collection has at least one context-aware primary identifier; duplicate semantic tuples are rejected. Aliases are resolution metadata, not identity. Alias collisions are evaluated across value/case behavior and effective scope (namespace, entity type, provider, locale); overlapping scopes cannot map the same alias to different canonical entities.

## Typed referential integrity

References are checked for both existence and target semantics. Applicability platform/product/provider/version/claim references resolve to their matching record/type families. Claim `entity-ref` resolves to EntityRecord; evidence sources resolve to SourceRecord; VersionRecord subjects are EntityRecord or SourceRecord; CoverageSnapshot subjects are EntityRecord.

Universal telemetry spine endpoint rules include:

```text
product --HAS_TELEMETRY_PROVIDER--> telemetry-provider
telemetry-provider --HAS_TELEMETRY_SOURCE--> telemetry-source
telemetry-source --EMITS--> event|audit-record|audit-action|operation|activity|finding|flow-record
telemetry-record --HAS_FIELD--> field
```

`RUNS_ON` requires EntityRecord endpoints.

## Claim/relationship provenance

Claim evidence remains source-backed. `PRECEDES` and `FOLLOWS` are semantic relationships and require supporting claims, as do other material semantic edges. Authoritative claims require approved Tier A direct/normalized evidence; authoritative relationships require at least one supporting authoritative trusted claim.

## Sources

`canonical_urls` are canonical HTTPS locations only. Non-HTTPS schemes, embedded credentials, and temporary/signed credential query URLs are rejected.

## Coverage semantics

CoverageSnapshot stores denominator, numerator and state counts but never stores `coverage_percent`. `numerator_basis` defines what the numerator means. Telemetry basis is one of `collected`, `normalized`, `validated`, `published`; detection basis is one of `covered`, `validated`. `numerator_count` must exactly equal `state_counts[numerator_basis]`; percentage remains derived.

## Registries

Controlled registries enforce entity types, namespaces, relationship types, native identifier types, claim predicates and alias kinds. `registry_version` has an independent lifecycle from schema version. Registry identities and values are unique.

## Scope boundary

Cross-domain records under `fixtures/phase-5.2/` are sanitized schema fixtures only and do not authorize Phase 5.3 production ingestion. Phase 5.1 legacy schemas remain preserved.
