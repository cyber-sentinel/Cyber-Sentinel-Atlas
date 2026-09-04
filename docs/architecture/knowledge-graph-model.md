# Knowledge Graph Model

## Goal

Represent cyber defense knowledge as explicit canonical entities, claims, typed relationships, provenance, lifecycle, validation, versions and coverage snapshots rather than disconnected pages.

## Record families

Phase 5.2 uses the first-class record families defined in [Canonical Data Model v1](canonical-data-model-v1.md): EntityRecord, ClaimRecord, RelationshipRecord, SourceRecord, ValidationRecord, VersionRecord and CoverageSnapshot.

## Universal telemetry spine

```text
Platform
  ↓
Product
  ↓
TelemetryProvider
  ↓
TelemetrySource
  ↓
TelemetryRecordType
        ├── Event
        ├── AuditRecord
        ├── AuditAction
        ├── Operation
        ├── Activity
        ├── Finding
        └── FlowRecord
```

The spine is vendor-neutral. Event ID is one native identifier type, not the ontology.

## Canonical entity vocabulary

The initial registry supports platform, product, technology, telemetry-provider, telemetry-source, event, audit-record, audit-action, operation, activity, finding, flow-record, field, artifact, behavior, ATT&CK/D3FEND/CAR concepts, detections, hunts, investigation/response/control concepts and tools.

The registry may evolve through controlled review without adding vendor-specific root schema fields.

## Canonical identifiers

Per ADR-0005 and ADR-0012:

`atlas:<entity-type>:<namespace>:<canonical-key>`

Native IDs and aliases remain separate structured data.

## Relationship semantics

The controlled registry preserves Stage 1 relationships and adds only structural spine edges `HAS_TELEMETRY_PROVIDER` and `HAS_TELEMETRY_SOURCE`.

Do not create redundant inverse edge sets merely for traversal convenience. Historical inverse semantics such as SUPERSEDES/SUPERSEDED_BY remain available because both directions may carry explicit source-backed meaning.

## Claims and semantic evidence

Material technical assertions are ClaimRecords. Material semantic relationship edges reference supporting claims so provenance remains inspectable. Structural topology edges may be deterministically validated from the canonical model.

## Lifecycle and curation

Lifecycle (`current`, `legacy`, `deprecated`, `superseded`, `retired`) is independent from curation (`draft`, `review`, `validated`, `published`, `withdrawn`).

## Coverage

Telemetry Coverage and Detection Coverage remain independent CoverageSnapshot metrics with declared scope/version/denominator.

## Storage boundary

The canonical model is JSON-compatible and storage-neutral. No database, graph database, search engine or ORM model is part of the v1 schema contract.