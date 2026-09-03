# Knowledge Graph Model

## Goal

Represent cyber defense knowledge as explicit entities, claims, typed relationships, provenance, lifecycle, and versioned measurements rather than disconnected pages.

## Universal Telemetry Spine

Per [ADR-0007](../adr/0007-universal-telemetry-taxonomy.md):

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
        ├── Operation
        ├── Activity
        ├── Finding
        └── FlowRecord
```

Event remains a valid subtype. Atlas is not Event-ID-centric.

## Canonical Concept Families

The conceptual model must support at minimum:

- Platform
- Product
- Technology
- TelemetryProvider
- TelemetrySource
- TelemetryRecordType
- Event
- AuditRecord
- Operation
- Activity
- Finding
- FlowRecord
- Field
- Artifact
- Behavior
- ATTACKTechnique
- ATTACKTactic
- D3FENDTechnique
- CARAnalytic
- Detection
- Hunt
- InvestigationProcedure
- ResponseAction
- DefensiveControl
- Source
- Claim
- ValidationRecord
- VersionRecord
- CoverageSnapshot / CoverageRecord

Phase 5.2 determines exact production schema representation and controlled vocabulary.

## Canonical Identifiers

Per [ADR-0005](../adr/0005-canonical-identifier-architecture.md):

```text
atlas:<entity-type>:<namespace>:<canonical-key>
```

Examples:

```text
atlas:event:microsoft.windows.security:4688
atlas:event:microsoft.sysmon:1
atlas:audit-record:linux.audit:execve
atlas:attack-technique:mitre.attack:t1059.001
atlas:operation:aws.cloudtrail.iam:createaccesskey
atlas:activity:kubernetes.audit:create.pods.exec
atlas:audit-action:mongodb.audit:authcheck
atlas:detection:defenseops:det-win-001
```

Canonical IDs are lowercase internal identities.

Native identifiers and aliases are separately preserved.

## Core Relationship Semantics

The graph must support relationships including:

- RUNS_ON
- EMITS
- HAS_FIELD
- INDICATES
- RELATED_TO
- EQUIVALENT_SIGNAL
- PRECEDES
- FOLLOWS
- MAPS_TO_ATTACK
- COUNTERED_BY
- DETECTED_BY
- HUNTED_BY
- INVESTIGATED_BY
- RESPONDED_BY
- REQUIRES_TELEMETRY
- DERIVED_FROM
- SUPPORTED_BY
- SUPERSEDES
- SUPERSEDED_BY
- VERSION_OF
- VALIDATED_BY

Relationship vocabulary remains controlled and source/provenance aware.

## Claim as a First-Class Object

A material technical statement is not stored only as prose.

Conceptual example:

```text
Claim:
  subject: atlas:event:microsoft.windows.security:4688
  predicate: "represents"
  value: "new process creation"
  confidence: authoritative
  valid_for:
    platform: Windows
  sources:
    - source-id
```

This enables:

- claim-level citations;
- conflicting-source handling;
- version-specific semantics;
- AI grounding;
- change auditing.

## Relationship Quality

Every material relationship should support:

- relationship type;
- source/derivation;
- confidence;
- applicable version;
- validation state;
- created/updated metadata.

## Lifecycle

Telemetry lifecycle uses:

- current
- legacy
- deprecated
- superseded
- retired

Lifecycle state is metadata, not a telemetry subtype.

See [Telemetry Lifecycle](telemetry-lifecycle.md).

## Coverage

Coverage is represented by versioned measurements rather than mutable percentages on entities.

See [Coverage Model](coverage-model.md).

## Schema Boundary

The graph model is conceptual.

Storage technology, graph database choice, embedded database choice, and search implementation must not leak into the canonical domain model.

The existing Phase 5.1 JSON schemas are provisional until Phase 5.2 implements the accepted ADRs.
