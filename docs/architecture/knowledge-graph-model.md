# Knowledge Graph Model

## Goal

Represent cyber defense knowledge as explicit entities, claims, and typed relationships rather than a collection of disconnected Markdown pages.

## Canonical Node Types

- Platform
- Product
- Technology
- TelemetrySource
- Event
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

## Example Identifiers

```text
atlas:event:windows-security:4688
atlas:event:sysmon:1
atlas:behavior:powershell-encoded-command
atlas:attack:T1059.001
atlas:detection:defenseops:DET-WIN-001
```

Identifiers are stable and independent from display labels.

## Core Edge Types

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
- VERSION_OF
- VALIDATED_BY

## Claim as a First-Class Object

A technical statement is not stored only as prose.

Example:

```text
Claim:
  subject: atlas:event:windows-security:4688
  predicate: "represents"
  value: "new process creation"
  confidence: authoritative
  valid_for:
    platform: Windows
  sources:
    - source-id
```

This allows:

- claim-level citations;
- conflicting-source handling;
- version-specific semantics;
- AI grounding;
- change auditing.

## Relationship Quality

Every relationship should have:

- relationship type;
- source or derivation;
- confidence;
- applicable version;
- validation state;
- created/updated metadata.

## Schema Boundary

The graph model is conceptual. Storage technology is an implementation choice and must not leak into the domain model.
