# ADR-0007 — Universal Telemetry Taxonomy

**Status:** Accepted
**Decision:** 2026-09-03

## Context

An Event-centric model cannot represent all telemetry domains Atlas must eventually support, including Linux audit records, cloud operations, container activity, findings, and flow data.

## Decision

Introduce the abstract concept `TelemetryRecordType`.

The conceptual hierarchy is:

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

Requirements:

- `Event` remains valid and is not removed;
- `Artifact` and `Behavior` remain valid concepts;
- legacy/current state is lifecycle metadata, not a telemetry type;
- the universal layer must not require vendor-specific special cases;
- Phase 5.2 production schemas must support the abstract model.

The taxonomy must support, without changing the universal abstraction:

- Windows Security Event 4688;
- Sysmon Event 1;
- Linux audit `EXECVE`;
- AWS CloudTrail `CreateAccessKey`;
- Azure operations;
- GCP audit methods;
- Kubernetes activities such as pods/exec;
- Docker actions;
- database audit actions;
- cloud findings;
- network/flow telemetry.

## Consequences

Positive:

- Atlas remains universal rather than Event-ID-centric;
- future domain expansion does not require redesigning the root telemetry model;
- Event ID becomes one identifier type rather than the ontology.

Constraints:

- Phase 5.1 node schema is provisional;
- production subtype representation is a Phase 5.2 schema task.
