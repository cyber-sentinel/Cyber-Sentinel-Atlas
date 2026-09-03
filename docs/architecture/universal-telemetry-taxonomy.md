# Universal Telemetry Taxonomy

Authoritative decision: [ADR-0007](../adr/0007-universal-telemetry-taxonomy.md).

## Objective

Model security-relevant telemetry across operating systems, cloud platforms, containers, DevOps systems, databases, and network/security products without forcing every source into an Event ID abstraction.

## Conceptual Hierarchy

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

## Core Concepts

### Platform

The broader operating/runtime/service environment.

### Product

A product/service that owns or participates in telemetry production.

### TelemetryProvider

The logical provider/emitter identity responsible for defining or emitting a telemetry family.

### TelemetrySource

A collection/channel/API/file/stream or other retrieval location through which telemetry is obtained.

### TelemetryRecordType

Abstract canonical concept for a defined type of telemetry record.

Specializations:

- Event
- AuditRecord
- Operation
- Activity
- Finding
- FlowRecord

### Artifact

Forensic or investigative evidence remains a separate valid concept.

### Behavior

Security/adversary/operational meaning remains separate from the raw telemetry record type.

## Cross-Domain Validation Examples

The universal model must represent all of the following without a vendor-specific root abstraction:

| Example | Record specialization |
|---|---|
| Windows Security Event 4688 | Event |
| Sysmon Event 1 | Event |
| Linux audit EXECVE | AuditRecord |
| AWS CloudTrail CreateAccessKey | Operation |
| Azure Activity operation | Operation |
| GCP audit method | Operation |
| Kubernetes pods/exec | Activity |
| Docker container exec-start | Activity |
| MongoDB authCheck | AuditRecord / audit action representation |
| cloud security finding | Finding |
| network flow telemetry | FlowRecord |

Exact source-specific classification details remain subject to source-backed Phase 5.2 modeling, but the universal layer must not require a vendor-specific exception.

## Lifecycle Boundary

`current`, `legacy`, `deprecated`, `superseded`, and `retired` are lifecycle metadata.

They are not telemetry record types.

See [Telemetry Lifecycle](telemetry-lifecycle.md).
