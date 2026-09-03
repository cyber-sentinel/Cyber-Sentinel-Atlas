# API & CLI Architecture

## Ownership Boundary

Cyber-Sentinel-Forge is retired as an independent Atlas architectural component.

Capability ownership is:

- Atlas consumer/search/investigation capabilities → Atlas interfaces and `atlas` CLI;
- defensive content authoring/engineering capabilities → DefenseOps tooling.

DefenseOps is an approved engineering source for Atlas, but its content still passes Atlas ingestion, provenance, validation, and release controls.

## API Principles

- stable canonical IDs;
- versioned API surface;
- entity-first design;
- explicit provenance;
- no UI-only hidden semantics;
- shared contracts across Desktop, Web/PWA, API, and CLI;
- native identifiers preserved separately from Atlas canonical IDs.

## Candidate API Resources

```text
GET /v1/entities/{id}
GET /v1/telemetry/{id}
GET /v1/events/{id}
GET /v1/techniques/{id}
GET /v1/detections/{id}
GET /v1/hunts/{id}
GET /v1/search
GET /v1/graph/{id}
GET /v1/sources/{id}
GET /v1/claims/{id}
GET /v1/coverage
GET /v1/packs
```

The exact API resource layout remains an implementation decision after Phase 5.2 schema contracts are defined.

## Search API

Future search contracts should support filters such as:

- q
- entity_type
- namespace
- native_identifier_type
- native_identifier_value
- platform
- provider
- attack_id
- engine
- validation_level
- source_class
- lifecycle
- offline_pack

Exact identifier resolution must precede semantic retrieval.

## CLI Direction

The official user-facing command is:

```text
atlas
```

Examples using the approved canonical identifier architecture:

```text
atlas search 4688
atlas show atlas:event:microsoft.windows.security:4688
atlas related t1059.001
atlas detection det-win-001
atlas sources atlas:event:microsoft.windows.security:4688
atlas pack list
atlas validate
```

Future examples may include:

```text
atlas search CreateAccessKey
atlas search EXECVE
atlas show atlas:operation:aws.cloudtrail.iam:createaccesskey
atlas show atlas:audit-record:linux.audit:execve
```

## CLI Rule

The CLI consumes the same canonical model and shared contracts as the Desktop/Web/API surfaces. It must not become a second knowledge implementation or a parallel Forge knowledge engine.

## Open Implementation Decisions

The following are intentionally not frozen:

- CLI packaging/distribution;
- API framework;
- Detection Intermediate Representation;
- exact DefenseOps → Atlas ingestion contract;
- local storage and graph implementation.
