# ADR-0005 — Canonical Identifier Architecture

**Status:** Accepted
**Decision:** 2026-09-03

## Context

Atlas must resolve and relate heterogeneous telemetry and security knowledge without allowing any vendor-native identifier scheme to define the universal domain model.

## Decision

The canonical Atlas identifier structure is:

```text
atlas:<entity-type>:<namespace>:<canonical-key>
```

Rules:

- canonical IDs are internal stable identities;
- canonical IDs are lowercase;
- `entity-type` comes from a controlled Atlas vocabulary;
- `namespace` provides source/product context;
- `canonical-key` is deterministic and unique within the namespace;
- vendor/native identifiers are stored separately and are never silently rewritten or discarded;
- aliases are searchable identifiers/labels only and do not replace canonical IDs;
- ambiguous aliases must be namespace/scoped;
- distinct historical telemetry identities must not be collapsed into aliases.

Approved examples:

```text
atlas:event:microsoft.windows.security:4688
atlas:event:microsoft.sysmon:1
atlas:audit-record:linux.audit:execve
atlas:attack-technique:mitre.attack:t1059.001
atlas:operation:aws.cloudtrail.iam:createaccesskey
atlas:operation:microsoft.azure.activity:microsoft.compute.virtualmachines.write
atlas:operation:gcp.audit:google.iam.admin.v1.createserviceaccount
atlas:activity:kubernetes.audit:create.pods.exec
atlas:activity:docker.events:container.exec-start
atlas:audit-action:mongodb.audit:authcheck
atlas:tool:lolbas:certutil
atlas:tool:gtfobins:bash
atlas:detection:defenseops:det-win-001
```

Native identifiers are represented separately, for example:

```yaml
native_identifier:
  type: event_id
  value: "4688"
```

or:

```yaml
native_identifier:
  type: attack_id
  value: "T1059.001"
```

or:

```yaml
native_identifier:
  type: aws_event_name
  value: "CreateAccessKey"
```

## Legacy Handling

Historically distinct telemetry retains its own canonical identity.

Example:

```text
atlas:event:microsoft.windows.security:592
atlas:event:microsoft.windows.security:4688
```

Their historical relationship is modeled through lifecycle metadata and graph relationships, not by replacing one canonical ID with the other.

Required relationship semantics include:

- SUPERSEDES
- SUPERSEDED_BY
- EQUIVALENT_SIGNAL
- VERSION_OF
- RELATED_TO

## Alias Handling

Aliases may include:

- native identifier spelling;
- case-sensitive native form;
- common names;
- historical names;
- provider-qualified names;
- display labels.

Aliases must not silently merge distinct entities.

## Consequences

Positive:

- universal domain model remains vendor-neutral;
- native identifiers remain searchable and lossless;
- legacy/current telemetry can coexist;
- identifiers are deterministic and portable.

Constraints:

- current Phase 5.1 schemas and examples are provisional and require migration/inventory during Phase 5.2;
- exact schema representation of native identifiers and aliases is a Phase 5.2 implementation task.
