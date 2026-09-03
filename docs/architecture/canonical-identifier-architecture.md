# Canonical Identifier Architecture

Authoritative decision: [ADR-0005](../adr/0005-canonical-identifier-architecture.md).

## Canonical Structure

```text
atlas:<entity-type>:<namespace>:<canonical-key>
```

Atlas canonical IDs are stable internal identities.

They are distinct from vendor/native identifiers.

## Rules

- canonical IDs are lowercase;
- entity types come from a controlled Atlas vocabulary;
- namespace supplies product/source context;
- canonical keys are deterministic and namespace-unique;
- native identifiers are preserved losslessly as separate data;
- aliases are searchable labels/identifiers, not identity replacements;
- ambiguous aliases require scope/namespace;
- historical identities remain distinct when the upstream telemetry itself is distinct.

## Approved Examples

| Domain | Canonical ID | Native identifier |
|---|---|---|
| Windows Security | `atlas:event:microsoft.windows.security:4688` | `event_id=4688` |
| Sysmon | `atlas:event:microsoft.sysmon:1` | `event_id=1` |
| Linux audit | `atlas:audit-record:linux.audit:execve` | `audit_record_type=EXECVE` |
| MITRE ATT&CK | `atlas:attack-technique:mitre.attack:t1059.001` | `attack_id=T1059.001` |
| AWS CloudTrail | `atlas:operation:aws.cloudtrail.iam:createaccesskey` | `aws_event_name=CreateAccessKey` |
| Azure Activity | `atlas:operation:microsoft.azure.activity:microsoft.compute.virtualmachines.write` | native operation preserved separately |
| GCP Audit | `atlas:operation:gcp.audit:google.iam.admin.v1.createserviceaccount` | native method preserved separately |
| Kubernetes audit | `atlas:activity:kubernetes.audit:create.pods.exec` | native verb/resource preserved separately |
| Docker events | `atlas:activity:docker.events:container.exec-start` | native action preserved separately |
| MongoDB audit | `atlas:audit-action:mongodb.audit:authcheck` | native audit action preserved separately |
| LOLBAS | `atlas:tool:lolbas:certutil` | source-native tool name preserved |
| GTFOBins | `atlas:tool:gtfobins:bash` | source-native tool name preserved |
| DefenseOps | `atlas:detection:defenseops:det-win-001` | `detection_id=DET-WIN-001` |

## Native Identifier Model

Conceptually:

```yaml
native_identifier:
  type: event_id
  value: "4688"
```

Native forms may be case-sensitive even though Atlas canonical IDs are lowercase.

## Alias Model

Aliases may include:

- native identifier spelling;
- case-sensitive source-native form;
- common names;
- historical names;
- provider-qualified names;
- display labels.

Aliases must resolve to canonical entities without silently merging distinct identities.

## Provisional Phase 5.1 Schema Inventory

The existing `schemas/atlas-node.schema.json` and `schemas/atlas-edge.schema.json` are foundation schemas created before ADR-0005.

Existing examples such as:

```text
atlas:event:windows-security:4688
atlas:event:sysmon:1
atlas:attack:T1059.001
```

are provisional and must be inventoried/migrated during Phase 5.2.

Stage 1 deliberately does **not** rewrite those schemas.

## Legacy Identity

Old and new telemetry IDs are distinct entities when they represent separately emitted telemetry definitions.

Example:

```text
atlas:event:microsoft.windows.security:592
atlas:event:microsoft.windows.security:4688
```

Relationships and lifecycle metadata express historical correspondence; aliases do not erase distinct identities.
