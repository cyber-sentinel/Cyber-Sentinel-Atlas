# Schema Versioning and Phase 5.1 Migration

## Independent versions

Atlas distinguishes:

- canonical schema version;
- record revision;
- product version;
- source version;
- platform/product/provider VersionRecords.

Schema v1 starts at `1.0.0` and follows Semantic Versioning principles defined in ADR-0015.

## Migration inventory

Phase 5.1 provisional IDs are explicitly mapped under `migrations/phase-5.1-to-v1/`.

Required reviewed examples:

```text
atlas:event:windows-security:4688
→ atlas:event:microsoft.windows.security:4688

atlas:event:sysmon:1
→ atlas:event:microsoft.sysmon:1

atlas:attack:T1059.001
→ atlas:attack-technique:mitre.attack:t1059.001
```

When an old Atlas ID refers to the same identity, it is preserved as a `legacy-canonical-id` alias on the new EntityRecord. Distinct historical telemetry identities remain distinct entities.

## Deprecated ambiguity

Phase 5.1 used `deprecated` in a mixed status vocabulary. The migration map therefore declares `deprecated_status_auto_migration=false`. Any real deprecated record requires explicit interpretation into lifecycle and/or curation state.

## Legacy schemas

`schemas/atlas-node.schema.json` and `schemas/atlas-edge.schema.json` remain untouched during Phase 5.2 review. They may later be archived or wrapped only after migration/reference inventory and Architecture Authority review.

## Referential integrity

Phase 5.2 validation treats missing canonical entity/source/claim/version/relationship endpoints as failures inside the fixture corpus. Cross-pack dependency mechanics remain an open later decision.