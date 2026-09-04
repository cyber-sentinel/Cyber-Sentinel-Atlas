# Phase 5.1 → Phase 5.2 Canonical Model Migration Inventory

The Phase 5.1 schemas remain preserved at:

- `schemas/atlas-node.schema.json`
- `schemas/atlas-edge.schema.json`

They are provisional foundation schemas and are not silently overwritten.

## Migration Rules

- old canonical IDs are mapped explicitly;
- `legacy-canonical-id` aliases are allowed only when identity is genuinely unchanged;
- distinct historical telemetry identities remain distinct entities;
- Phase 5.1 `deprecated` status is **never auto-migrated** because the old schema mixed curation and lifecycle semantics;
- every ambiguous legacy status requires explicit review;
- no destructive schema deletion is part of Phase 5.2.

## Initial Inventory

The machine-readable map is `migration-map.json`.

It covers the minimum approved examples and one DefenseOps canonical-key normalization example.
