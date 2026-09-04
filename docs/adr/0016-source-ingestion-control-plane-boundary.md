# ADR-0016 — Source & Ingestion Control Plane Boundary

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Phase 5.2 established seven canonical `AtlasRecord` families. Phase 5.3 requires reproducible acquisition and transformation metadata without turning operational build artifacts into canonical knowledge.

## Decision

Atlas separates two corpora:

- **Canonical Knowledge Corpus:** the seven Phase 5.2 `AtlasRecord` families under `schemas/v1/`.
- **Ingestion Artifact Corpus:** connector, acquisition, snapshot, parser, PSR, normalizer, lineage, inventory, validation, review and build artifacts under `schemas/ingestion/v1/`.

`SourceRecord` answers what a source is, including authority, licensing, redistribution and freshness policy. `SourceConnectorDefinition` answers how Atlas acquires that source. They remain distinct.

Ingestion artifacts may use Atlas-owned IDs such as `atlas:connector:atlas.ingestion:<key>` without becoming `AtlasRecord` records. The ingestion contract version stream is independent from Canonical Schema Version 1.0.0.

Phase 5.3 terminates successfully at `PACK_READY`. `PACK_READY` is not released, signed or installed content. Pack runtime, signing, installation and rollback runtime remain outside Phase 5.3.

## Consequences

- no eighth `AtlasRecord` family is introduced;
- `schemas/v1/` remains authoritative and unchanged by Phase 5.3.1;
- ingestion artifacts have independent schemas and lifecycle;
- no storage, search, graph, Desktop, Detection IR, pack-format or signing technology is selected.
