# Cyber-Sentinel-Atlas

**Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the signature product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security records, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed knowledge system.

> Branch status: **Phase 5.1 COMPLETE; Stage 1 COMPLETE; Phase 5.2 Canonical Data Model IN PROGRESS — Architecture Review Required**
> Authoritative `main`: Phase 5.2 remains **NOT STARTED** until this branch is approved and merged.
> Visibility: **Private during active development**

## Product Position

Atlas is a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform + Detection Engineering Platform**. It is not an Event-ID-only wiki, a vendor-specific detection portal, or an AI system without inspectable evidence.

## Architecture Sequence

```text
Canonical Data Model
        ↓
Source / Ingestion Core
        ↓
Deterministic Search Core
        ↓
Offline Pack Runtime / Shared Core
        ↓
Windows Desktop MVP
        ↓
Web / PWA
        ↓
API / CLI
        ↓
Grounded AI
```

The official user-facing CLI command is `atlas`.

## Phase 5.2 Canonical Model

Schema contract under review: **1.0.0** using JSON Schema Draft 2020-12.

Record families:

- EntityRecord
- ClaimRecord
- RelationshipRecord
- SourceRecord
- ValidationRecord
- VersionRecord
- CoverageSnapshot

See:

- [Project State](docs/project-state.md)
- [Canonical Data Model v1](docs/architecture/canonical-data-model-v1.md)
- [Schema Versioning & Migration](docs/architecture/schema-versioning-and-migration.md)
- [Knowledge Graph Model](docs/architecture/knowledge-graph-model.md)
- [Canonical Identifier Architecture](docs/architecture/canonical-identifier-architecture.md)
- [Source & Provenance](docs/architecture/source-provenance-model.md)
- [Coverage Model](docs/architecture/coverage-model.md)
- [Telemetry Lifecycle](docs/architecture/telemetry-lifecycle.md)
- [Roadmap](docs/roadmap.md)
- [Architecture Decision Records](docs/adr/)

## MVP Boundary

MVP content remains intentionally narrow: Windows Security Events, Sysmon, PowerShell, Active Directory, MITRE ATT&CK, selected D3FEND/CAR relationships, validated DefenseOps content, provenance, and offline deterministic search.

Cross-domain Phase 5.2 fixtures for Linux/cloud/container/database telemetry validate the universal schema only; they do not authorize production ingestion.

## Ecosystem

```text
Cyber-Sentinel
├── DefenseOps  → approved defensive engineering source
└── Atlas       → knowledge graph, search, offline runtime and analyst product
```

Forge is retired as an independent Atlas component. Historical Forge material is preserved rather than automatically deleted.

## Core Principle

> **No technical claim without provenance. No AI answer without inspectable evidence. No engine-specific syntax confused with the underlying security concept.**

**Maintainer:** Ali RahimDabagh  
**GitHub:** `cyber-sentinel`
