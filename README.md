# Cyber-Sentinel-Atlas

**Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the signature product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security records, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed knowledge system.

> Branch status: **Phase 5.1 COMPLETE; Stage 1 COMPLETE; Phase 5.2 Canonical Data Model IN PROGRESS — REVISION 2**
> Authoritative `main`: Phase 5.2 remains **NOT STARTED** until PR #4 is explicitly approved and merged.
> Visibility: **Private during active development**

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDRs, cloud platforms, container runtimes, databases, vendor documentation, detection repositories, threat intelligence, and incident-response references. Atlas makes those relationships searchable and operational.

```text
Platform / Technology
        ↓
Telemetry Provider / Source
        ↓
Telemetry Record / Artifact
        ↓
Security Meaning / Behavior
        ↓
ATT&CK / D3FEND / CAR
        ↓
Detection / Hunt
        ↓
Investigation / DFIR
        ↓
Response / Defensive Action
        ↓
Claim-level Sources & Provenance
```

## Product Position

Atlas is a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform + Detection Engineering Platform**. It is not another Event ID wiki, another detection-rule repository, another ATT&CK browser, a SIEM-specific content portal, or an AI system without inspectable evidence.

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

Schema contract under architecture review: **1.0.0**, JSON Schema Draft 2020-12. Record families: EntityRecord, ClaimRecord, RelationshipRecord, SourceRecord, ValidationRecord, VersionRecord, CoverageSnapshot. Revision 2 hardens typed references, provenance semantics, extension registries, coverage numerator meaning, alias/native integrity, authoritative trust, HTTPS sources, datetime ordering, registry contracts, and schema URI authority.

## Initial MVP Domain

The MVP remains intentionally narrow: Windows Security Events, Sysmon, PowerShell, Active Directory, MITRE ATT&CK, selected D3FEND/CAR relationships, validated DefenseOps detections/hunts, provenance, and offline deterministic search. Cross-domain Phase 5.2 fixtures validate the universal model only; they do not authorize production ingestion.

## Ecosystem

```text
Cyber-Sentinel
├── DefenseOps  → approved defensive engineering source for validated content
└── Atlas       → knowledge graph, search, offline runtime, analyst workspace and product interfaces
```

Cyber-Sentinel-Forge is retired as an independent Atlas architectural component; historical Forge material is preserved rather than automatically deleted. DefenseOps content enters Atlas only through versioned ingestion, provenance, validation and controlled release gates.

## Documentation

### Product Foundation
- [Project State](docs/project-state.md)
- [Product Vision](docs/product/product-vision.md)
- [Product Principles](docs/product/product-principles.md)
- [Personas](docs/product/personas.md)
- [Competitive Positioning](docs/product/competitive-positioning.md)

### Architecture
- [System Context](docs/architecture/system-context.md)
- [Canonical Data Model v1](docs/architecture/canonical-data-model-v1.md)
- [Schema Versioning & Migration](docs/architecture/schema-versioning-and-migration.md)
- [Knowledge Graph Model](docs/architecture/knowledge-graph-model.md)
- [Canonical Identifier Architecture](docs/architecture/canonical-identifier-architecture.md)
- [Source & Provenance Model](docs/architecture/source-provenance-model.md)
- [Search Architecture](docs/architecture/search-architecture.md)
- [AI / RAG Architecture](docs/architecture/ai-rag-architecture.md)
- [Offline-first Architecture](docs/architecture/offline-first-architecture.md)
- [API / CLI Architecture](docs/architecture/api-cli-architecture.md)
- [Security Architecture](docs/architecture/security-architecture.md)
- [Coverage Model](docs/architecture/coverage-model.md)
- [Telemetry Lifecycle](docs/architecture/telemetry-lifecycle.md)

### Product Delivery
- [UX Information Architecture](docs/ux/ux-information-architecture.md)
- [MVP Scope](docs/mvp/mvp-scope.md)
- [MVP Release Gates](docs/mvp/release-gates.md)
- [Roadmap](docs/roadmap.md)
- [Architecture Decision Records](docs/adr/)

## Core Principle

> **No technical claim without provenance. No AI answer without inspectable evidence. No engine-specific syntax confused with the underlying security concept.**

**Maintainer:** Ali RahimDabagh  
**GitHub:** `cyber-sentinel`
