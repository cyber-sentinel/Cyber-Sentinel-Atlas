# Cyber-Sentinel-Atlas

**Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the signature product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security records, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed knowledge system.

> Branch status: **Phase 5.1 COMPLETE; Stage 1 COMPLETE; Phase 5.2 Canonical Data Model IN PROGRESS — FINALIZATION**
> Authoritative `main`: Phase 5.2 remains **NOT STARTED** until PR #4 is explicitly approved and merged.
> Visibility: **Private during active development**

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDRs, cloud platforms, container runtimes, databases, vendor documentation, detection repositories, threat intelligence, and incident-response references.

Atlas makes those relationships searchable and operational:

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

Atlas is **not**:

- another Event ID wiki;
- another detection-rule repository;
- another ATT&CK browser;
- another SIEM-specific content portal;
- an AI chatbot without verifiable sources.

Atlas is designed as a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform + Detection Engineering Platform**.

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

The schema contract under architecture review is **1.0.0**, using JSON Schema Draft 2020-12.

Record families:

- EntityRecord
- ClaimRecord
- RelationshipRecord
- SourceRecord
- ValidationRecord
- VersionRecord
- CoverageSnapshot

Canonical schema URI base:

```text
https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/
```

The permanent canonical semantic validator is `tools/validate_phase52.py`. Permanent model tests are `tests/test_phase52_model.py` and `tests/test_phase52_invariants.py`.

## Initial MVP Domain

The first usable MVP intentionally starts narrow:

- Windows Security Events
- Sysmon
- PowerShell
- Active Directory
- MITRE ATT&CK relationships
- selected D3FEND/CAR relationships
- DefenseOps validated detections and hunts
- investigation pivots
- official-source provenance
- fast exact/lexical search
- offline-first local dataset

The architecture is intentionally extensible to Linux, macOS, Exchange, SharePoint, Microsoft 365, Azure, AWS, Google Cloud, Docker, Kubernetes, DevOps/CI-CD, databases, LOLBAS, GTFOBins, DFIR, incident response, and cyber deception. Cross-domain Phase 5.2 fixtures validate the universal model only; they do not authorize production ingestion.

## Ecosystem

```text
Cyber-Sentinel
├── DefenseOps  → approved defensive engineering source for validated content
└── Atlas       → knowledge graph, search, offline runtime, analyst workspace and product interfaces
```

Cyber-Sentinel-Forge is retired as an independent Atlas architectural component. Historical Forge material, if present, is preserved rather than deleted automatically.

DefenseOps content enters Atlas only through versioned ingestion, provenance, validation, and controlled release gates.

## Foundation Documents

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

---

**Maintainer:** Ali RahimDabagh
**GitHub:** `cyber-sentinel`
