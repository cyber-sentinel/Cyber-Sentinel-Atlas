# Cyber-Sentinel-Atlas

**Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the signature product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security records, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed knowledge system.

> Status: **Phase 5.1 COMPLETE; Stage 1 COMPLETE; Phase 5.2 COMPLETE; Phase 5.3 COMPLETE; Phase 5.3.1–5.3.4 COMPLETE; Phase 5.4 NEXT**
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

The authoritative schema contract is **1.0.0**, using JSON Schema Draft 2020-12.

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

## Phase 5.3 Source & Ingestion Core

Phase 5.3 is **COMPLETE / MERGED**. It established the independent ingestion/control plane, proved deterministic ingestion against ATT&CK, Windows Security, Sysmon, D3FEND and CAR, defined the controlled DefenseOps export boundary, and closed the immutable validation/review/promotion path through `PACK_READY`.

Ingestion Contract Version: **1.0.0**

```text
SourceRecord / source control
        ↓
SourceConnectorDefinition
        ↓
AcquisitionRun → RawSnapshot
        ↓
ParserRun → ParsedSourceRecord
        ↓
NormalizationRun + Lineage
        ↓
Canonical Candidate Corpus
        ↓
Inventory Diff → Validation → Human Review
        ↓
PACK_READY
```

`PACK_READY` is the successful terminal Phase 5.3 state and is not equivalent to signed, released or installed content. The canonical seven-family `AtlasRecord` model remains unchanged.

### Completed slices

- **5.3.1 — Ingestion Foundation / Contracts: COMPLETE / MERGED**
- **5.3.2 — MITRE ATT&CK Structured-Source Canary: COMPLETE / MERGED**
  - Enterprise ATT&CK release `19.2` pinned to upstream commit `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`;
  - deterministic STIX 2.1 Parser → PSR → Normalizer pipeline;
  - phase-aware, fail-closed authorization of real ingestion implementations;
  - unknown structured fields preserved and reported;
  - ambiguous identity quarantined;
  - exact Phase 5.3.1 PSR and RawSnapshot identity contracts enforced;
  - full upstream corpus retrieved transiently in CI and not committed.
- **5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline: COMPLETE / MERGED**
  - PR `#8`, merge commit `84d125c61051442c509a701c2d6bc6ffb85a9090`;
  - post-merge Foundation Hygiene run `33973584356`: SUCCESS;
  - Windows Server 2025 Datacenter 24H2 build `26100.33296` provider inventory: 488 event/version definitions and 423 unique Event IDs;
  - Sysmon `15.21` schema export: 24 schema manifests, 587 parsed event records, current schema `4.91`, 30 current Event IDs;
  - real controlled reference-host export pipeline remains out-of-band from Atlas core;
  - Windows documentation vs provider inventory and Sysmon documentation vs schema inventory remain independent authority dimensions;
  - deterministic structural normalizers create canonical identity shells without inferring unsupported global lifecycle;
  - `4688`, independent legacy `592`, and `sysmon 1` acceptance semantics are preserved without identity collapse;
  - three-layer Raw / Parsed / Canonical inventory diff and reconciliation gates are validated;
  - canonical `schemas/v1` remained unchanged.
- **5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates: COMPLETE / MERGED**
  - PR `#11`, merge commit `7270ba54dbcceb3460e922e82bb3fb20bf149f29`;
  - post-merge Foundation Hygiene run `33977610969`: SUCCESS;
  - post-merge Phase 5.3.4 Canaries run `33977610961`: SUCCESS;
  - D3FEND ontology `1.6.0` pinned to exact official SHA-256 `4909a5bb66b75d2c359624398848936fb56a6b246bcd5cfcd277977a1277753a`;
  - D3FEND live canary produced 272 PSR records and 544 canonical candidate records from the pinned source;
  - CAR sample `CAR-2016-03-001` is pinned to repository commit `1b922fe1527d956e222a99473472e594f10f610b` and Git blob `b0f899e2875d4469ac58838dcb77db59e4feee96`;
  - DefenseOps ingestion is an explicit commit-bound validated-export contract; repository origin does not confer canonical authority;
  - DefenseOps repository licensing remains fail-closed when unknown and G14 is non-waivable;
  - G1–G15, four-eyes high-risk review, stale-review rejection, immutable digest binding and Last Known Good preservation are validated;
  - canonical `schemas/v1` remained unchanged.

### Next phase

- **5.4 — Deterministic Search Core: NEXT / ARCHITECTURE GATE**

Phase 5.3 is not a released content pack. Content-pack signing, archive format, installation and rollback remain Phase 5.5 responsibilities.

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
- [Source & Ingestion Core](docs/architecture/source-ingestion-core.md)
- [Search Architecture](docs/architecture/search-architecture.md)
- [AI / RAG Architecture](docs/architecture/ai-rag-architecture.md)
- [Offline-first Architecture](docs/architecture/offline-first-architecture.md)
- [API / CLI Architecture](docs/architecture/api-cli-architecture.md)
- [Security Architecture](docs/architecture/security-architecture.md)
- [Coverage Model](docs/architecture/coverage-model.md)
- [Telemetry Lifecycle](docs/architecture/telemetry-lifecycle.md)
- [Phase 5.3.2 ATT&CK Canary](docs/architecture/phase-5.3.2-attack-canary.md)
- [Phase 5.3.3 Windows/Sysmon Encyclopedia](docs/architecture/phase-5.3.3-windows-sysmon-encyclopedia.md)
- [Phase 5.3.4 D3FEND/CAR/DefenseOps Promotion](docs/architecture/phase-5.3.4-d3fend-car-defenseops-promotion.md)

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
