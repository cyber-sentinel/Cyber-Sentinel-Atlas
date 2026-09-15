# Cyber-Sentinel-Atlas

**Provenance-First Cyber Defense Knowledge & Investigation Platform**

Foundation descriptor: **Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the **KNOW** layer and knowledge/investigation product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security records, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed, inspectable knowledge system.

> **Development:** Active
> **Foundation state:** Phase 5.1 COMPLETE; Stage 1 COMPLETE
> **Current delivery boundary:** Phase 5.6 — Windows Desktop MVP
> **Completed:** Phases 5.1–5.5, including Phase 5.5.4A–5.5.4D production Go Shared Core closure
> **Next implementation slice:** Phase 5.6 — Windows Desktop MVP
> **Visibility:** Private during active development
> **Version:** `0.1.0-foundation.1`

The live `main` branch is the final repository authority. Detailed phase evidence and roadmap state are maintained in [Current Status](docs/current-status.md), [Project State](docs/project-state.md), and the [Roadmap](docs/roadmap.md).

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDRs, cloud platforms, container runtimes, databases, vendor documentation, detection repositories, threat intelligence, and incident-response references.

Atlas makes those relationships searchable and operational while keeping technical claims bound to inspectable evidence:

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
- an AI chatbot without verifiable sources;
- a replacement for the defensive-content engineering ownership of Cyber-Sentinel-DefenseOps;
- a replacement for the reusable operational procedures and playbooks owned by Cyber-Sentinel-Skills.

Atlas is designed as a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform**.

Within the wider Cyber-Sentinel model, Atlas answers the **KNOW** question: *What do we know about what we are seeing?* DefenseOps turns that knowledge into defensive engineering, while Skills turns repeatable operating methods into reusable procedures for humans and AI agents.

Validated detections, hunts, and other defensive engineering outputs can enter Atlas from DefenseOps only through explicit versioned ingestion, provenance, validation, and controlled release gates.

## Current Architecture

<p align="center">
  <img src="assets/ATLAS-IR.png" alt="Cyber-Sentinel Atlas content pipeline and production architecture" width="100%" />
</p>

The architecture is offline-first. Deterministic exact and lexical retrieval must work without AI, and no UI, search index, upstream source, or model response becomes canonical truth.

## Accepted Architecture Decisions

The current implementation boundary includes the following accepted decisions:

- **Canonical schema:** Atlas schema contract `1.0.0`, JSON Schema Draft 2020-12;
- **Canonical model:** exactly seven `AtlasRecord` families;
- **Search contract:** deterministic exact-before-lexical retrieval with bounded ambiguity and ordering semantics;
- **Search engine:** SQLite + FTS5;
- **Content-pack trust:** TUF-based trust and update model with offline verification and Last Known Good preservation;
- **Pack format/runtime:** verified `.atlaspack` handling, immutable generations, rollback guards, and atomic activation semantics;
- **Production Shared Core:** Go;
- **Reference/conformance role:** Python remains the semantic and cross-language conformance oracle for Shared Core conformance;
- **Local Shared Core boundary:** `atlas-core --serve-stdio` using a versioned, bounded, length-prefixed UTF-8 JSON protocol;
- **Network posture:** no default local HTTP/TCP listener and no hidden network fallback;
- **Official user-facing CLI command:** `atlas`.

These decisions do **not** automatically select the Windows Desktop UI framework, broader application storage, graph database, HSM/KMS provider, application updater/CDN topology, Detection IR, semantic/vector retrieval, or Grounded AI runtime.

## Canonical Model

The authoritative schema contract is **1.0.0**.

Record families:

- `EntityRecord`
- `ClaimRecord`
- `RelationshipRecord`
- `SourceRecord`
- `ValidationRecord`
- `VersionRecord`
- `CoverageSnapshot`

Canonical schema URI base:

```text
https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/
```

The current schema `$id` / `$ref` namespace is part of the accepted v1 contract. Any future public-hosting or immutable-URI migration must be explicit and version-controlled rather than silently changing canonical identity.

The permanent canonical semantic validator is `tools/validate_phase52.py`. Permanent model tests are `tests/test_phase52_model.py` and `tests/test_phase52_invariants.py`.

## Source & Ingestion Core

The ingestion/control plane has been validated against ATT&CK, Windows Security, Sysmon, D3FEND, CAR, and the controlled DefenseOps export boundary.

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

`PACK_READY` is a validated promotion state; it is not itself equivalent to signed, installed, or active content.

The ingestion pipeline preserves source lineage, ambiguous-identity quarantine, independent authority dimensions, legacy/current lifecycle semantics, and fail-closed promotion controls without changing the seven-family canonical model.

## Deterministic Search

Phase 5.4 established the production deterministic search contract and selected **SQLite + FTS5** after cross-platform evaluation.

The search layer provides:

- exact identifier resolution before lexical retrieval;
- scoped/native identifier and alias handling;
- deterministic ambiguity and result ordering;
- bounded filters and catalog browsing;
- lifecycle-aware browsing;
- bounded graph pivots;
- corruption/staleness checks;
- rebuildable derived search artifacts;
- no semantic/vector fallback in the deterministic core.

Search indexes are derived artifacts and never become the canonical source of truth.

## Verified Offline Packs & Shared Core

Phase 5.5 established and closed the verified offline pack and production Shared Core boundary.

Completed capabilities include:

- TUF-based content trust contracts;
- secure `.atlaspack` validation and extraction rules;
- offline verification;
- exact manifest/artifact/control binding;
- trusted-time and highest-seen rollback guards;
- immutable generations;
- atomic activation and Last Known Good rollback;
- deterministic verified-pack building;
- Go production protocol core (`5.5.4A`);
- Go canonical, SQLite/FTS5 search, catalog, and bounded graph parity (`5.5.4B`);
- Go TUF/pack trust, durable state, activation and LKG parity (`5.5.4C`);
- Linux/Windows supply-chain closure, reproducible-build evidence, SBOM/vulnerability checks, dependency hardening and Python-oracle conformance (`5.5.4D`).

Phase 5.5.4D merged through PR #35 at `00a27df6b28b034fecc3905865e0aac200e5aa87`, closing the production Go Shared Core implementation sequence. The next delivery boundary is **Phase 5.6 — Windows Desktop MVP**; its UI technology remains a separate evidence/ADR decision and is not implied by the Go Shared Core.

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
- verified offline local datasets

The architecture is intentionally extensible to Linux, macOS, Exchange, SharePoint, Microsoft 365, Entra/Azure, AWS, Google Cloud, Docker, Kubernetes/OpenShift, DevOps/CI-CD, SQL/NoSQL databases, LOLBAS, GTFOBins, broader DFIR/IR, and cyber deception.

Architecture support does not imply MVP ingestion of every domain.

## Cyber-Sentinel Ecosystem

Cyber-Sentinel is intentionally a **contract-separated ecosystem**, not a single monolithic product. The three current project layers have distinct responsibilities:

```text
Cyber-Sentinel
├── Atlas       — KNOW   → Connect • Search • Investigate • Explain
├── DefenseOps  — DEFEND → Detect • Hunt • Validate • Respond • Automate
└── Skills      — APPLY  → Execute • Review • Reuse • Govern
```

### Atlas — KNOW

[Cyber-Sentinel-Atlas](https://github.com/cyber-sentinel/Cyber-Sentinel-Atlas) owns governed cyber-defense knowledge, canonical relationships, deterministic retrieval, provenance, investigation context, offline knowledge delivery, and analyst-facing product interfaces.

**Core question:** *What do we know about what we are seeing?*

### DefenseOps — DEFEND

[Cyber-Sentinel-DefenseOps](https://github.com/cyber-sentinel/Cyber-Sentinel-DefenseOps) owns defensive engineering content: detections, hunts, validation assets, response engineering, DFIR/IR material, deception-oriented content, and defensive automation.

**Core question:** *What can we detect, validate, hunt, and defend?*

DefenseOps may provide controlled defensive content to Atlas, but repository origin alone never grants canonical authority. Atlas applies its own ingestion, provenance, licensing, validation, promotion, and release boundaries.

### Skills — APPLY

[Cyber-Sentinel-Skills](https://github.com/cyber-sentinel/Cyber-Sentinel-Skills) owns reusable, vendor-neutral operational procedures and playbooks that make security tasks explicit, reviewable, attributable, repeatable, and usable by both humans and AI agents.

**Core question:** *How should this security task be performed consistently?*

Skills does not replace Atlas product contracts or DefenseOps engineering artifacts; it captures the repeatable operating method used to apply them consistently.

### Ecosystem Operating Loop

<p align="center">
  <img src="assets/azadi-tower-atlas.png" alt="Cyber-Sentinel ecosystem operating loop: KNOW, DEFEND, APPLY, VALIDATE, AUTOMATE, EVOLVE" width="100%" />
</p>

`VALIDATE`, `AUTOMATE`, and `EVOLVE` are ecosystem operating outcomes and feedback stages, not separate repositories. Together the model is:

`KNOW → DEFEND → APPLY → VALIDATE → AUTOMATE → EVOLVE`

## Delivery Sequence

```text
5.1  Product Foundation                         COMPLETE
5.2  Canonical Data Model                      COMPLETE
5.3  Source & Ingestion Core                   COMPLETE
5.4  Deterministic Search Core                 COMPLETE
5.5  Offline Pack Runtime / Shared Core         COMPLETE
     5.5.1 Pack Trust Contracts                COMPLETE
     5.5.2 Verified Pack Runtime               COMPLETE
     5.5.3 Shared Core Technology Selection    COMPLETE
     5.5.4A Go Protocol Core                   COMPLETE
     5.5.4B Canonical / Search / Graph Core    COMPLETE
     5.5.4C Pack Trust / Durable State         COMPLETE
     5.5.4D Supply-chain / Closure             COMPLETE
5.6  Windows Desktop MVP                       NEXT
5.7  Web / PWA                                 NOT STARTED
5.8  API / CLI                                 NOT STARTED
5.9  Grounded AI                               NOT STARTED
5.10 Public Preview Readiness                  NOT STARTED
```

This summary is intentionally phase-level. Exact merge SHAs, workflow evidence, and historical phase snapshots belong in the status/history documentation rather than the repository landing page.

## Documentation

### Project & Product

- [Current Authoritative Status](docs/current-status.md)
- [Project State](docs/project-state.md)
- [Roadmap](docs/roadmap.md)
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
- [Offline-first Architecture](docs/architecture/offline-first-architecture.md)
- [API / CLI Architecture](docs/architecture/api-cli-architecture.md)
- [AI / RAG Architecture](docs/architecture/ai-rag-architecture.md)
- [Security Architecture](docs/architecture/security-architecture.md)
- [Coverage Model](docs/architecture/coverage-model.md)
- [Telemetry Lifecycle](docs/architecture/telemetry-lifecycle.md)
- [Architecture Decision Records](docs/adr/)

### Product Delivery & Governance

- [UX Information Architecture](docs/ux/ux-information-architecture.md)
- [MVP Scope](docs/mvp/mvp-scope.md)
- [MVP Release Gates](docs/mvp/release-gates.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Third-Party Notices](THIRD_PARTY_NOTICES.md)
- [Trademarks](TRADEMARKS.md)
- [Licensing & Contributions](docs/governance/licensing-and-contributions.md)

## Development & Release Posture

The repository remains private during active development. A public project license has not yet been adopted. Third-party licensing, redistribution rights, contributor-rights review, security review, accessibility, and signed public release processes remain fail-closed requirements before Public Preview.

Official changes follow the repository governance path:

```text
branch → pull request → CI → architecture/security review → merge → post-merge verification
```

## Core Principle

> **No technical claim without provenance. No AI answer without inspectable evidence. No engine-specific syntax confused with the underlying security concept.**

---

**Maintainer:** Ali RahimDabagh
**GitHub:** `cyber-sentinel`
