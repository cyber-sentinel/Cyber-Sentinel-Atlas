# Cyber-Sentinel-Atlas

**Provenance-First Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the **KNOW** layer of the Cyber-Sentinel ecosystem: an offline-first, analyst-first platform for connecting security telemetry, canonical records, adversary behavior, detections, hunts, DFIR artifacts, defensive context, investigation pivots, and claim-level provenance into an inspectable knowledge system.

> **Development:** Active
> **Phase 5.1:** COMPLETE
> **Stage 1:** COMPLETE
> **Completed foundation:** Phases 5.1–5.5 COMPLETE / MERGED / VERIFIED
> **Current delivery boundary:** Phase 5.6 — Windows Desktop MVP
> **Completed desktop slices:** 5.6.0 COMPLETE / VERIFIED; 5.6.1 COMPLETE / VERIFIED
> **Active desktop slice:** 5.6.2 — Mandatory Hard Gates, Measurements & Desktop Selection
> **Current technical focus:** G-D6 — Verified Pack Update + Safe Manual Rollback
> **Desktop framework:** Not selected; ADR-0026 remains blocked until every mandatory gate is closed
> **Repository visibility:** Public
> **Release state:** Pre-preview / unreleased

Public repository visibility does **not** mean the product is release-ready. `main` remains the release authority; active Phase 5.6 work stays on feature branches until review, CI, merge, and post-merge verification are complete.

Detailed implementation state is maintained in [Current Status](docs/current-status.md), [Project State](docs/project-state.md), and the [Roadmap](docs/roadmap.md).

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDR/XDR platforms, cloud environments, container runtimes, databases, vendor documentation, detection repositories, threat intelligence, and incident-response references.

ATLAS makes those relationships searchable and operational while keeping technical claims bound to inspectable evidence.

<p align="center">
  <img src="assets/satellite.png" alt="Cyber-Sentinel Atlas product thesis — telemetry, security knowledge, investigation, defensive action and provenance" width="100%" />
</p>

ATLAS is designed as a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform**.

Within the Cyber-Sentinel ecosystem, ATLAS answers:

> **What do we know about what we are seeing?**

ATLAS is not another Event ID wiki, detection-rule dump, ATT&CK browser, SIEM-specific content portal, or ungrounded AI chatbot. DefenseOps owns defensive engineering content; Skills owns reusable operating procedures. ATLAS owns governed knowledge, retrieval, provenance, relationships, and investigation context.

## Current Architecture

<p align="center">
  <img src="assets/ATLAS-IR.png" alt="Cyber-Sentinel Atlas content pipeline and production architecture" width="100%" />
</p>

ATLAS is **offline-first**. Deterministic exact and lexical retrieval must work without AI, and no UI, search index, upstream source, or model response becomes canonical truth.

### Accepted architecture boundary

- **Canonical schema:** contract `1.0.0`, JSON Schema Draft 2020-12;
- **Canonical model:** exactly seven `AtlasRecord` families;
- **Search:** deterministic exact-before-lexical retrieval using SQLite + FTS5;
- **Content trust:** TUF-based verification, trusted-time and highest-seen rollback protection;
- **Pack runtime:** verified `.atlaspack`, immutable generations, durable state, health-gated activation and Last Known Good semantics;
- **Production Shared Core:** Go;
- **Conformance oracle:** Python;
- **Desktop/Core IPC:** `atlas-core --serve-stdio`, protocol `atlas-core/1.0.0`;
- **Framing:** bounded 4-byte unsigned big-endian length prefix + UTF-8 JSON;
- **Protocol behavior:** mandatory handshake, one request at a time, duplicate-key rejection and bounded payloads;
- **Network posture:** no default local HTTP/TCP/WebSocket listener and no hidden network fallback;
- **Official user-facing CLI command:** `atlas`.

The Desktop layer may consume Shared Core capabilities but may not duplicate or redefine canonical validation, search/graph semantics, TUF verification, durable trust state, or rollback protection.

## Canonical Model

The authoritative schema contract remains **1.0.0** with exactly seven record families:

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

The current `$id` / `$ref` namespace is part of the accepted v1 contract. Schema changes must be explicit and versioned; CI includes a canonical-schema drift guard to prevent silent contract changes.

## Source, Ingestion & Deterministic Search

The ingestion/control plane has been validated against ATT&CK, Windows Security, Sysmon, D3FEND, CAR, and the controlled DefenseOps export boundary.

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

`PACK_READY` is a validated promotion state; it is not equivalent to signed, installed, or active content.

The deterministic search core provides exact identifier resolution before lexical retrieval, bounded ambiguity, deterministic ordering, catalog browsing, lifecycle-aware filters, bounded graph pivots, corruption/staleness checks, and rebuildable derived indexes. Search artifacts never become canonical truth.

## Phase 5.5 — Verified Offline Packs & Shared Core

**COMPLETE / MERGED / VERIFIED / FROZEN**

Delivered production capabilities include:

- TUF-based content trust contracts;
- secure `.atlaspack` extraction and verification;
- offline verification;
- exact manifest/artifact/control binding;
- trusted-time and highest-seen rollback guards;
- immutable generations;
- atomic activation and Last Known Good recovery state;
- deterministic verified-pack building;
- production Go protocol core;
- canonical record loading;
- SQLite/FTS5 search;
- bounded graph operations;
- durable pack trust state;
- supply-chain, conformance and vulnerability gates;
- bounded local stdio protocol for Desktop consumption.

Phase 5.5 is frozen. Phase 5.6 may integrate with this boundary but must not silently redefine it.

## Phase 5.6 — Windows Desktop MVP

### 5.6.0 — Desktop Environment / Core Boundary

**COMPLETE / VERIFIED**

The Windows runner, Go Shared Core sidecar, protocol handshake/status, offline posture, deterministic sidecar evidence, and no-default-listener boundary are validated.

### 5.6.1 — Executable Desktop Candidate Builds

**COMPLETE / VERIFIED**

Three Windows host candidates build and exercise the same production `atlas-core` sidecar:

- Tauri 2.x;
- Electron;
- .NET 10 Windows Desktop / WPF.

This evidence is comparative only. It does **not** select a framework.

Electron uses a committed dependency lockfile. Tauri currently builds with a pinned/verified dependency procedure, but its candidate directory does **not yet contain a committed `Cargo.lock`**; committing that lockfile remains part of reproducibility closure before framework selection.

### 5.6.2 — Hard Gates, Measurements & Desktop Selection

**IN PROGRESS**

The signed-pack Active Generation integration gate proves a verified pack can be installed and loaded into the production read model on Windows, including canonical data, immutable search, graph runtime and generation identity. **G-D5 is closed and verified.** Current G-D6 changes remain subject to exact-head CI before they can be treated as verified evidence.

Current mandatory-gate state:

| Gate | Requirement | State |
| --- | --- | --- |
| G-D1 | Clean Windows build | **PASS** |
| G-D2 | `atlas-core` stdio handshake/status | **PASS** |
| G-D3 | Offline / no-default-listener behavior | **PARTIAL — core/TCP pass; UDP review pending** |
| G-D4 | Deterministic sidecar location + integrity/version | **PASS** |
| G-D5 | Active verified pack → search / record / graph / provenance read model | **PASS / VERIFIED** |
| G-D6 | Verified pack state, update and safe manual rollback | **IN PROGRESS — core-owned primitives implemented; IPC, same-process reload and signed end-to-end closure pending** |
| G-D7 | Desktop security surface | **PENDING** |
| G-D8 | Installer + portable feasibility | **PENDING** |
| G-D9 | Comparable startup / IPC / process / memory / package measurements | **PARTIAL — common harness captured; closure pending** |

G-D6 now has a core-owned primitive layer on the feature branch: the update archive is consumed only from the fixed runtime inbox (`inbox/pending.atlaspack`), verification reuses durable TUF trust state and trusted-time protections, rollback targets are recorded by the core rather than supplied by the UI, and manual rollback does not rewind `HighestSeenPacks` or durable TUF metadata. This is **not yet G-D6 closure**: stdio protocol methods, same-process read-model replacement, signed end-to-end update/rollback coverage, and failure/recovery validation still have to pass CI.

Only candidates that pass **every mandatory gate** may enter final weighted comparison. ADR-0026 therefore remains intentionally undecided.

### 5.6.3 — First Preview UI

**PLANNED — blocked on 5.6.2 framework selection**

The first preview remains intentionally constrained to:

- Offline Global Search;
- Canonical Entity / Record Detail;
- Relationship Navigation and graph pivots;
- Claim-level Provenance / Sources;
- Windows Event / Sysmon-oriented investigation context within the available pack data;
- Verified Pack State;
- Pack Update;
- Safe Rollback / Last Known Good;
- core failure/recovery visibility;
- time display suitable for investigations, including UTC plus user-selected/system time zone; Tehran and Jalali display are UX requirements, not canonical timestamp replacements.

### First Preview UX direction

The current visual direction is an **operational intelligence dark interface**, not a promotional dashboard:

- dark navy / graphite foundation;
- cyan/teal operational accents;
- green reserved for verified/healthy state;
- amber for warning and red for high-severity/critical state;
- user-selectable theme tokens without changing security-state semantics;
- dense analyst-oriented layouts for Search, Investigation, Record Detail, Graph and Pack Management;
- restrained Iranian visual identity on the Home surface only;
- geographic maps must use validated SVG/GeoJSON/raster assets rather than generated imagery so Iran, the Persian Gulf, Strait of Hormuz and neighboring geography remain accurate;
- decorative military/space motifs remain subordinate to operational data and are not repeated across technical pages.

The visual baseline guides implementation but does not expand First Preview scope.

### 5.6.4 — Windows Packaging / Smoke Closure

**PLANNED**

This slice will close the Windows executable/package/installer boundary, sidecar integrity packaging, portable-mode behavior, and clean-machine smoke tests across launch, search, record/provenance, pack state/update, and rollback.

**FIRST PREVIEW READY may only be claimed after 5.6.4 is complete and verified.**

## Initial Product Domain

The initial usable domain is intentionally narrow:

- Windows Security Events;
- Sysmon;
- PowerShell;
- Active Directory;
- MITRE ATT&CK relationships;
- selected D3FEND/CAR relationships;
- DefenseOps validated detections and hunts;
- investigation pivots;
- official-source provenance;
- deterministic exact/lexical search;
- verified offline local datasets.

Architecture support for broader platforms does not imply initial ingestion or First Preview delivery for every domain.

## Cyber-Sentinel Ecosystem

```text
Cyber-Sentinel
├── ATLAS       — KNOW   → Connect • Search • Investigate • Explain
├── DefenseOps  — DEFEND → Detect • Hunt • Validate • Respond • Automate
└── Skills      — APPLY  → Execute • Review • Reuse • Govern
```

ATLAS owns governed knowledge, canonical relationships, deterministic retrieval, provenance and investigation context. DefenseOps owns defensive engineering content. Skills owns reusable, reviewable operating procedures.

Controlled content can flow between projects only through explicit provenance, validation, versioning and release boundaries.

### Ecosystem Operating Loop

<p align="center">
  <img src="assets/azadi-tower-atlas.png" alt="Cyber-Sentinel ecosystem operating loop: KNOW, DEFEND, APPLY, VALIDATE, AUTOMATE, EVOLVE" width="100%" />
</p>

`VALIDATE`, `AUTOMATE`, and `EVOLVE` are ecosystem operating outcomes and feedback stages, not separate repositories.

## Delivery Sequence

```text
5.1  Product Foundation                         COMPLETE
Stage 1 Governance / Architecture Sync         COMPLETE
5.2  Canonical Data Model                      COMPLETE
5.3  Source & Ingestion Core                   COMPLETE
5.4  Deterministic Search Core                 COMPLETE
5.5  Offline Pack Runtime / Shared Core        COMPLETE / MERGED / VERIFIED / FROZEN
5.6  Windows Desktop MVP                       IN PROGRESS
     5.6.0 Environment / Core Boundary         COMPLETE / VERIFIED
     5.6.1 Executable Candidate Builds         COMPLETE / VERIFIED
     5.6.2 Hard Gates / Selection / ADR-0026   IN PROGRESS
            G-D5 Active Pack Integration       COMPLETE / VERIFIED
            G-D6 Update / Safe Rollback        IN PROGRESS — core primitives implemented; closure pending
     5.6.3 First Preview UI                    PLANNED
     5.6.4 Windows Packaging / Smoke Closure   PLANNED
5.7  Web / PWA                                 DEFERRED BEYOND FIRST PREVIEW
5.8  Broader API surfaces                      DEFERRED BEYOND FIRST PREVIEW
5.9  Grounded AI                               DEFERRED BEYOND FIRST PREVIEW
5.10 Public Preview Readiness                  PLANNED
```

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

### Delivery & Governance

- [UX Information Architecture](docs/ux/ux-information-architecture.md)
- [MVP Scope](docs/mvp/mvp-scope.md)
- [MVP Release Gates](docs/mvp/release-gates.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Third-Party Notices](THIRD_PARTY_NOTICES.md)
- [Trademarks](TRADEMARKS.md)
- [Licensing & Contributions](docs/governance/licensing-and-contributions.md)

## Development & Release Posture

The source repository is currently public, but ATLAS remains **pre-preview and unreleased**. No public project license has yet been adopted. Third-party licensing and redistribution rights, contributor-rights review, security review, accessibility, signed artifacts, packaging, and release governance remain fail-closed requirements before Public Preview.

Official changes follow:

```text
branch → pull request → CI → architecture/security review → merge → post-merge verification
```

## Core Principle

> **No technical claim without provenance. No AI answer without inspectable evidence. No engine-specific syntax confused with the underlying security concept.**

---

**Maintainer:** Ali RahimDabagh

**GitHub:** `cyber-sentinel`
