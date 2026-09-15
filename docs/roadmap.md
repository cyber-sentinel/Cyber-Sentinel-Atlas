# Cyber-Sentinel-Atlas Roadmap

This file is the current phase-level roadmap. The detailed pre-Phase-5.4 snapshot is preserved in [`docs/history/roadmap-pre-phase54-snapshot.md`](history/roadmap-pre-phase54-snapshot.md). Operational detail and exact completion SHAs are maintained in [`docs/current-status.md`](current-status.md).

## Phase 5.1 — Product Foundation

Status: **COMPLETE**

Delivered the product vision, personas, knowledge-graph foundation, provenance-first design, offline-first principles, search/AI boundaries, API/CLI direction, security architecture, UX and initial MVP scope.

## Stage 1 — Governance / Architecture Sync

Status: **COMPLETE**

Delivered project-state control, Atlas/DefenseOps/Forge ownership, canonical identifiers, shared-core/interface sequencing, universal telemetry taxonomy, coverage architecture, controlled publication and lifecycle preservation.

## Phase 5.2 — Canonical Data Model

Status: **COMPLETE / MERGED**

Delivered canonical schema v1.0.0 with exactly seven AtlasRecord families, native identifiers, claims/evidence, relationships, lifecycle/applicability, source/version/validation/coverage contracts and deterministic validation.

## Phase 5.3 — Source & Ingestion Core

Status: **COMPLETE / MERGED**

### Phase 5.3.1 — Ingestion Foundation / Contracts
Status: **COMPLETE / MERGED**

### Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary
Status: **COMPLETE / MERGED**

### Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline
Status: **COMPLETE / MERGED**

### Phase 5.3.4 — D3FEND + CAR + DefenseOps + Promotion Gates
Status: **COMPLETE / MERGED**

Phase 5.3 established deterministic acquisition, parsing, normalization, lineage, inventory/reconciliation, review/promotion, licensing and Last Known Good semantics across the first authoritative canaries.

## Phase 5.4 — Deterministic Search Core

Status: **COMPLETE / MERGED**

### Phase 5.4.1 — Search Contracts + Reference Resolver
Status: **COMPLETE / MERGED**

### Phase 5.4.2 — Search Engine Spike + ADR-0022
Status: **COMPLETE / MERGED**

### Phase 5.4.3 — Production SQLite/FTS5 Search Core
Status: **COMPLETE / MERGED**

### Phase 5.4.4 — Catalog / Graph / Benchmark Closure
Status: **COMPLETE / MERGED**

Phase 5.4 froze exact-before-lexical semantics and delivered deterministic SQLite/FTS5 search, catalogs, bounded graph reads, lifecycle browsing and permanent regression/performance gates.

## Phase 5.5 — Offline Pack Runtime / Shared Core

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

### Phase 5.5.1 — Pack Trust Contracts + ADR-0023
Status: **COMPLETE / MERGED**

Froze Pack Manifest, Source/License Inventory and TUF-based trust/update architecture.

### Phase 5.5.2 — Verified Pack Runtime
Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Delivered secure `.atlaspack` extraction, offline TUF verification, exact artifact/control binding, canonical validation, deterministic search-index validation/rebuild, trusted-time and version rollback guards, immutable generations, atomic active/LKG state and rollback, deterministic verified pack building, and Linux/Windows adversarial CI.

### Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024
Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Evidence-driven technology selection chose Go as the production Shared Core implementation family. Python remains the semantic/conformance oracle. The Atlas deterministic JSON profile remained frozen and no JCS digest migration occurred.

The original selection evidence included `go-tuf/v2 v2.4.2`, `modernc.org/sqlite v1.58.0` and `golang.org/x/text v0.36.0`. Phase 5.5.4D later patched the production security baseline to Go 1.25.13 and `golang.org/x/text v0.39.0` without changing the architectural selection.

### Phase 5.5.4 — Production Go Shared Core
Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

ADR-0025 freezes the local integration boundary as a typed child-process stdio protocol implemented by `atlas-core --serve-stdio`. Protocol v1 uses a 4-byte unsigned big-endian payload length followed by UTF-8 JSON, exact protocol handshake/versioning, strict bounded parsing, one request at a time per child process, compiled method allowlists, protocol-only stdout and no default local HTTP/TCP listener or hidden network fallback.

Delivered execution slices:

- **5.5.4A — Core skeleton + protocol:** **COMPLETE / MERGED / VERIFIED**
- **5.5.4B — Canonical + search + graph:** **COMPLETE / MERGED / VERIFIED**
- **5.5.4C — Pack trust + durable state:** **COMPLETE / MERGED / VERIFIED**
- **5.5.4D — Supply-chain / closure:** **COMPLETE / MERGED / POST-MERGE VERIFIED**

The closure includes locked dependencies, reproducible Linux/Windows builds, CycloneDX SBOM evidence, fail-closed vulnerability checks, dependency/license evidence, full Python-oracle conformance, strict archive/state adversarial tests and binary/IPC measurements. PR #35 merged the closure at `main@00a27df6b28b034fecc3905865e0aac200e5aa87`.

## Phase 5.6 — Windows Desktop MVP

Status: **READY / IMPLEMENTATION ENTRY AUTHORIZED**

First full end-user interface. The Desktop must remain a consumer of the Shared Core boundary rather than a parallel knowledge engine. User-visible requirements include fast offline exact/lexical lookup, canonical entity detail, relationship navigation, provenance/evidence visibility, verified pack state/update flows, safe rollback and portable Windows mode evaluation.

### Phase 5.6.1 — Desktop Technology Spike + ADR-0026

Status: **AUTHORIZED / NEXT**

Desktop technology requires its own executable evidence and ADR; it is not implied by the Go Shared Core selection or ADR-0025 local protocol choice.

The spike must compare viable Windows Desktop implementation candidates against mandatory gates for:

- strict `atlas-core --serve-stdio` integration with no FFI coupling or hidden network fallback;
- offline operation and clean process lifecycle/crash containment;
- Windows packaging/install and portable-mode feasibility;
- startup/runtime resource measurements;
- dependency/SBOM/vulnerability/license visibility;
- automated Windows smoke testing;
- accessibility, keyboard navigation and DPI/scaling feasibility;
- code-signing/release compatibility without selecting the final signing provider;
- maintainability and UI iteration speed without violating canonical/search/pack ownership boundaries.

No framework is accepted until evidence and ADR-0026 are green.

### Phase 5.6.2 — Desktop Shell + Shared Core Session
Status: **BLOCKED ON 5.6.1**

Establish the selected production Desktop shell, deterministic child-process supervision, handshake/session lifecycle, structured diagnostics and first offline smoke journey.

### Phase 5.6.3 — Search / Entity / Provenance UX
Status: **BLOCKED ON 5.6.2**

Deliver the first analyst-facing end-to-end UX for exact/lexical search, entity pages, relationships and claim-level provenance.

### Phase 5.6.4 — Pack Management / Rollback / Portable Mode
Status: **BLOCKED ON 5.6.3**

Expose verified pack state, installation/activation, health/LKG rollback and the accepted Windows packaging/portable-mode model.

### Phase 5.6.5 — Desktop MVP Closure
Status: **BLOCKED ON 5.6.4**

Complete Windows security review, automated acceptance tests, performance evidence, installer/portable artifacts, accessibility baseline and Desktop MVP closure.

## Phase 5.7 — Web / PWA

Status: **NOT STARTED**

Build on the same canonical model and shared contracts: global search, entity pages, relationship navigation, evidence panels, responsive UX and appropriate offline capability.

## Phase 5.8 — API / CLI

Status: **NOT STARTED**

Deliver versioned read/search/graph/source/pack APIs and the official `atlas` CLI without implementing a parallel knowledge engine.

## Phase 5.9 — Grounded AI

Status: **NOT STARTED**

Only after deterministic retrieval and provenance are mature: entity-aware Q&A, cited explanations, investigation pivots and optional offline model support. AI never becomes canonical truth.

## Phase 5.10 — Public Preview Readiness

Status: **NOT STARTED**

Security review, third-party licensing/redistribution closure, accessibility, contributor workflow, source freshness, signed release process, public documentation and launch criteria.

## Expansion After MVP

The universal architecture remains intended to expand beyond the Windows-first MVP to Linux/macOS, Microsoft 365/Exchange/SharePoint, Azure/Entra, AWS, Google Cloud, containers/Kubernetes/OpenShift, DevOps/CI-CD, SQL and NoSQL databases, LOLBAS/GTFOBins and broader DFIR/IR/deception content.

Architecture support does not imply MVP ingestion of all domains.
