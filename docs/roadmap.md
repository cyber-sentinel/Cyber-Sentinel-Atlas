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

Established acquisition, RawSnapshot, parser/PSR, normalizer/lineage, inventory/diff, G1–G15 validation, review and `PACK_READY` contracts.

### Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary

Status: **COMPLETE / MERGED**

Proved deterministic structured-source ingestion against a pinned official ATT&CK source while preserving canonical schema boundaries.

### Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline

Status: **COMPLETE / MERGED**

Proved Windows Security and Sysmon inventory/reconciliation, provider-scoped Event-ID identity, legacy preservation and deterministic Encyclopedia ingestion semantics.

### Phase 5.3.4 — D3FEND + CAR + DefenseOps + Promotion Gates

Status: **COMPLETE / MERGED**

Completed D3FEND/CAR canaries, DefenseOps validated-export boundary, licensing fail-closed behavior, final G1–G15 promotion and Last Known Good semantics.

## Phase 5.4 — Deterministic Search Core

Status: **COMPLETE / MERGED**

### Phase 5.4.1 — Search Contracts + Reference Resolver

Status: **COMPLETE / MERGED**

Froze Search Projection Corpus, exact/scoped/alias precedence, bounded query semantics and deterministic ambiguity behavior.

### Phase 5.4.2 — Search Engine Spike + ADR-0022

Status: **COMPLETE / MERGED**

Benchmarked SQLite+FTS5 and Tantivy on Linux/Windows and accepted SQLite+FTS5 for the production deterministic/lexical search artifact.

### Phase 5.4.3 — Production SQLite/FTS5 Search Core

Status: **COMPLETE / MERGED**

Implemented exact + lexical search, filters/catalogs, deterministic ordering, corruption/staleness checks and disposable index rebuild semantics.

### Phase 5.4.4 — Catalog / Graph / Benchmark Closure

Status: **COMPLETE / MERGED**

Completed provider catalog browse, bounded graph pivots, lifecycle browsing and permanent acceptance/performance closure without selecting a graph database.

## Phase 5.5 — Offline Pack Runtime / Shared Core

Status: **IN PROGRESS**

### Phase 5.5.1 — Pack Trust Contracts + ADR-0023

Status: **COMPLETE / MERGED**

Froze Pack Manifest, Source/License Inventory and TUF-based trust/update architecture.

### Phase 5.5.2 — Verified Pack Runtime

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Delivered secure `.atlaspack` extraction, offline TUF verification, exact artifact/control binding, canonical validation, deterministic search-index validation/rebuild, trusted-time and version rollback guards, immutable generations, atomic active/LKG state and rollback, deterministic verified pack building, and Linux/Windows adversarial CI.

### Phase 5.5.3 — Production Shared Core Technology Spike

Status: **ARCHITECTURE GATE / SPIKE AUTHORIZED**

This subphase is introduced at the current architecture boundary; it was not previously frozen.

Purpose:

- select the production Shared Core implementation/runtime only after reproducible evidence;
- preserve all Phase 5.4 search and Phase 5.5 trust/runtime contracts;
- compare Rust, Go, Python control, TypeScript/Node.js and .NET/C# architecturally;
- execute the initial finalist spike for Rust, Go and Python control;
- prove Windows/Linux search, TUF/POUF, atomic-state, rollback, offline and cross-language digest semantics;
- generate machine-readable benchmark/security evidence;
- accept ADR-0024 only after all mandatory gates pass.

No Desktop UI framework, graph database, HSM/KMS provider, broader application storage, binary updater or CDN topology is selected by the Phase 5.5.3 architecture gate.

### Phase 5.5 production implementation after ADR-0024

Status: **BLOCKED ON PHASE 5.5.3 EVIDENCE / ADR-0024**

After ADR-0024 selects the production Shared Core, a dedicated implementation slice will port/implement the accepted contracts without reopening canonical/search/pack semantics.

## Phase 5.6 — Windows Desktop MVP

Status: **NOT STARTED / BLOCKED ON SHARED CORE SELECTION**

First full end-user interface. Requirements include fast offline exact/lexical lookup, canonical data, relationship navigation, provenance visibility, signed pack updates, safe rollback and portable Windows mode evaluation.

Desktop technology requires its own evidence/ADR and is not implied by the Shared Core selection.

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
