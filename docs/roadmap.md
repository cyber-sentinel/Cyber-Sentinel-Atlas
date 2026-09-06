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

### Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Evidence-driven technology selection completed on Linux and Windows. ADR-0024 selected Go as the production Shared Core implementation family after Go passed all mandatory G-SC1..G-SC8 gates on both operating systems and ranked first among eligible candidates. Python remains the semantic/conformance oracle during the production port. The existing Atlas deterministic JSON profile remains frozen and no JCS digest migration occurred.

The accepted evidence baseline includes `go-tuf/v2 v2.4.2`, `modernc.org/sqlite v1.58.0` and the normalized Go dependency graph including `golang.org/x/text v0.36.0`.

This decision does not select the Desktop UI framework, broader application storage, graph database, HSM/KMS provider, application updater/CDN, Detection IR, semantic/vector retrieval or Grounded AI runtime.

### Phase 5.5.4 — Production Go Shared Core

Status: **ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED**

Implement the accepted Shared Core contracts as production Go code rather than spike/benchmark code.

ADR-0025 freezes the local integration boundary as a typed child-process stdio protocol implemented by `atlas-core --serve-stdio`. The v1 protocol uses a 4-byte unsigned big-endian payload length followed by UTF-8 JSON, exact protocol handshake/versioning, strict bounded parsing, one request at a time per child process, compiled method allowlists, protocol-only stdout and no default local HTTP/TCP listener or hidden network fallback.

Mandatory scope:

- preserve the seven-family canonical/read-model and deterministic Atlas serialization/digest profile;
- implement Phase 5.4 exact-before-lexical SQLite/FTS5 search, catalogs and bounded graph reads without semantic fallback;
- implement ADR-0023 / Atlas TUF POUF v1 verification and verified-pack consumption;
- preserve strict `.atlaspack` archive rules, offline/no-network operation, immutable generations, highest-seen/trusted-time guards, atomic activation and Last Known Good rollback;
- retain Python reference/control conformance fixtures until the production Go implementation proves parity;
- lock dependencies and produce clean-build, SBOM and vulnerability evidence;
- pass Linux and Windows correctness/security/reproducibility CI;
- keep the Windows Desktop UI framework independent from Go internals.

Execution slices:

- **5.5.4A — Core skeleton + protocol:** Go module, `atlas-core`, framing/parser/handshake/error model, `core.status`, Linux/Windows adversarial protocol tests and deterministic build metadata.
- **5.5.4B — Canonical + search + graph:** canonical loader, deterministic serialization vectors, SQLite/FTS5 resolver/search/catalog/graph parity and performance regression gates.
- **5.5.4C — Pack trust + durable state:** go-tuf POUF v1 verification, archive/manifest/license validation, immutable generations, highest-seen/trusted-time state, activation/LKG/health rollback and filesystem adversarial tests.
- **5.5.4D — Supply-chain / closure:** reproducible Linux/Windows builds, SBOM, Go vulnerability evidence, dependency/license inventory, full Python-oracle conformance, binary/IPC measurements and closure status sync.

## Phase 5.6 — Windows Desktop MVP

Status: **NOT STARTED / BLOCKED ON PRODUCTION SHARED CORE**

First full end-user interface. Requirements include fast offline exact/lexical lookup, canonical data, relationship navigation, provenance visibility, verified pack updates, safe rollback and portable Windows mode evaluation.

Desktop technology requires its own evidence/ADR and is not implied by the Go Shared Core selection or ADR-0025 local protocol choice.

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
