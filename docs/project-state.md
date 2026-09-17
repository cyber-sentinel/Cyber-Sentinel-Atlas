# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Live Main SHA: resolve from the GitHub `main` branch tip.
- Last Reviewed Main SHA: `00a27df6b28b034fecc3905865e0aac200e5aa87`
- Last Architecture-Reviewed Baseline SHA: `94f3136687f8e9765c0343b938a1049436878783`
- Last Production Shared Core Closure SHA: `00a27df6b28b034fecc3905865e0aac200e5aa87`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version: `1.0.0`
- Ingestion Contract Version: `1.0.0`
- Search Contract Version: `1.0.0`
- Search Engine: SQLite + FTS5 — ADR-0022 Accepted
- Content Pack Trust Model: TUF — ADR-0023 Accepted
- Production Shared Core: Go — ADR-0024 Accepted
- Shared Core Local Interface: child-process stdio protocol — ADR-0025 Accepted
- Production Go baseline: Go 1.25.13
- Production Shared Core dependency baselines: `go-tuf/v2 v2.4.2`, `modernc.org/sqlite v1.58.0`, `golang.org/x/text v0.39.0`
- Python Role: semantic/conformance oracle retained for regression/conformance testing
- Repository Visibility: Private during active development
- Branch Protection: unavailable/not enabled on the current private-repository plan; procedural PR + CI + architecture-review gates remain mandatory.

Detailed current status is maintained in [`docs/current-status.md`](current-status.md). Historical project-state detail from the Phase 5.3-era snapshot is preserved in [`docs/history/project-state-phase53-snapshot.md`](history/project-state-phase53-snapshot.md).

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.1 — Pack Trust Contracts + ADR-0023: **COMPLETE / MERGED**
- Phase 5.5.2 — Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.4A — Core Skeleton + Protocol: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4B — Canonical + Search + Graph: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4C — Pack Trust + Durable State: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4D — Supply Chain + Closure: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.6 — Windows Desktop MVP: **READY / IMPLEMENTATION ENTRY AUTHORIZED**
- Phase 5.6.1 — Desktop Technology Spike + ADR-0026: **AUTHORIZED / NEXT**
- Phase 5.7 — Web / PWA: **NOT STARTED**
- Phase 5.8 — API / CLI: **NOT STARTED**
- Phase 5.9 — Grounded AI: **NOT STARTED**
- Phase 5.10 — Public Preview Readiness: **NOT STARTED**

## Frozen Architecture

The following remain authoritative:

- exactly seven canonical AtlasRecord families under `schemas/v1/`;
- canonical identifier pattern `atlas:<entity-type>:<namespace>:<canonical-key>`;
- native identifiers remain separate and Event ID is not globally unique;
- legacy/current lifecycle preservation;
- deterministic exact identifier resolution before lexical retrieval;
- SQLite + FTS5 for the derived deterministic search artifact;
- TUF-based signed content-pack trust, verification and rollback boundary;
- Go as the production Shared Core implementation family;
- the existing Atlas deterministic JSON serialization/digest profile; no implicit JCS migration;
- Python as the semantic/conformance oracle for regression/conformance verification;
- ADR-0025 child-process stdio protocol as the local Desktop-facing Shared Core boundary;
- offline-first operation, inspectable provenance and Last Known Good preservation;
- shared contracts across Desktop, Web/PWA, API and CLI;
- official CLI command: `atlas`.

The Desktop implementation stack is intentionally **not** frozen yet. It must be selected by Phase 5.6.1 evidence and ADR-0026.

## Phase 5.5 Production Closure

Phase 5.5 converted the accepted content-pack and deterministic-search contracts into a production offline Shared Core.

Phase 5.5.3 selected Go through cross-platform evidence and accepted ADR-0024. Phase 5.5.4 then implemented production Go code across protocol, canonical/search/graph, pack trust/durable state and supply-chain closure slices.

ADR-0025 freezes the local integration boundary as `atlas-core --serve-stdio` with 4-byte big-endian length-prefixed UTF-8 JSON frames, strict `atlas-core` protocol `1.0.0` handshake, bounded request/response sizes, duplicate-key and malformed-input rejection, one request at a time per child process, method allowlisting, protocol-only stdout, diagnostic-only stderr and no default local network listener or hidden network fallback.

Production closure includes:

- canonical/read-model validation against the seven-family schema;
- deterministic SQLite/FTS5 exact, lexical, catalog and bounded graph behavior;
- Atlas TUF POUF v1 verification and verified-pack consumption;
- strict `.atlaspack` archive validation and no pack-provided executable code;
- durable install/activation/highest-seen/trusted-time/LKG rollback behavior;
- locked Go dependencies, clean/reproducible builds, CycloneDX SBOM and fail-closed vulnerability evidence;
- Linux/Windows conformance against the Python oracle;
- stable versioned local protocol conformance without freezing the Desktop UI framework.

PR #35 merged the exact-head green Phase 5.5.4D closure through Merge Commit `00a27df6b28b034fecc3905865e0aac200e5aa87`. During closure, `govulncheck` findings were remediated rather than suppressed: the production Go baseline moved from 1.25.0 to 1.25.13 and `golang.org/x/text` from v0.36.0 to v0.39.0. `go-tuf/v2 v2.4.2` and `modernc.org/sqlite v1.58.0` remain locked.

Post-merge Phase 5.5.4A/B/C/D workflows are green on the closure SHA. The former Phase 5.6 blocker is therefore cleared.

## Phase 5.6 Production Boundary

Phase 5.6 is the first full end-user Windows interface and must consume, not duplicate, the Shared Core.

### Phase 5.6.1 — Desktop Technology Spike + ADR-0026

The first required step is an executable Windows technology spike. It must evaluate viable Desktop candidates without preselecting a framework and must produce reproducible evidence for:

- exact ADR-0025 child-process stdio integration;
- no FFI dependency on Go internals and no hidden HTTP/TCP fallback;
- offline operation;
- process supervision, clean shutdown, crash containment and diagnostic separation;
- Windows installer/package feasibility and portable-mode feasibility;
- startup time, idle/runtime memory and packaged-size measurements;
- dependency/SBOM/vulnerability/license visibility;
- code-signing/release-pipeline compatibility;
- keyboard/accessibility/DPI feasibility;
- deterministic Windows smoke automation;
- maintainability and UI iteration speed.

ADR-0026 may be accepted only after the mandatory evidence gates pass. Until then, Windows Desktop technology remains an open decision.

Planned implementation sequence after 5.6.1:

1. 5.6.2 — Desktop shell + Shared Core session lifecycle;
2. 5.6.3 — search/entity/relationship/provenance UX;
3. 5.6.4 — verified pack management, LKG rollback and portable packaging;
4. 5.6.5 — Desktop MVP security/performance/accessibility/release closure.

## Accepted ADRs

- ADR-0001 — Canonical Vendor-Neutral Model
- ADR-0002 — Claim-Level Provenance
- ADR-0003 — Offline-first Core
- ADR-0004 — Ecosystem Ownership: Atlas, DefenseOps and Forge
- ADR-0005 — Canonical Identifier Architecture
- ADR-0006 — Shared Core and Interface Sequencing
- ADR-0007 — Universal Telemetry Taxonomy
- ADR-0008 — Coverage Measurement Model
- ADR-0009 — Controlled Content Release Pipeline
- ADR-0010 — Telemetry Lifecycle and Legacy Preservation
- ADR-0011 — Canonical Record Families and Record Envelope
- ADR-0012 — Native Identifiers, Aliases and Controlled Registries
- ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation
- ADR-0014 — Claim, Evidence and Relationship Contracts
- ADR-0015 — Schema Versioning, Migration and Referential Integrity
- ADR-0016 — Source & Ingestion Control Plane Boundary
- ADR-0017 — Deterministic Acquisition, Parsing and Normalization
- ADR-0018 — Authoritative Inventory, Completeness and Change Safety
- ADR-0019 — Validation, Review and Pack-Ready Promotion
- ADR-0020 — Encyclopedia Identifier Search/Browse Data Contract
- ADR-0021 — Search Projection and Exact Resolver Contract
- ADR-0022 — Search Engine Selection
- ADR-0023 — Secure Content Pack Trust and Update Model
- ADR-0024 — Production Shared Core Technology Selection
- ADR-0025 — Shared Core Local Interface Boundary

## Technology Decisions Still Open

- Windows Desktop implementation stack — to be selected by Phase 5.6.1 / ADR-0026;
- broader local application storage beyond the accepted derived search artifact;
- graph persistence/index implementation beyond current bounded derived reads;
- Detection Intermediate Representation;
- HSM/KMS and production signing-provider selection;
- final portable Windows packaging implementation;
- application binary update mechanism;
- remote content distribution/CDN topology;
- Grounded AI runtime.

## Architecture Sync

- Architecture Sync Date: 2026-09-15
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Architecture Sync Status: **GREEN** — PHASE 5.5 CLOSED / PHASE 5.6 ENTRY AUTHORIZED
- Stage 1: **APPROVED AND MERGED**
- Phase 5.2: **APPROVED AND MERGED**
- Phase 5.3: **APPROVED AND COMPLETE**
- Phase 5.4: **APPROVED AND COMPLETE**
- Phase 5.5.1: **APPROVED AND COMPLETE**
- Phase 5.5.2: **APPROVED, MERGED AND POST-MERGE VERIFIED**
- Phase 5.5.3: **APPROVED, GO SELECTED, MERGED AND POST-MERGE VERIFIED**
- Phase 5.5.4: **APPROVED, IMPLEMENTED, MERGED AND POST-MERGE VERIFIED — ADR-0025**
- Phase 5.6.1: **AUTHORIZED FOR EVIDENCE SPIKE — NO DESKTOP STACK SELECTED YET**

No blocking architecture conflict is known at this boundary. Phase 5.6 may not redefine canonical, search, pack or Shared Core protocol contracts to simplify the UI implementation.
