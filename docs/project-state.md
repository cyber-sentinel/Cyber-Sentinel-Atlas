# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Live Main SHA: resolve from the GitHub `main` branch tip.
- Last Reviewed Main SHA: `00a27df6b28b034fecc3905865e0aac200e5aa87`
- Last Architecture-Reviewed Main SHA: `94f3136687f8e9765c0343b938a1049436878783`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version: `1.0.0`
- Ingestion Contract Version: `1.0.0`
- Search Contract Version: `1.0.0`
- Search Engine: SQLite + FTS5 — ADR-0022 Accepted
- Content Pack Trust Model: TUF — ADR-0023 Accepted
- Production Shared Core: Go — ADR-0024 Accepted
- Shared Core Local Interface: child-process stdio protocol — ADR-0025 Accepted
- Python Role: semantic/conformance oracle for frozen cross-language conformance
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
- Phase 5.6 — Windows Desktop MVP: **IN PROGRESS**
- Phase 5.6.0 — Desktop Spike Contract + Environment/Core-Boundary Probe: **COMPLETE / VERIFIED**
- Phase 5.6.1 — Executable Desktop Candidate Builds: **IN PROGRESS**
- Phase 5.7 — Web / PWA: **NOT STARTED**
- Phase 5.8 — API / CLI: **NOT STARTED**
- Phase 5.9 — Grounded AI: **NOT STARTED**
- Phase 5.10 — Public Preview Readiness: **NOT STARTED**

The Phase 5.5.3 and 5.5.4 numbering was introduced at the Shared Core architecture boundary and is now part of the active roadmap.

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
- Python as the semantic/conformance oracle for frozen vectors;
- ADR-0025 child-process stdio protocol as the local Desktop-facing Shared Core boundary;
- offline-first operation, inspectable provenance and Last Known Good preservation;
- shared contracts across Desktop, Web/PWA, API and CLI;
- official CLI command: `atlas`.

## Phase 5.5.3 Closure

Phase 5.5.3 merged via PR #23 at Merge Commit `bbb462b11de460216acb80116146f651ac2ef1ca` and is post-merge verified. PR #24 synchronized the resulting status boundary at `94f3136687f8e9765c0343b938a1049436878783`.

The evidence-driven decision accepted ADR-0024 and selected Go because it was the only non-control finalist to pass every mandatory G-SC1..G-SC8 gate on both Linux and Windows. The accepted baseline includes:

- Go toolchain family evidenced with `go1.25.0`;
- `go-tuf/v2 v2.4.2`;
- `modernc.org/sqlite v1.58.0`;
- normalized dependency graph including `golang.org/x/text v0.36.0`;
- SQLite/FTS5 parity with the accepted Phase 5.4 search contracts;
- TUF/POUF, offline, archive, durable state, trusted-time and LKG/rollback parity with Phase 5.5.1/5.5.2;
- cross-language deterministic JSON vectors preserved without digest migration;
- no change to canonical `schemas/v1/`.

Python control remains an eligible reference implementation and conformance oracle. Rust was not selected because the Phase 5.5.3 mandatory trust/runtime evidence envelope was incomplete or failed; that result is scoped to Phase 5.5.3 rather than a general language judgment.

## Phase 5.5.4 Production Boundary and Closure

Phase 5.5.4 converted the accepted Go spike evidence into the production Shared Core while keeping all canonical/search/pack contracts authoritative. ADR-0025 freezes the local integration boundary as `atlas-core --serve-stdio` with 4-byte big-endian length-prefixed UTF-8 JSON frames, strict `atlas-core` protocol `1.0.0` handshake, bounded request/response sizes, strict parsing, one request at a time per child process, method allowlisting and no default local network listener.

PR #35 merged Phase 5.5.4D through Merge Commit `00a27df6b28b034fecc3905865e0aac200e5aa87`. Post-merge verification on that exact main SHA passed Foundation, architecture/canary gates, 5.5.4A/B/C/D on Linux and Windows, cross-language conformance, reproducibility, SBOM/license closure, `govulncheck`, binary/IPC measurement and pack trust/LKG regression coverage.

The frozen production boundary includes:

- canonical/read-model validation against the seven-family schema;
- deterministic SQLite/FTS5 exact, lexical, catalog and bounded graph behavior;
- Atlas TUF POUF v1 verification and verified-pack consumption;
- durable install/activation/highest-seen/trusted-time/LKG rollback behavior;
- locked Go dependencies, clean builds, SBOM and vulnerability evidence;
- Linux/Windows conformance against the Python oracle;
- stable versioned local protocol conformance without freezing the Desktop UI framework.

Execution completed as 5.5.4A protocol/core skeleton, 5.5.4B canonical/search/graph parity, 5.5.4C pack trust/durable state, and 5.5.4D supply-chain/cross-platform closure.

## Phase 5.6 Active Boundary

Phase 5.6 consumes the frozen Shared Core rather than reimplementing it. Phase 5.6.0 proved the Windows CI/toolchain environment, production `atlas-core.exe` build, exact stdio `core.handshake` + `core.status`, offline-capable status, absence of a default network listener, and no canonical schema drift.

Phase 5.6.1 now evaluates minimal executable Tauri, Electron and .NET Windows Desktop hosts against the same sidecar and protocol operation before ADR-0026 selects exactly one Desktop host family.

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

- Windows Desktop implementation stack — Phase 5.6 spike in progress; ADR-0026 pending;
- broader local application storage beyond the accepted derived search artifact;
- graph persistence/index implementation;
- Detection Intermediate Representation;
- HSM/KMS and production signing-provider selection;
- portable Windows packaging implementation;
- application binary update mechanism;
- remote content distribution/CDN topology;
- Grounded AI runtime.

## Architecture Sync

- Architecture Sync Date: 2026-09-15
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Architecture Sync Status: **GREEN**
- Stage 1: **APPROVED AND MERGED**
- Phase 5.2: **APPROVED AND MERGED**
- Phase 5.3: **APPROVED AND COMPLETE**
- Phase 5.4: **APPROVED AND COMPLETE**
- Phase 5.5.1: **APPROVED AND COMPLETE**
- Phase 5.5.2: **APPROVED, MERGED AND POST-MERGE VERIFIED**
- Phase 5.5.3: **APPROVED, GO SELECTED, MERGED AND POST-MERGE VERIFIED**
- Phase 5.5.4: **APPROVED, MERGED AND POST-MERGE VERIFIED — ADR-0025**
- Phase 5.6.0: **EXECUTED AND VERIFIED — DESKTOP STACK NOT YET SELECTED**

No blocking architecture conflict is known at this boundary. Phase 5.6 Desktop candidates must consume the frozen Atlas security/search/pack/protocol contracts and may not redefine them to simplify a UI host.
