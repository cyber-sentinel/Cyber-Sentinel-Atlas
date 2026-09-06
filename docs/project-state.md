# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Live Main SHA: resolve from the GitHub `main` branch tip.
- Last Reviewed Main SHA: `d2c837b0740b52aeca9dd579c32911e01c8c6ecc`
- Last Architecture-Reviewed Main SHA: `d2c837b0740b52aeca9dd579c32911e01c8c6ecc`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version: `1.0.0`
- Ingestion Contract Version: `1.0.0`
- Search Contract Version: `1.0.0`
- Search Engine: SQLite + FTS5 — ADR-0022 Accepted
- Content Pack Trust Model: TUF — ADR-0023 Accepted
- Repository Visibility: Private during active development
- Branch Protection: unavailable/not enabled on the current private-repository plan; procedural PR + CI + architecture-review gates remain mandatory.

Detailed current status is maintained in [`docs/current-status.md`](current-status.md). Historical project-state detail from the Phase 5.3-era snapshot is preserved in [`docs/history/project-state-phase53-snapshot.md`](history/project-state-phase53-snapshot.md).

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **IN PROGRESS**
- Phase 5.5.1 — Pack Trust Contracts + ADR-0023: **COMPLETE / MERGED**
- Phase 5.5.2 — Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.3 — Production Shared Core Technology Spike: **ARCHITECTURE GATE / SPIKE AUTHORIZED**
- Phase 5.6 — Windows Desktop MVP: **NOT STARTED**
- Phase 5.7 — Web / PWA: **NOT STARTED**
- Phase 5.8 — API / CLI: **NOT STARTED**
- Phase 5.9 — Grounded AI: **NOT STARTED**
- Phase 5.10 — Public Preview Readiness: **NOT STARTED**

The Phase 5.5.3 numbering is introduced by the current architecture gate. It was not a previously frozen roadmap subphase.

## Frozen Architecture

The following remain authoritative:

- exactly seven canonical AtlasRecord families under `schemas/v1/`;
- canonical identifier pattern `atlas:<entity-type>:<namespace>:<canonical-key>`;
- native identifiers remain separate and Event ID is not globally unique;
- legacy/current lifecycle preservation;
- deterministic exact identifier resolution before lexical retrieval;
- SQLite + FTS5 for the derived deterministic search artifact;
- TUF-based signed content-pack trust, verification and rollback boundary;
- offline-first operation, inspectable provenance and Last Known Good preservation;
- shared contracts across Desktop, Web/PWA, API and CLI;
- official CLI command: `atlas`.

## Phase 5.5.2 Closure

Phase 5.5.2 merged via PR #20 at merge commit `9a8f9f30a937d546ed08a205d19998bbbd1ed0d9` and is post-merge verified. It delivered:

- bounded fail-closed `.atlaspack` extraction;
- parser-sanitization rejection for non-canonical ZIP wire names;
- offline TUF verification with caller-supplied bootstrap trust and durable metadata rollback state;
- exact manifest/license/artifact byte binding;
- canonical AtlasRecord validation;
- verified SPC plus SQLite/FTS5 validation/rebuild fallback;
- strict runtime compatibility and SemVer/highest-seen rollback protection;
- persistent trusted-time rollback/state-loss guard;
- immutable generation staging, atomic activation, health checks, LKG preservation and rollback;
- deterministic verified pack building without production private-key handling;
- Linux/Windows adversarial and regression CI;
- no change to canonical `schemas/v1/`.

The post-merge documentation synchronization was merged via PR #21 at `d2c837b0740b52aeca9dd579c32911e01c8c6ecc`.

## Phase 5.5.3 Architecture Gate

The next material decision is the production Shared Core implementation/runtime. The spike must compare candidates against the already accepted Atlas contracts rather than redefining them.

Architecture screening covers Rust, Go, Python control, TypeScript/Node.js and .NET/C#. The initial executable finalists are Rust, Go and Python control, subject to hard pass/fail gates for:

- canonical and cross-language digest fidelity;
- exact Phase 5.4 search semantic parity;
- SQLite + FTS5 behavior;
- TUF / Atlas POUF v1 interoperability;
- durable Windows/Linux state and rollback semantics;
- offline/no-network trust boundary;
- reproducible cross-platform builds and machine-readable evidence.

`ADR-0024 — Production Shared Core Technology Selection` remains Proposed until the executable evidence is complete. No production Shared Core language/runtime is frozen by the architecture-gate PR.

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

Proposed:

- ADR-0024 — Production Shared Core Technology Selection

## Technology Decisions Still Open

- production Shared Core implementation language/runtime — Phase 5.5.3;
- Windows Desktop implementation stack;
- broader local application storage beyond the accepted derived search artifact;
- graph persistence/index implementation;
- Detection Intermediate Representation;
- HSM/KMS and production signing-provider selection;
- portable Windows packaging implementation;
- application binary update mechanism;
- remote content distribution/CDN topology;
- Grounded AI runtime.

## Architecture Sync

- Architecture Sync Date: 2026-09-06
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Architecture Sync Status: **GREEN**
- Stage 1: **APPROVED AND MERGED**
- Phase 5.2: **APPROVED AND MERGED**
- Phase 5.3: **APPROVED AND COMPLETE**
- Phase 5.4: **APPROVED AND COMPLETE**
- Phase 5.5.1: **APPROVED AND COMPLETE**
- Phase 5.5.2: **APPROVED, MERGED AND POST-MERGE VERIFIED**
- Phase 5.5.3: **ARCHITECTURE SPIKE AUTHORIZED; TECHNOLOGY NOT YET SELECTED**

No blocking architecture conflict is known at this boundary. A technology candidate that cannot reproduce Atlas security/search/pack contracts is disqualified rather than accommodated by changing those contracts.
