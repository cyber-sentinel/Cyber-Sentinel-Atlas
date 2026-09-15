# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-15

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative branch: `main`
- Phase 5.5.3 selection completion main SHA: `bbb462b11de460216acb80116146f651ac2ef1ca`
- Phase 5.5.4 architecture baseline main SHA: `94f3136687f8e9765c0343b938a1049436878783`
- Phase 5.5.4 production closure merge SHA: `00a27df6b28b034fecc3905865e0aac200e5aa87`
- Phase 5.5.4 closure PR: `#35`
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5, accepted by ADR-0022
- Content-pack trust model: TUF-based, accepted by ADR-0023
- Production Shared Core implementation family: **Go**, accepted by ADR-0024
- Production Shared Core local interface: **child-process stdio protocol**, accepted by ADR-0025
- Production Go toolchain baseline after closure remediation: **Go 1.25.13**
- Production dependency baselines relevant to Phase 5.5 closure: `go-tuf/v2 v2.4.2`, `modernc.org/sqlite v1.58.0`, `golang.org/x/text v0.39.0`
- Python implementation role: semantic/conformance oracle retained for regression/conformance testing
- Repository visibility: private during active development
- Public project license: not yet adopted; see `docs/governance/licensing-and-contributions.md`

Git history and the live `main` branch tip remain the final repository authority. This document records the last verified phase boundary without predicting a future merge SHA.

## Completed phases

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.3.1 — Ingestion Foundation: **COMPLETE / MERGED**
- Phase 5.3.2 — ATT&CK Canary: **COMPLETE / MERGED**
- Phase 5.3.3 — Windows Security + Sysmon: **COMPLETE / MERGED**
- Phase 5.3.4 — D3FEND + CAR + DefenseOps + Promotion Gates: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.4.1 — Search Contracts + Reference Resolver: **COMPLETE / MERGED**
- Phase 5.4.2 — Engine Spike + ADR-0022: **COMPLETE / MERGED**
- Phase 5.4.3 — Production SQLite/FTS5 Search Core: **COMPLETE / MERGED**
- Phase 5.4.4 — Catalog, Graph Pivots, Benchmarks and Closure: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.1 — Pack Trust Contracts + ADR-0023: **COMPLETE / MERGED**
- Phase 5.5.2 — Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.4A — Core skeleton + protocol: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4B — Canonical + SQLite/FTS5 search + graph parity: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4C — TUF/pack trust + durable state/LKG: **COMPLETE / MERGED / VERIFIED**
- Phase 5.5.4D — Supply-chain / cross-platform closure: **COMPLETE / MERGED / POST-MERGE VERIFIED**

## Phase 5.5.3 technology-selection boundary

Phase 5.5.3 selected Go only after executable cross-platform evidence. The accepted selection baseline proved mandatory G-SC1 through G-SC8 on Linux and Windows, retained Python as the semantic/conformance oracle, kept SQLite/FTS5 subordinate to the Phase 5.4 contracts, preserved the existing Atlas deterministic JSON profile, and did not select the Desktop UI framework or other later technology decisions.

The original Phase 5.5.3 evidence baseline used Go 1.25.0 and `golang.org/x/text v0.36.0`. Those values remain historical selection evidence only; Phase 5.5.4D subsequently patched the production baseline to Go 1.25.13 and `golang.org/x/text v0.39.0` after fail-closed vulnerability checks.

## Phase 5.5.4 production closure

ADR-0025 freezes the local Desktop-facing Shared Core boundary as a versioned child-process stdio protocol implemented by `atlas-core --serve-stdio`, rather than Go FFI or a default local HTTP/TCP listener.

Protocol v1 uses a 4-byte unsigned big-endian length prefix followed by UTF-8 JSON. It requires an exact `atlas-core` protocol `1.0.0` handshake, one request at a time per child process, compiled method allowlists, protocol-only stdout, diagnostic-only stderr, bounded request/response sizes, duplicate-key rejection, bounded nesting depth, strict UTF-8/JSON validation and no hidden network fallback.

Phase 5.5.4 closed the production port across four slices:

1. 5.5.4A — production Go core skeleton and typed stdio protocol;
2. 5.5.4B — canonical validation plus deterministic SQLite/FTS5 exact/lexical search, catalogs and bounded graph reads;
3. 5.5.4C — Atlas TUF POUF v1, strict `.atlaspack` handling, immutable generations, trusted-time/highest-seen guards, activation/LKG and rollback;
4. 5.5.4D — reproducible Linux/Windows builds, CycloneDX SBOM evidence, linked-module validation, vulnerability evidence, dependency/license inventory, Python-oracle conformance and binary/IPC measurements.

PR #35 merged the exact-head green closure as merge commit `00a27df6b28b034fecc3905865e0aac200e5aa87`. The production baseline was patched rather than suppressing findings: Go moved from 1.25.0 to 1.25.13 and `golang.org/x/text` from v0.36.0 to v0.39.0, while `go-tuf/v2 v2.4.2` and `modernc.org/sqlite v1.58.0` remained locked.

Post-merge CI on the closure SHA passed the Phase 5.5.4A, 5.5.4B, 5.5.4C and 5.5.4D workflows. The Production Shared Core dependency of Phase 5.6 is therefore satisfied.

## Active implementation slice

**Phase 5.6 — Windows Desktop MVP: READY / IMPLEMENTATION ENTRY AUTHORIZED**

The first slice is **Phase 5.6.1 — Desktop Technology Spike + ADR-0026**. It must select the Windows Desktop implementation stack from executable evidence rather than inherit a UI technology from Go, ADR-0024 or ADR-0025.

Mandatory 5.6.1 evidence gates include:

- correct integration with `atlas-core --serve-stdio` using the frozen protocol boundary without FFI coupling or hidden network fallback;
- offline startup and core user journeys without internet dependency;
- exact/lexical search, entity detail, relationships, provenance and pack-state flows through the Shared Core rather than a parallel knowledge engine;
- Windows install/package feasibility and portable-mode feasibility;
- clean process lifecycle, crash containment and safe child-process termination;
- bounded startup time and idle/runtime memory evidence on the Windows CI runner;
- dependency/SBOM/vulnerability and license visibility;
- code-signing and release-pipeline compatibility without prematurely selecting the final signing provider;
- accessibility, keyboard navigation, DPI/scaling and Windows UX feasibility;
- deterministic automated smoke testing on the self-hosted Windows runner.

No Desktop stack is accepted until the spike evidence and ADR-0026 pass review and CI.

## Remaining roadmap

- Phase 5.6 — Windows Desktop MVP: **READY / 5.6.1 NEXT**
- Phase 5.6.1 — Desktop Technology Spike + ADR-0026: **AUTHORIZED / NOT YET SELECTED**
- Phase 5.7 — Web / PWA: **NOT STARTED**
- Phase 5.8 — API / CLI (`atlas`): **NOT STARTED**
- Phase 5.9 — Grounded AI: **NOT STARTED**
- Phase 5.10 — Public Preview Readiness, licensing, security, accessibility, release and final repository hygiene: **NOT STARTED**

## Governance

All official changes remain branch → PR → CI → architecture/security review → expected-head Merge Commit → post-merge verification. The standing Architecture Authority authorization permits autonomous progression through the accepted roadmap while these evidence and merge controls remain mandatory. Third-party licensing and public contributor-rights review remain fail-closed before Public Preview.
