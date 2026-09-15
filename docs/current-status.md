# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-15

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative branch: `main`
- Phase 5.5.3 selection completion main SHA: `bbb462b11de460216acb80116146f651ac2ef1ca`
- Phase 5.5.4 architecture baseline main SHA: `94f3136687f8e9765c0343b938a1049436878783`
- Phase 5.5.4 closure/post-merge verification main SHA: `00a27df6b28b034fecc3905865e0aac200e5aa87`
- Active implementation branch: `feature/phase-5.6-windows-desktop-mvp`
- Phase 5.6.0 verified evidence SHA: `a923ef63ba3e31cb8b51c6cd0d32b40113d08379`
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5, accepted by ADR-0022
- Content-pack trust model: TUF-based, accepted by ADR-0023
- Production Shared Core implementation family: **Go**, accepted by ADR-0024
- Production Shared Core local interface: **child-process stdio protocol**, accepted by ADR-0025
- Repository visibility: private during active development
- Public project license: not yet adopted; see `docs/governance/licensing-and-contributions.md`

Git history and the live `main` branch tip remain final repository authority. This document records the currently verified implementation boundary and active development slice.

## Completed phases

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE**
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

## Phase 5.5.3 historical selection boundary

Phase 5.5.3 selected Go only after executable cross-platform evidence. The accepted historical evidence boundary proved:

- Go passed mandatory G-SC1 through G-SC8 on Linux and Windows;
- Python control also passed and remains the semantic/conformance oracle for frozen vectors;
- Rust was not selected because the Phase 5.5.3 mandatory trust/runtime evidence envelope was incomplete or failed; this was not a general rejection of Rust;
- `go-tuf/v2 v2.4.2`, `modernc.org/sqlite v1.58.0`, and the then-normalized `golang.org/x/text v0.36.0` graph were evidenced selection baselines;
- SQLite/FTS5 exact and lexical behavior stayed subordinate to accepted Phase 5.4 contracts;
- existing Atlas deterministic JSON bytes remained the serialization/digest profile; no RFC 8785/JCS digest migration occurred;
- canonical `schemas/v1/` remained unchanged;
- Desktop UI technology remained a separate decision.

PR #23 merged ADR-0024 through Merge Commit `bbb462b11de460216acb80116146f651ac2ef1ca`. PR #24 synchronized that architecture boundary on `main@94f3136687f8e9765c0343b938a1049436878783`.

## Phase 5.5.4 closure

**Phase 5.5.4 — Production Go Shared Core: COMPLETE / MERGED / POST-MERGE VERIFIED**

ADR-0025 remains authoritative and freezes the local Desktop-facing Shared Core boundary as a versioned child-process stdio protocol implemented by `atlas-core --serve-stdio`, rather than Go FFI or a default local HTTP/TCP listener.

Protocol v1 uses a 4-byte unsigned big-endian length prefix followed by UTF-8 JSON. It requires an exact `atlas-core` protocol `1.0.0` handshake, one request at a time per child process, compiled method allowlists, protocol-only stdout, diagnostic-only stderr, maximum 1 MiB requests, maximum 8 MiB responses, duplicate-key rejection, bounded nesting depth, strict UTF-8/JSON validation and no hidden network fallback.

PR #35 merged Phase 5.5.4D through Merge Commit `00a27df6b28b034fecc3905865e0aac200e5aa87`. On that exact `main` SHA, post-merge verification passed:

- Foundation Hygiene and architecture/canary gates;
- 5.5.4A protocol/core on Linux and Windows;
- 5.5.4B canonical/search/graph plus Python-oracle parity on Linux and Windows;
- 5.5.4C TUF/pack trust, durable state and adversarial integration on Linux and Windows;
- 5.5.4D supply-chain closure on Linux and Windows;
- `go vet`, reproducible builds, SBOM/license validation and pinned `govulncheck`;
- cross-language conformance, binary footprint and stdio startup/IPC evidence;
- canonical `schemas/v1/` preservation.

The Shared Core is frozen for Phase 5.6 consumption. Desktop work may not duplicate or redefine canonical validation, search/graph semantics, pack trust, durable state or rollback logic.

## Active implementation slice

**Phase 5.6 — Windows Desktop MVP: IN PROGRESS**

### Phase 5.6.0 — Desktop Spike Contract + Environment/Core-Boundary Probe

Status: **COMPLETE / VERIFIED**

Run `35003711686` on exact evidence SHA `a923ef63ba3e31cb8b51c6cd0d32b40113d08379` completed successfully on the self-hosted Windows runner. It proved:

- Go `1.25.13`, Python `3.12.10`, Node `24.21.0`, npm `11.19.0`, .NET SDK `10.0.401`, Rust/Cargo `1.95.0`;
- production `atlas-core.exe` clean build and Go regression suite;
- protocol `atlas-core` version `1.0.0` handshake with session nonce echo;
- successful `core.status` response;
- `network_listener: false` and `offline_capable: true`;
- process exit code `0`, zero stderr bytes and two valid protocol responses;
- measured bootstrap handshake/status round trip `164.745 ms`;
- `atlas-core.exe` size `10,657,792` bytes;
- binary SHA-256 `ecd511e1409c124f6f73c95fe3bdac643a30780a9a93dbb977e8e3c3a2dbd6e5`;
- no canonical schema drift.

Evidence artifact `phase56-desktop-bootstrap-windows` was uploaded as artifact ID `10410728061`; the artifact ZIP SHA-256 is `73371df1fa988a04cc1e8a5e5a915844ede8bdcbbb09614cf7174779c275343a`.

### Phase 5.6.1 — Executable Desktop Candidate Builds

Status: **IN PROGRESS**

The evidence set evaluates three Desktop host families without granting any candidate architecture preference:

- Tauri 2.x;
- Electron;
- .NET 10 Windows Desktop.

Each candidate must perform the same controlled operation against the frozen production sidecar:

1. locate the packaged `atlas-core` executable;
2. validate expected executable/version identity;
3. spawn `atlas-core --serve-stdio`;
4. perform the exact protocol `1.0.0` handshake;
5. call `core.status`;
6. render returned status;
7. terminate cleanly;
8. avoid any parallel search/index/trust implementation.

Hard gates G-D1 through G-D9 remain fail-closed. No Desktop framework is selected until executable evidence is complete and ADR-0026 records one accepted host family plus rejected alternatives/residual risk.

## Remaining roadmap

- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
  - 5.5.1 Pack Trust Contracts: **COMPLETE / MERGED**
  - 5.5.2 Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**
  - 5.5.3 Production Shared Core Technology Spike + ADR-0024: **COMPLETE / MERGED / POST-MERGE VERIFIED**
  - 5.5.4 Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.6 — Windows Desktop MVP: **IN PROGRESS**
  - 5.6.0 Spike Contract + Environment/Core-Boundary Probe: **COMPLETE / VERIFIED**
  - 5.6.1 Executable Desktop Candidate Builds: **IN PROGRESS**
  - 5.6.2 Evidence Review + ADR-0026: **NOT STARTED**
  - 5.6.3 First Preview UI: **NOT STARTED**
  - 5.6.4 Windows Packaging / Portable Smoke: **NOT STARTED**
- Phase 5.7 — Web / PWA: **NOT STARTED**
- Phase 5.8 — API / CLI (`atlas`): **NOT STARTED**
- Phase 5.9 — Grounded AI: **NOT STARTED**
- Phase 5.10 — Public Preview Readiness: **NOT STARTED**

## Governance

All official changes remain branch → PR → CI → architecture/security review → expected-head Merge Commit → post-merge verification. The standing Architecture Authority authorization permits autonomous progression through the accepted roadmap while these evidence and merge controls remain mandatory. Third-party licensing and public contributor-rights review remain fail-closed before Public Preview.
