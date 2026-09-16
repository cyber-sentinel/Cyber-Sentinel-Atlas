# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Active implementation branch: `feature/phase-5.6-windows-desktop-mvp`
- Last Reviewed Main SHA: `ebe2d29c8857bdbfde5c87bedb4b91e08d05777a`
- Architecture Sync Status: **GREEN**
- Repository visibility: **Public**
- Release state: **Pre-preview / unreleased**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022 Accepted
- Content-pack trust model: TUF — ADR-0023 Accepted
- Production Shared Core: Go — ADR-0024 Accepted
- Shared Core local interface: child-process stdio protocol — ADR-0025 Accepted
- Desktop implementation stack: **not selected** — ADR-0026 pending

Detailed operational status is maintained in [`docs/current-status.md`](current-status.md). Historical snapshots remain under `docs/history/`.

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**
- Phase 5.6 — Windows Desktop MVP: **IN PROGRESS**
  - 5.6.0 Environment / Core Boundary: **COMPLETE / VERIFIED**
  - 5.6.1 Executable Candidate Builds: **COMPLETE / VERIFIED**
  - 5.6.2 Mandatory Hard Gates / Desktop Selection: **IN PROGRESS**
    - G-D1 Clean Windows build: **PASS**
    - G-D2 stdio handshake/status: **PASS**
    - G-D3 Offline / TCP / UDP process-tree network posture: **PASS / VERIFIED**
    - G-D4 Sidecar location/integrity/version: **PASS**
    - G-D5 Active verified pack read model: **PASS / VERIFIED**
    - G-D6 Pack update + safe rollback: **PASS / VERIFIED**
    - G-D7 Desktop security surface: **IMPLEMENTED / CI PENDING**
    - G-D8 Installer / Portable feasibility: **IMPLEMENTED / CI PENDING**
    - G-D9 Measurements / reproducibility closure: **PARTIAL**
  - 5.6.3 First Preview UI: **PLANNED**
  - 5.6.4 Windows Packaging / Smoke Closure: **PLANNED**
- Phase 5.7 — Web / PWA: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.8 — Broader API surfaces: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.9 — Grounded AI: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.10 — Public Preview Readiness: **PLANNED**

## Frozen Architecture

The following remain authoritative and may not drift merely to simplify the Desktop host:

- exactly seven canonical `AtlasRecord` families under `schemas/v1/`;
- canonical identifiers remain provider/entity scoped; Event ID is not globally unique;
- deterministic exact-before-lexical retrieval;
- SQLite + FTS5 as the derived deterministic search artifact;
- TUF-based signed content-pack trust, trusted-time and anti-rollback state;
- immutable generations, atomic activation and Last Known Good behavior;
- Go production Shared Core with Python retained as semantic/conformance oracle;
- existing Atlas deterministic serialization/digest profile;
- ADR-0025 `atlas-core --serve-stdio` local protocol boundary;
- no default local HTTP/TCP/WebSocket listener and no hidden network fallback;
- offline-first operation and inspectable provenance.

## Phase 5.6 Active Boundary

Phase 5.6 consumes the frozen Shared Core rather than reimplementing it.

Three Windows host candidates remain under evaluation:

- Tauri 2.x;
- Electron;
- .NET 10 Windows Desktop / WPF.

No framework preference or selection is accepted until every mandatory hard gate is closed and ADR-0026 records the evidence, rejected alternatives and residual risk.

### Verified desktop evidence to date

- G-D3: exact-head Candidate Builds run `35078440647` at `4e0a770e06cfacb195bfaf2ebb11a647aabc83e8` passed common process-tree TCP and UDP probes for all three candidates.
- G-D5: verified Active Generation loads into production canonical/search/graph read models on Windows.
- G-D6: exact-head run `35075820479` at `32874c7b95239579d6c11839a325dec0081d18f5` passed real-process signed update → same-process status/search → rollback → same-process status/search, while preserving highest-seen trust state and rejecting an untrusted-root update without losing the active read model.

### Implemented evidence awaiting CI closure

- G-D7: machine-enforced candidate security-surface validation is implemented for Electron, Tauri and native .NET/WPF; it remains unverified until the active Windows Candidate run completes successfully.
- G-D8: portable relocation and packaging-feasibility evidence is implemented. Each real candidate must run from a relocated path containing spaces while retaining the adjacent Shared Core integrity boundary. Final installer build/signing and clean-machine installer smoke remain Phase 5.6.4 work.
- Tauri reproducibility: `Cargo.lock` is committed and exact-hash guarded; Candidate CI no longer calls `cargo generate-lockfile`, uses `--locked`, and fails on missing/drifted/mutated lock state.
- Current Windows Candidate verification run: `35084472666` on branch snapshot `19242f0cabb27a606dc4ddc1603a381ea5a19342`; status at this project-state update: **IN PROGRESS**.

## First Preview Product Boundary

The first preview is intentionally constrained to analyst-critical functionality:

- Offline Global Search;
- Canonical Record Detail;
- bounded relationship/graph navigation;
- claim/source provenance;
- Windows Event and Sysmon-oriented investigation context present in the pack;
- verified pack state/update;
- safe rollback / recovery visibility;
- UTC plus system/user-selected time zones, with Tehran/Jalali presentation as UX formatting rather than canonical timestamp mutation.

Visual direction is an operational intelligence dark interface with user-selectable theme tokens, stable security-state semantics, dense technical surfaces and validated geographic assets. Decorative identity remains subordinate to data.

## Accepted ADRs

ADR-0001 through ADR-0025 remain accepted according to repository history. The current major technology decisions are:

- ADR-0022 — SQLite + FTS5 deterministic search artifact;
- ADR-0023 — Secure Content Pack Trust and Update Model;
- ADR-0024 — Go Production Shared Core;
- ADR-0025 — Shared Core Local Interface Boundary;
- ADR-0026 — Windows Desktop Host Selection: **PENDING**.

## Technology Decisions Still Open

- Windows Desktop host family — Phase 5.6.2 / ADR-0026;
- final installer technology and portable packaging implementation;
- application binary update mechanism;
- production signing provider / HSM/KMS;
- broader graph persistence/index implementation;
- Detection Intermediate Representation;
- remote content distribution/CDN topology;
- Grounded AI runtime.

## Immediate Sequence

```text
G-D7 / G-D8 Exact-head Windows Verification
       ↓
G-D9 Measurement Closure
       ↓
ADR-0026 Desktop Selection
       ↓
5.6.3 First Preview UI
       ↓
5.6.4 Windows Packaging / Smoke Closure
```

No blocking architecture conflict is currently known. Mandatory gates remain fail-closed and First Preview readiness may not be claimed before Phase 5.6.4 completes and verifies.
