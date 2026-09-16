# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Active implementation branch: `feature/phase-5.6-windows-desktop-mvp`
- Active release vehicle: **PR #39**
- Last Reviewed Main SHA: `ebe2d29c8857bdbfde5c87bedb4b91e08d05777a`
- Architecture Sync Status: **GREEN**
- Repository visibility: **Public**
- Release state: **First Preview candidate / feature implementation complete / final PR regression closure active / not yet merged**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022 Accepted
- Content-pack trust model: TUF — ADR-0023 Accepted
- Production Shared Core: Go — ADR-0024 Accepted
- Shared Core Local Interface: child-process stdio protocol — ADR-0025 Accepted
- Desktop implementation stack: **Tauri 2.x — ADR-0026 Accepted**

Operational evidence is summarized in [`docs/current-status.md`](current-status.md). Historical snapshots remain under `docs/history/`.

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**
- Phase 5.5.2 — Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.6 — Windows Desktop MVP: **FEATURE-BRANCH IMPLEMENTATION COMPLETE / PR RELEASE CLOSURE ACTIVE**
  - 5.6.0 Environment / Core Boundary: **COMPLETE / VERIFIED**
  - 5.6.1 Executable Candidate Builds: **COMPLETE / VERIFIED**
  - 5.6.2 Mandatory Hard Gates / Desktop Selection: **COMPLETE / VERIFIED FOR ACCEPTED SELECTION EVIDENCE**
    - G-D1 through G-D9: **PASS / CLOSED in frozen selection evidence**
    - accepted evidence run: `35090304056`
    - candidate evidence commit: `c343ffd881dd7b6a420f04cea2ffb91c3ea8a715`
    - ADR-0026: **ACCEPTED — Tauri 2.x**
    - current PR regression: **BLOCKED pending Electron UDP measurement attribution/closure**
    - failed regression run snapshot: `35100673553`
  - 5.6.3 First Preview UI: **COMPLETE / VERIFIED ON FEATURE BRANCH**
  - 5.6.4 Windows Packaging / Clean-Machine Smoke: **COMPLETE / VERIFIED ON FEATURE BRANCH**
    - latest verified PR implementation-head package/smoke run: `35100673319`
    - verified implementation head: `8feb39a62a1b480428b180ad68cf6ab88340f513`
    - earlier acceptance run: `35095383694`
- Phase 5.7 — Web / PWA: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.8 — Broader API surfaces: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.9 — Grounded AI: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.10 — Public Preview Readiness: **PLANNED**

The explicit Phase 5.5.2/5.5.3/5.5.4 lifecycle markers above are retained as current compatibility invariants for historical architecture gates even though the aggregate Phase 5.5 boundary is now frozen.

## Frozen Architecture

The following remain authoritative and may not drift to simplify the Desktop host:

- exactly seven canonical `AtlasRecord` families under `schemas/v1/`;
- canonical identifiers remain provider/entity scoped;
- deterministic exact-before-lexical retrieval;
- SQLite + FTS5 as derived deterministic search artifact;
- TUF signed content-pack trust, trusted-time and anti-rollback state;
- immutable generations, atomic activation and Last Known Good behavior;
- Go production Shared Core with Python retained as semantic/conformance oracle;
- deterministic Atlas serialization/digest profile;
- ADR-0025 `atlas-core --serve-stdio` local boundary;
- no default local HTTP/TCP/WebSocket listener or hidden network fallback;
- offline-first operation and inspectable provenance.

## Phase 5.6 Closed Selection Boundary

All three candidate families passed mandatory hard gates in the accepted selection evidence. The accepted weighted review is retained in `benchmarks/desktop/phase56/weighted-review.json` and ADR-0026 records the final host decision:

- **Selected:** Tauri 2.x;
- .NET 10 / WPF: evaluated and not selected;
- Electron: evaluated and not selected.

Selection does not move canonical, search, graph, provenance or pack-trust ownership into the UI. Those remain Shared Core responsibilities.

### Selected-host security boundary

The Tauri First Preview is limited to one main-window capability and exactly seven application commands:

`core_status`, `search_records`, `get_record`, `expand_graph`, `pack_status`, `pack_update`, `pack_rollback`.

The baseline retains CSP `connect-src 'none'`, no Tauri plugins, no generic frontend-controlled Shared Core method bridge, no generic application network API, committed/hash-guarded `Cargo.lock`, and adjacent SHA-256-bound `atlas-core.exe`.

## Current PR Regression Blocker

PR #39 is the active release-closure vehicle. On implementation head `8feb39a62a1b480428b180ad68cf6ab88340f513`, the following major workflows completed successfully before documentation sync advanced the branch head:

- Governance Hygiene;
- Foundation Hygiene;
- Phase 5.5.1 Pack Trust Contracts;
- Phase 5.5.2 Verified Pack Runtime;
- Phase 5.5.3 Shared Core Architecture;
- Phase 5.5.4 Production Go Architecture;
- Phase 5.5.4A Go Protocol Core;
- Phase 5.5.4B Canonical Search Graph;
- Phase 5.5.4D Supply Chain Closure;
- Phase 5.6.2 Active Pack Integration;
- Phase 5.6.4 Windows First Preview Package.

`Phase 5.6.2 Desktop Gate Evidence` run `35100673553` failed at `Measure candidates with common external harness` because the **Electron process tree opened a UDP endpoint during the controlled probe**. The security-surface validator, exact-head Shared Core build/IPC, and Tauri/.NET/Electron candidate builds and probes had already passed.

This does not change ADR-0026 by assertion. Electron is not the selected product host, and the selected Tauri package/clean-Windows gate is green. It does remain a PR regression blocker because the comparative candidate workflow is still part of the release CI contract. The observation must be attributed and closed without weakening the intended network-posture check or bypassing the gate.

## First Preview Product Boundary

The implemented First Preview is intentionally constrained to analyst-critical functionality:

- Offline Global Search;
- Canonical Record Detail;
- bounded relationship/graph navigation;
- claim/source provenance;
- Windows Event and Sysmon-oriented investigation context present in the pack;
- verified pack state/update;
- safe rollback / recovery visibility;
- UTC plus system-local and Tehran/Jalali presentation as UI formatting;
- operational dark UI and basic accessibility/high-contrast support.

## Packaging Boundary

Phase 5.6.4 produced a byte-bound portable Windows ZIP containing the selected Tauri host, the exact-head production Shared Core and its SHA-256 manifest. Latest verified PR implementation-head package evidence is run `35100673319` at `8feb39a62a1b480428b180ad68cf6ab88340f513`. The same immutable artifact passed clean-Windows verification for:

- package and payload integrity;
- relocation to a path containing spaces;
- exact Shared Core commit binding;
- packaged offline/no-listener probe;
- deliberate sidecar-corruption rejection;
- recovery after restoring verified bytes;
- WebView2 prerequisite detection;
- GUI liveness;
- zero TCP listeners across the GUI process tree;
- zero UDP endpoints owned by ATLAS or Shared Core.

Runtime-owned WebView2 UDP, when present, is attributed and recorded in evidence; it is not conflated with an ATLAS/Core listener and is not silently ignored.

First Preview packaging is intentionally unsigned. Production Authenticode signing and public distribution/release hardening remain later release-readiness work. Binary auto-update is not part of First Preview.

## Accepted ADRs

ADR-0001 through ADR-0026 are accepted according to repository history. Current major technology decisions include:

- ADR-0022 — SQLite + FTS5 deterministic search artifact;
- ADR-0023 — Secure Content Pack Trust and Update Model;
- ADR-0024 — Production Shared Core Technology Selection;
- ADR-0025 — Shared Core Local Interface Boundary;
- ADR-0026 — Windows Desktop Host Selection: **Tauri 2.x**.

## Technology Decisions Still Open

- production signing provider / HSM/KMS;
- public installer/distribution policy beyond First Preview portable ZIP;
- application binary update mechanism;
- broader graph persistence/index implementation;
- Detection Intermediate Representation;
- remote content distribution/CDN topology;
- Grounded AI runtime.

## Immediate Sequence

```text
Feature implementation + selected-host package/smoke verification   COMPLETE
       ↓
README / authoritative documentation sync                           COMPLETE
       ↓
PR #39 final regression blocker closure                             ACTIVE
       ↓
Merge to main                                                       PENDING
       ↓
Post-merge package verification                                     PENDING
       ↓
FIRST PREVIEW READY / POST-MERGE VERIFIED
```

Current blocker: identify ownership/cause of the Electron process-tree UDP endpoint observed by the historical multi-candidate measurement harness, remediate or correctly scope the assertion based on evidence, and obtain a green regression run without bypassing security policy.

No mandatory gate is bypassed. The project must not claim First Preview readiness before all PR checks, merge and post-merge verification complete.
