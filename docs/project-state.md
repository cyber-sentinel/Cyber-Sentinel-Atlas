# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Latest verified Public Preview control-plane baseline: `d1efb549c1b651b58052a616bba82a3b146c0d6e`
- Release authority remains `main`; documentation commits may advance the branch without redefining the verified control-plane baseline above.
- First Preview package release baseline SHA: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- Phase 5.6 release vehicle: PR #39 — **MERGED**
- Phase 5.6 documentation closure: PR #41 — **MERGED**
- Phase 5.10 readiness baseline: PR #42 — **MERGED**
- Phase 5.10 README sync: PR #43 — **MERGED**
- Phase 5.10.4 governance/freshness closure: PR #44 — **MERGED**
- Architecture Sync Status: **GREEN**
- Repository visibility: **Public**
- Release state: **First Preview engineering readiness READY / public release Pre-preview / unreleased**
- Active phase: **Phase 5.10 — Public Preview Readiness**
- Phase 5.10.5 Usable Data Preview: **COMPLETE / EXACT-HEAD VERIFIED — MERGE PENDING**
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
- Phase 5.6 — Windows Desktop MVP: **COMPLETE / MERGED / POST-MERGE VERIFIED**
  - 5.6.0 Environment / Core Boundary: **COMPLETE / VERIFIED**
  - 5.6.1 Executable Candidate Builds: **COMPLETE / VERIFIED**
  - 5.6.2 Mandatory Hard Gates / Desktop Selection: **COMPLETE / VERIFIED**
    - G-D1 through G-D9: **PASS / CLOSED**
    - accepted selection evidence run: `35090304056`
    - final PR regression run: `35112236628` — **SUCCESS**
    - ADR-0026: **ACCEPTED — Tauri 2.x**
  - 5.6.3 First Preview UI: **COMPLETE / MERGED / VERIFIED**
  - 5.6.4 Windows Packaging / Clean-Machine Smoke: **COMPLETE / MERGED / POST-MERGE VERIFIED**
    - authoritative post-merge run: `35133827422` — **SUCCESS**
    - First Preview package release baseline: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- First Preview engineering readiness: **READY**
- Phase 5.7 — Web / PWA: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.8 — Broader API surfaces: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.9 — Grounded AI: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.10 — Public Preview Readiness: **ACTIVE**
  - 5.10.0 Public Preview Readiness Baseline: **COMPLETE / MERGED**
  - 5.10.1 Licensing / Redistribution Closure: **CONTROL PLANE COMPLETE / PPR-03 & PPR-04 BLOCKED**
  - 5.10.2 Production Signing / Key Custody / Attestation: **CONTROL PLANE COMPLETE / PPR-05 BLOCKED**
  - 5.10.3 Public Packaging / Distribution Hardening: **CONTROL PLANE COMPLETE / PPR-06 BLOCKED**
  - 5.10.4 Accessibility / Freshness / Launch Governance: **CONTROL PLANE COMPLETE / PPR-07 PARTIAL**
    - PPR-08 source freshness/public-pack publication policy: **PASS**
    - PPR-09 release governance/launch criteria: **PASS**
    - PPR-07 packaged accessibility release review: **PARTIAL**
  - 5.10.5 Usable Data Preview: **COMPLETE / EXACT-HEAD VERIFIED — MERGE PENDING**
    - clean-Windows Windows Security Event ID `4688`: **PASS**
    - clean-Windows Sysmon Event ID `1`: **PASS**
    - Search / Record / Graph / Provenance: **PASS**
    - deliberate TUF target tamper rejection: **PASS / FAIL-CLOSED**
    - exact-head run `35253441607`: **SUCCESS**
  - Public Preview readiness: **BLOCKED**

The explicit Phase 5.5.2/5.5.3/5.5.4 lifecycle markers above are compatibility invariants consumed by historical architecture gates even though the aggregate Phase 5.5 boundary is frozen.

## Frozen Architecture

The following remain authoritative and may not drift to simplify later release work:

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

All three desktop candidate families passed the mandatory selection gates in accepted evidence. The weighted review is retained in `benchmarks/desktop/phase56/weighted-review.json` and ADR-0026 records the final host decision:

- **Selected:** Tauri 2.x;
- .NET 10 / WPF: evaluated and not selected;
- Electron: evaluated and not selected.

Selection does not move canonical, search, graph, provenance or pack-trust ownership into the UI. Those remain Shared Core responsibilities.

### Selected-host security boundary

The Tauri First Preview is limited to one main-window capability and exactly seven application commands:

`core_status`, `search_records`, `get_record`, `expand_graph`, `pack_status`, `pack_update`, `pack_rollback`.

The baseline retains CSP `connect-src 'none'`, no Tauri plugins, no generic frontend-controlled Shared Core method bridge, no generic application network API, committed/hash-guarded `Cargo.lock`, and adjacent SHA-256-bound `atlas-core.exe`.

## First Preview Product Boundary

The First Preview is intentionally constrained to analyst-critical functionality:

- Offline Global Search;
- Canonical Record Detail;
- bounded relationship/graph navigation;
- claim/source provenance;
- Windows Event and Sysmon-oriented investigation context present in the pack;
- verified pack state/update;
- safe rollback / recovery visibility;
- UTC plus system-local and Tehran/Jalali presentation as UI formatting;
- operational dark UI and accessibility/high-contrast support.

## Post-Merge Packaging Evidence

Phase 5.6.4 post-merge run `35133827422` built the selected Tauri host and exact production Shared Core from First Preview package release baseline `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`, produced one byte-bound portable package, and consumed the same immutable artifact on clean GitHub-hosted Windows.

Verified acceptance included:

- package/payload hash and size binding;
- exact Shared Core commit binding;
- relocation to a path containing spaces;
- packaged offline/no-listener probe;
- deliberate sidecar-corruption rejection;
- recovery after restoring verified bytes;
- WebView2 prerequisite detection;
- GUI liveness;
- zero TCP listeners across the GUI process tree;
- zero UDP endpoints owned by ATLAS or Shared Core.

Artifacts:

- package artifact `10462114843`, digest `sha256:57d9cce8a2ec85900bbc6b4fe250eefe53b43b241ddbefd2a9a1d9aafaee6f50`;
- clean-Windows evidence artifact `10463420685`, digest `sha256:456ea3aa6a7b2c84a555c2c1e60c8f31086781172ce53d530d677abd29f019d5`.

First Preview packaging is intentionally unsigned. Production Authenticode signing and public distribution/release hardening are Phase 5.10 work. Binary auto-update is not part of First Preview.

## Phase 5.10.5 Usable Data Preview Boundary

Phase 5.10.5 closes the usability defect in which the desktop/process/IPC path could be healthy while the packaged product still had no active verified knowledge pack and search returned `ATLAS_PACK_NOT_READY`.

Exact-head evidence authority before PR creation:

- branch: `phase-5.10.5-usable-data-preview`;
- exact head: `e5f76ef8f9bc8dad83b12387a7e7b9edfc6dd8a4`;
- workflow run: `35253441607` — **SUCCESS**;
- package artifact `10512162655`, digest `sha256:65bc9987b9673c0c711e049813b8562b978f30192799f11397cff1113d450f62`;
- clean-Windows evidence artifact `10511033598`, digest `sha256:7c7569437f6139a27cee3743e1e0e426a64f03f0dc20044526165c3068bcc60e`.

The same packaged acceptance path proved exact Windows Security Event ID `4688`, Sysmon Event ID `1`, canonical Record, bounded Graph and Provenance behavior. A deliberately modified signed target was rejected by TUF verification; the final harness explicitly treats that expected non-zero exit as successful fail-closed evidence.

This slice adds no Public Preview authority. It preserves the frozen canonical schema, Shared Core, stdio, trust, anti-rollback, LKG and no-default-listener boundaries.

## Phase 5.10 Public Preview Readiness Boundary

Phase 5.10 establishes a strict separation between First Preview engineering readiness and Public Preview publication authority.

Machine-readable authority: `docs/releases/phase-5.10-public-preview-readiness.json`.

Human-readable gate matrix: `docs/releases/phase-5.10-public-preview-readiness.md`.

Current mandatory blocker set:

- first-party licensing decision — **BLOCKED**;
- third-party redistribution closure — **BLOCKED**;
- production code signing and protected key custody — **BLOCKED**;
- public packaging and distribution hardening — **BLOCKED**;
- accessibility release review — **PARTIAL**.

Already closed supporting gates:

- First Preview engineering baseline — **PASS**;
- security disclosure/supported-release policy — **PASS**;
- source freshness/public-pack publication policy — **PASS**;
- release governance/launch criteria — **PASS**;
- supply-chain evidence — **PASS**;
- trademark/attribution controls — **PASS**.

The source freshness policy is defined in `docs/releases/source-freshness-and-publication-policy.md`. It establishes source-specific refresh objectives, maximum unattended age, staleness handling, Last Known Good behavior and public-pack acceptance evidence.

The launch governance contract is defined in `docs/releases/public-preview-launch-governance.md`. It establishes exact release authority, strict GO/NO-GO criteria, immutable release evidence, rollback, withdrawal and emergency security revocation.

The accessibility acceptance contract is defined in `docs/releases/accessibility-release-review.md`. PPR-07 remains PARTIAL until the exact packaged Windows candidate completes the keyboard, Narrator, high-contrast, scaling and semantic review with executable evidence.

The Phase 5.10.5 evidence contract is defined in `docs/releases/phase-5.10.5-usable-data-preview.md` and records the clean-Windows usable-data acceptance without changing mandatory PPR status.

A baseline CI gate validates that blockers are represented honestly. A separate strict release mode fails until every mandatory Public Preview gate is `PASS` and release evidence exists.

## Accepted ADRs

ADR-0001 through ADR-0026 are accepted according to repository history. Current major technology decisions include:

- ADR-0022 — SQLite + FTS5 deterministic search artifact;
- ADR-0023 — Secure Content Pack Trust and Update Model;
- ADR-0024 — Production Shared Core Technology Selection;
- ADR-0025 — Shared Core Local Interface Boundary;
- ADR-0026 — Windows Desktop Host Selection: **Tauri 2.x**.

## Technology Decisions Still Open

- first-party licensing model;
- production signing provider / HSM/KMS and certificate lifecycle;
- public installer/distribution policy beyond First Preview portable ZIP;
- application binary update mechanism;
- broader graph persistence/index implementation;
- Detection Intermediate Representation;
- remote content distribution/CDN topology;
- Grounded AI runtime.

The source-freshness/public-pack publication policy and release-governance/launch criteria are no longer open policy decisions; they now require per-release operational evidence rather than architecture selection.

## Immediate Sequence

```text
Phase 5.6 / First Preview engineering closure                 COMPLETE
       ↓
Phase 5.10.0 readiness baseline                              COMPLETE / MERGED
       ↓
Phase 5.10.5 clean-Windows usable-data acceptance            COMPLETE / EXACT-HEAD VERIFIED
       ↓
Phase 5.10.4 freshness + launch governance                   PASS / POLICY CLOSED
       ↓
Phase 5.10.4 packaged accessibility review                   PARTIAL
       ↓
Licensing / third-party redistribution                       BLOCKED
       ↓
Signing / key custody / artifact attestation                 BLOCKED
       ↓
Public packaging / distribution hardening                    BLOCKED
       ↓
STRICT PUBLIC PREVIEW READINESS GATE                         BLOCKED
```

There is no remaining Phase 5.6 engineering blocker. The public release remains intentionally pre-preview/unreleased until the mandatory Phase 5.10 boundaries are closed.

No mandatory gate was bypassed.
