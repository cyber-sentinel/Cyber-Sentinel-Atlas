# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-16

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Active implementation branch: `feature/phase-5.6-windows-desktop-mvp`
- Repository visibility: **Public**
- Release state: **First Preview candidate / not yet merged to release authority**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022 Accepted
- Content-pack trust model: TUF — ADR-0023 Accepted
- Production Shared Core: Go — ADR-0024 Accepted
- Desktop/Core boundary: child-process stdio protocol — ADR-0025 Accepted
- Desktop host: **Tauri 2.x** — ADR-0026 Accepted

`main` remains release authority. This document records verified feature-branch evidence without claiming merge or post-merge verification before those events occur.

## Completed foundation

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**
- Phase 5.6.0 — Desktop Environment/Core Boundary: **COMPLETE / VERIFIED**
- Phase 5.6.1 — Executable Desktop Candidate Builds: **COMPLETE / VERIFIED**
- Phase 5.6.2 — Hard Gates / Measurements / Desktop Selection: **COMPLETE / VERIFIED**
- Phase 5.6.3 — First Preview UI: **COMPLETE / VERIFIED ON FEATURE BRANCH**
- Phase 5.6.4 — Windows Packaging / Clean-Machine Smoke: **IN PROGRESS**

## Frozen Shared Core boundary

Phase 5.5 remains frozen. Desktop code consumes, but does not redefine:

- exactly seven canonical `AtlasRecord` families under `schemas/v1/`;
- deterministic exact-before-lexical SQLite/FTS5 search semantics;
- bounded catalog and graph behavior;
- TUF pack trust, trusted-time and highest-seen anti-rollback state;
- immutable generations, atomic activation and Last Known Good behavior;
- deterministic Atlas serialization/digest semantics;
- `atlas-core --serve-stdio`, protocol `atlas-core/1.0.0`;
- 4-byte unsigned big-endian framing + UTF-8 JSON;
- mandatory handshake, strict bounded parsing, method allowlists and protocol-only stdout;
- no default local HTTP/TCP/WebSocket listener or hidden network fallback.

## Phase 5.6.2 — Closed mandatory gates

Exact-head Candidate Evidence run `35090304056` at commit `c343ffd881dd7b6a420f04cea2ffb91c3ea8a715` completed successfully. The corresponding artifact `phase562-desktop-gate-evidence` records the following fail-closed state:

| Gate | Requirement | State |
| --- | --- | --- |
| G-D1 | Clean Windows build | **PASS / VERIFIED** |
| G-D2 | `atlas-core` stdio handshake/status | **PASS / VERIFIED** |
| G-D3 | Offline / no-default-listener behavior | **PASS / VERIFIED** |
| G-D4 | Deterministic sidecar location + integrity/version | **PASS / VERIFIED** |
| G-D5 | Active verified pack → search / record / graph / provenance | **PASS / VERIFIED** |
| G-D6 | Verified pack update + safe rollback | **PASS / VERIFIED** |
| G-D7 | Desktop security surface | **PASS / VERIFIED** |
| G-D8 | Installer + portable feasibility | **PASS / VERIFIED FOR FEASIBILITY** |
| G-D9 | Footprint / startup / IPC / process / memory measurements | **PASS / VERIFIED** |

The same run preserved the canonical schema v1 drift guard and used an identical exact-head Shared Core across all candidates.

### Measurement snapshot

For the selected-candidate review, the successful evidence snapshot recorded approximately:

- Tauri package: 28.1 MB;
- Tauri warm external launch median: 259 ms;
- Tauri median process-tree working set: 17.7 MB;
- no TCP listener observed;
- no UDP endpoint observed.

The common exact-head Shared Core IPC evidence separately measures handshake/status against the identical sidecar. Measurements are CI evidence, not universal performance guarantees for all hardware.

## ADR-0026 — Windows Desktop Host Selection

**ACCEPTED — Tauri 2.x**

The frozen weighted review is stored in `benchmarks/desktop/phase56/weighted-review.json`. All three candidates passed mandatory hard gates. Using the documented evidence-based review method, the recorded totals are:

- Tauri 2.x: `94.13`;
- .NET 10 / WPF: `88.09`;
- Electron: `82.66`.

ADR-0026 records the decision, rejected alternatives, evidence boundary and residual risks. Candidate comparison does not alter the Shared Core authority model.

## Phase 5.6.3 — First Preview UI

**COMPLETE / VERIFIED ON FEATURE BRANCH**

The selected Tauri host exposes exactly seven allowlisted application commands:

- `core_status`;
- `search_records`;
- `get_record`;
- `expand_graph`;
- `pack_status`;
- `pack_update`;
- `pack_rollback`.

The First Preview provides the analyst-critical flow:

- Offline Global Search;
- Canonical Record Detail;
- bounded Relationship / Graph navigation;
- claim/source provenance;
- verified pack status;
- pack update and safe rollback;
- diagnostics and failure visibility;
- UTC, system-local and Tehran/Jalali presentation without changing canonical UTC timestamps;
- dark operational UI with accessibility/high-contrast controls.

Security-surface regression evidence enforces one main-window capability, explicit application-command ACLs, CSP `connect-src 'none'`, no Tauri plugins, no generic frontend-controlled Shared Core method bridge and no generic application network API.

## Phase 5.6.4 — Windows Packaging / Smoke Closure

**IN PROGRESS**

Active exact-head workflow: `Phase 5.6.4 Windows First Preview Package`, run `35092036802`, feature HEAD `9b58be1a542d2d86a84ddfd14053a66be4162a1a`.

The gate builds one portable Windows First Preview package and consumes the same immutable artifact on a fresh GitHub-hosted Windows runner. Acceptance requires:

- exact package ZIP SHA-256 verification;
- exact host and `atlas-core.exe` manifest/hash/size verification;
- relocation to a path containing spaces;
- portable probe with `network_listener=false` and `offline_capable=true`;
- exact `core_commit` binding to the workflow SHA;
- deliberate sidecar corruption rejected fail-closed;
- recovery after restoration of verified sidecar bytes;
- WebView2 prerequisite audit without ATLAS downloading the runtime;
- GUI launch/liveness smoke;
- no TCP listener or UDP endpoint in the packaged GUI process tree.

The First Preview artifact is intentionally an **unsigned portable ZIP**. Production Authenticode signing, public distribution hardening and a broader release process remain later release-readiness boundaries; CI does not simulate a signature. Binary auto-update is disabled/not part of First Preview.

## First Preview readiness rule

`FIRST PREVIEW READY` may be claimed only after Phase 5.6.4 succeeds, the feature branch is reviewed through PR, merged into `main`, and required post-merge verification completes. Until then the correct state is **First Preview candidate**.

## Governance

Official changes remain branch → PR → CI → architecture/security review → exact-head verification → merge → post-merge verification. No mandatory gate is bypassed and no failed assertion is relaxed merely to obtain a green run.
