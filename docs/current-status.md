# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-16

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Active implementation branch: `feature/phase-5.6-windows-desktop-mvp`
- Repository visibility: **Public**
- Release state: **Pre-preview / unreleased**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022
- Content-pack trust model: TUF — ADR-0023
- Production Shared Core: Go — ADR-0024
- Desktop/Core boundary: child-process stdio protocol — ADR-0025
- Desktop framework: **not selected**; ADR-0026 remains blocked until all mandatory Phase 5.6.2 gates are closed.

Git history and the live `main` branch remain release authority. This document records the current implementation/evidence boundary on the active Phase 5.6 branch and distinguishes **implemented** from **verified** work.

## Completed foundation

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**
- Phase 5.6.0 — Desktop Environment/Core Boundary: **COMPLETE / VERIFIED**
- Phase 5.6.1 — Executable Desktop Candidate Builds: **COMPLETE / VERIFIED**

## Frozen Shared Core boundary

Phase 5.5 remains frozen for Phase 5.6 consumption. Desktop work may consume but may not redefine:

- exactly seven canonical `AtlasRecord` families under `schemas/v1/`;
- deterministic exact-before-lexical SQLite/FTS5 search semantics;
- bounded catalog and graph behavior;
- TUF-based pack trust, trusted-time and highest-seen anti-rollback state;
- immutable generations, atomic activation and Last Known Good behavior;
- the existing deterministic Atlas serialization/digest profile;
- `atlas-core --serve-stdio`, protocol `atlas-core/1.0.0`;
- 4-byte unsigned big-endian frame length + UTF-8 JSON;
- mandatory handshake, strict bounded parsing, method allowlists and protocol-only stdout;
- no default local HTTP/TCP/WebSocket listener or hidden network fallback.

## Phase 5.6 — Windows Desktop MVP

Status: **IN PROGRESS**

### 5.6.0 — Environment / Core Boundary

**COMPLETE / VERIFIED**

Windows toolchain, production `atlas-core.exe`, stdio handshake/status, offline posture and canonical schema preservation are verified.

### 5.6.1 — Executable Candidate Builds

**COMPLETE / VERIFIED**

The three candidate host families remain:

- Tauri 2.x;
- Electron;
- .NET 10 Windows Desktop / WPF.

All candidates consume the same production Shared Core sidecar. No candidate selection is implied by build success.

Dependency reproducibility is now explicit for both webview candidates: Electron consumes its committed `package-lock.json`; Tauri now carries a committed `Cargo.lock`, and Candidate CI requires the approved lock hash, uses `--locked` for build/metadata, and fails on lockfile mutation. Tauri dependency resolution is no longer generated inside Candidate CI.

### 5.6.2 — Mandatory Hard Gates, Measurements & Desktop Selection

**IN PROGRESS**

| Gate | Requirement | State |
| --- | --- | --- |
| G-D1 | Clean Windows build | **PASS** |
| G-D2 | `atlas-core` stdio handshake/status | **PASS** |
| G-D3 | Offline / no-default-listener behavior | **PASS / VERIFIED** |
| G-D4 | Deterministic sidecar location + integrity/version | **PASS** |
| G-D5 | Active verified pack → search / record / graph / provenance | **PASS / VERIFIED** |
| G-D6 | Verified pack update + safe manual rollback | **PASS / VERIFIED** |
| G-D7 | Desktop security surface | **IMPLEMENTED / CI PENDING** |
| G-D8 | Installer + portable feasibility | **IMPLEMENTED / CI PENDING** |
| G-D9 | Comparable startup / IPC / process / memory / package measurements | **PARTIAL — common harness captured** |

#### G-D3 evidence

Exact-head Candidate Builds run `35078440647` at commit `4e0a770e06cfacb195bfaf2ebb11a647aabc83e8` passed. The common external Windows harness probed the full process tree for Tauri, Electron and .NET/WPF and recorded:

- `tcp_listener_seen=false` for every candidate;
- `udp_endpoint_seen=false` for every candidate;
- no default network listener/endpoint observed during first-launch or measured samples.

G-D3 is therefore **CLOSED / VERIFIED**.

#### G-D5 evidence

The signed-pack Active Generation integration path is verified on Windows: verified pack installation can load canonical records, immutable search, graph runtime and generation identity into the production read model without inventing cross-artifact identity guarantees not present in the frozen contracts.

G-D5 is **CLOSED / VERIFIED**.

#### G-D6 evidence

Exact-head Windows run `35075820479` at commit `32874c7b95239579d6c11839a325dec0081d18f5` passed the real-process signed update/rollback path. The production `atlas-core.exe` process proves:

- fixed core-owned inbox update input;
- no caller-selected filesystem path or generation ID;
- TUF/trusted-time/highest-seen ownership remains in Shared Core;
- same-process hot reload after generation changes;
- signed update → status/search → manual rollback → status/search;
- highest-seen state is not rewound by rollback;
- untrusted-root update rejection leaves active generation and search usable;
- successfully consumed pending archives are removed without deleting a concurrently replaced pending file.

G-D6 is **CLOSED / VERIFIED**.

#### G-D7 implementation state

G-D7 is implemented as machine-enforced candidate-specific security-surface evidence. The validator enforces:

- Electron: context isolation, sandbox, `nodeIntegration=false`, navigation/window/webview denial, permission/download denial, constrained preload IPC and no generic renderer/main network API;
- Tauri: CSP with `connect-src 'none'`, explicit main-window capability, application-command ACL for only `core_status`, disabled asset protocol, no Tauri plugins and no generic Rust/frontend network API;
- .NET/WPF: native WPF, no browser bridge, no generic application network API, shell-disabled verified sidecar launch and no external runtime packages.

The security-surface implementation remains **UNVERIFIED** until the current Windows Candidate workflow completes successfully across all candidates and the fail-closed summary.

#### G-D8 implementation state

G-D8 portable/packaging feasibility is implemented as executable evidence rather than documentation-only assertions. The workflow:

- copies every staged candidate to a relocated directory whose path contains spaces;
- executes the real candidate probe from the relocated directory;
- verifies the adjacent `atlas-core.exe` against its SHA-256 manifest;
- requires `network_listener=false` and `offline_capable=true` in the relocated probe;
- records candidate runtime prerequisites, installer options, signing boundary and disabled binary auto-update posture;
- validates the resulting `packaging-feasibility.json` fail-closed.

The PowerShell portable probe collision with the reserved `$Host` automatic variable was corrected by renaming the local executable variable to `$hostPath` in commit `69daca1c5b3a96bda9f9debe4906b6424fd24a58`.

G-D8 feasibility does **not** prove final installer build/signing or clean-machine installer behavior. Those remain Phase 5.6.4 requirements. G-D8 remains **UNVERIFIED** until successful Windows Candidate CI covers the current implementation.

#### Tauri reproducibility closure

The previously open Tauri repository-level dependency-lock gap has been closed at implementation level:

- commit `792dddf2ac14dc814cbf0708c482141ae6701a9b` added the verified `Cargo.lock` recovered from successful candidate evidence;
- approved lock SHA-256: `dd2a97c412b0f7289f07ba16cfc28b4cca02ea9b7a5f5ed4d488b34977e37b3e`;
- commit `0a5c2f622846b576481887f8e97d12007661da37` removed in-job `cargo generate-lockfile`, requires the committed lock, uses `--locked`, and fails on lock drift/mutation.

This closes the identified dependency-resolution gap without selecting Tauri and remains subject to the active exact-head Windows Candidate run.

#### Active verification run

Current Candidate run: `35084472666` on branch snapshot `19242f0cabb27a606dc4ddc1603a381ea5a19342`.

At this status update the run is **IN PROGRESS**. Therefore G-D7 and G-D8 are intentionally not marked PASS/VERIFIED yet.

### 5.6.3 — First Preview UI

**PLANNED — blocked on 5.6.2 framework selection**

Preview-critical scope remains:

- Offline Global Search;
- Canonical Record Detail;
- Relationship Navigation / bounded graph pivots;
- claim/source provenance;
- Windows Event / Sysmon investigation context present in the pack;
- verified pack state/update;
- safe rollback / recovery visibility;
- UTC plus user-selected/system time display, with Tehran and Jalali presentation supported without changing canonical UTC timestamps.

Current visual direction: operational intelligence dark UI, dense analyst surfaces, user-selectable theme tokens, stable security-state colors, restrained Iranian identity on Home, and validated geographic assets rather than generated maps.

### 5.6.4 — Windows Packaging / Smoke Closure

**PLANNED**

First Preview may only be called ready after package/installer boundary, portable behavior, sidecar integrity packaging and clean-machine smoke tests are complete and verified.

## Immediate execution sequence

```text
G-D7 / G-D8  Exact-head Windows verification
       ↓
G-D9           Measurement closure
       ↓
ADR-0026       Select one eligible Windows host
       ↓
Phase 5.6.3    First Preview UI
       ↓
Phase 5.6.4    Packaging + Clean-Machine Smoke
```

## Governance

Official changes remain branch → PR → CI → architecture/security review → exact-head verification → merge → post-merge verification. No mandatory gate may be bypassed, and ADR-0026 must not select a framework before every required candidate gate is closed.
