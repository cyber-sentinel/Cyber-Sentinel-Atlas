# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-16

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Authoritative main SHA: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- Phase 5.6 release vehicle: PR #39 — **MERGED**
- Repository visibility: **Public**
- Release state: **First Preview engineering readiness READY / public release Pre-preview / unreleased**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022 Accepted
- Content-pack trust model: TUF — ADR-0023 Accepted
- Production Shared Core implementation family: **Go**
- Production Shared Core: Go — ADR-0024 Accepted
- Desktop/Core boundary: child-process stdio protocol — ADR-0025 Accepted
- Desktop host: **Tauri 2.x** — ADR-0026 Accepted

`main` is the release authority. Phase 5.6 has completed implementation, PR regression closure, merge, and post-merge package/smoke verification. `FIRST PREVIEW READY` denotes engineering readiness only; no signed public binary/GA release is claimed.

## Phase state

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE / MERGED**
- Phase 5.3 — Source & Ingestion Core: **COMPLETE / MERGED**
- Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**
- Phase 5.5 — Offline Pack Runtime / Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**
- Phase 5.5.2 — Verified Pack Runtime: COMPLETE / MERGED / POST-MERGE VERIFIED
- Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024: COMPLETE / MERGED / POST-MERGE VERIFIED
- Phase 5.5.4 — Production Go Shared Core: COMPLETE / MERGED / POST-MERGE VERIFIED
- Phase 5.6.0 — Desktop Environment/Core Boundary: **COMPLETE / VERIFIED**
- Phase 5.6.1 — Executable Desktop Candidate Builds: **COMPLETE / VERIFIED**
- Phase 5.6.2 — Hard Gates / Measurements / Desktop Selection: **COMPLETE / VERIFIED**
- Phase 5.6.3 — First Preview UI: **COMPLETE / MERGED / VERIFIED**
- Phase 5.6.4 — Windows Packaging / Clean-Machine Smoke: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.6 — Windows Desktop MVP: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- First Preview engineering readiness: **READY**

The explicit Phase 5.5.2/5.5.3/5.5.4 lifecycle markers are retained because frozen architecture validators use them to prove lifecycle continuity across later phases.

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

## Phase 5.6.2 — Selection evidence

Accepted Candidate Evidence run `35090304056` established the frozen selection evidence and closed G-D1 through G-D9. Subsequent PR regression run `35112236628` on final PR head `bae4b2d87b5c227f6e332ffc3ca166d37b3fe4cd` completed successfully after fail-closed network-observation instrumentation was corrected without relaxing the network policy.

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

ADR-0026 is **ACCEPTED — Tauri 2.x**. Candidate comparison does not alter the Shared Core authority model.

## First Preview UI

The selected Tauri host exposes exactly seven allowlisted application commands:

- `core_status`;
- `search_records`;
- `get_record`;
- `expand_graph`;
- `pack_status`;
- `pack_update`;
- `pack_rollback`.

The First Preview provides Offline Global Search, Canonical Record Detail, bounded graph navigation, claim/source provenance, pack status/update/rollback, diagnostics, Windows Event/Sysmon-oriented investigation context present in the pack, UTC/system-local/Tehran-Jalali presentation, and operational dark/high-contrast UI controls.

Security regression evidence enforces one main-window capability, explicit application-command ACLs, CSP `connect-src 'none'`, no Tauri plugins, no generic frontend-controlled Shared Core method bridge and no generic application network API.

## Phase 5.6.4 — Release-authority evidence

Post-merge workflow `Phase 5.6.4 Windows First Preview Package`, run `35133827422`, completed **SUCCESS** on authoritative `main` SHA `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`.

Both jobs completed successfully:

- `build exact-head preview package`;
- `consume package on clean GitHub Windows`.

The same immutable package artifact was verified after relocation for package/payload integrity, exact Shared Core commit binding, offline probe behavior, sidecar-corruption fail-closed handling, recovery, WebView2 prerequisite handling, GUI liveness, and the accepted network-posture audit.

Artifacts:

- `phase564-first-preview-package` — ID `10462114843`, digest `sha256:57d9cce8a2ec85900bbc6b4fe250eefe53b43b241ddbefd2a9a1d9aafaee6f50`;
- `phase564-clean-windows-evidence` — ID `10463420685`, digest `sha256:456ea3aa6a7b2c84a555c2c1e60c8f31086781172ce53d530d677abd29f019d5`.

The First Preview artifact remains an **unsigned portable ZIP**. Production Authenticode signing, public distribution hardening, installer/release policy and binary auto-update are later release-readiness boundaries.

## Release-authority closure

```text
Feature implementation                         COMPLETE
        ↓
PR #39 regression CI                           COMPLETE / ALL GREEN
        ↓
Merge to main                                  COMPLETE
        ↓
Post-merge package + clean-Windows verification COMPLETE / VERIFIED
        ↓
FIRST PREVIEW READY — ENGINEERING READINESS
```

There is no open Phase 5.6 engineering blocker. Public release remains intentionally unreleased until the separate release-readiness boundaries are closed.

## Governance

Official changes remain branch → PR → CI → architecture/security review → exact-head verification → merge → post-merge verification. No mandatory gate was bypassed and no failed security assertion was relaxed merely to obtain a green run.
