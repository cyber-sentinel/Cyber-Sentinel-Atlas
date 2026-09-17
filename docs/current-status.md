# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-17

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Current control-plane main SHA: `a8f3b4e9177e89b38a1dcf91ad9ef2d31416bafe` at Phase 5.10.5 branch start; resolve live `main` after merge.
- First Preview package release baseline SHA: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- Phase 5.6 release vehicle: PR #39 — **MERGED**
- Phase 5.6 documentation closure: PR #41 — **MERGED**
- Phase 5.10 readiness baseline: PR #42 — **MERGED**
- Phase 5.10 README sync: PR #43 — **MERGED**
- Phase 5.10.4 governance/freshness closure: PR #44 — **MERGED**
- Repository visibility: **Public**
- Release state: **First Preview engineering readiness READY / public release Pre-preview / unreleased**
- Active phase: **Phase 5.10 — Public Preview Readiness**
- Baseline slice: **Phase 5.10.0 — COMPLETE / MERGED**
- Phase 5.10.4 — Accessibility / Freshness / Launch Governance: **IN PROGRESS**
- Phase 5.10.5 — Usable Data Preview: **COMPLETE / EXACT-HEAD VERIFIED — MERGE PENDING**
- Public Preview readiness: **BLOCKED**
- Canonical schema version: `1.0.0`
- Ingestion contract version: `1.0.0`
- Search contract version: `1.0.0`
- Search engine: SQLite + FTS5 — ADR-0022 Accepted
- Content-pack trust model: TUF — ADR-0023 Accepted
- Production Shared Core implementation family: **Go**
- Production Shared Core: Go — ADR-0024 Accepted
- Desktop/Core boundary: child-process stdio protocol — ADR-0025 Accepted
- Desktop host: **Tauri 2.x** — ADR-0026 Accepted

`main` is the release authority. Phase 5.6 completed implementation, regression closure, merge, post-merge package/smoke verification, and documentation closure. `FIRST PREVIEW READY` denotes engineering readiness only; no signed Public Preview or GA release is claimed.

The First Preview package evidence remains bound to `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`. Subsequent control-plane and release-governance work does not change those verified package bytes or the frozen Phase 5.5/5.6 architecture.

Phase 5.10.5 is a separate engineering usability/evidence slice. It proves that a clean packaged Windows flow can bootstrap a verified engineering knowledge pack, retrieve real Windows/Sysmon knowledge, navigate Record/Graph/Provenance, and reject deliberate signed-target tampering fail-closed. It does not grant Public Preview authority or change any PPR blocker.

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
- Phase 5.7 — Web / PWA: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.8 — Broader API surfaces: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.9 — Grounded AI: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.10 — Public Preview Readiness: **ACTIVE**
- Phase 5.10.0 — Public Preview Readiness Baseline: **COMPLETE / MERGED**
- Phase 5.10.1 — Licensing / Redistribution Closure: **BLOCKED**
- Phase 5.10.2 — Production Signing / Key Custody / Attestation: **BLOCKED**
- Phase 5.10.3 — Public Packaging / Distribution Hardening: **BLOCKED**
- Phase 5.10.4 — Accessibility / Freshness / Launch Governance: **IN PROGRESS**
  - source freshness / public-pack publication policy: **PASS / POLICY CLOSED**
  - release governance / launch / rollback / revocation criteria: **PASS / POLICY CLOSED**
  - packaged accessibility release review: **PARTIAL / EXECUTABLE REVIEW REQUIRED**
- Phase 5.10.5 — Usable Data Preview: **COMPLETE / EXACT-HEAD VERIFIED — MERGE PENDING**
  - exact Windows Security Event ID `4688` search: **PASS**
  - Sysmon Event ID `1` search: **PASS**
  - packaged Record / Graph / Provenance flow: **PASS**
  - TUF target tamper rejection: **PASS / FAIL-CLOSED**
  - exact-head workflow run `35253441607`: **SUCCESS**

The explicit Phase 5.5.2/5.5.3/5.5.4 lifecycle markers are retained because frozen architecture validators use them to prove lifecycle continuity across later phases.

## Frozen Shared Core boundary

Phase 5.5 remains frozen. Later release-readiness work consumes, but does not redefine:

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

Accepted Candidate Evidence run `35090304056` established the frozen selection evidence and closed G-D1 through G-D9. Final PR regression run `35112236628` on head `bae4b2d87b5c227f6e332ffc3ca166d37b3fe4cd` completed successfully after fail-closed network-observation instrumentation was corrected without relaxing the network policy.

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

Post-merge workflow `Phase 5.6.4 Windows First Preview Package`, run `35133827422`, completed **SUCCESS** on First Preview package baseline `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`.

Both jobs completed successfully:

- `build exact-head preview package`;
- `consume package on clean GitHub Windows`.

The same immutable package artifact was verified after relocation for package/payload integrity, exact Shared Core commit binding, offline probe behavior, sidecar-corruption fail-closed handling, recovery, WebView2 prerequisite handling, GUI liveness, and the accepted network-posture audit.

Artifacts:

- `phase564-first-preview-package` — ID `10462114843`, digest `sha256:57d9cce8a2ec85900bbc6b4fe250eefe53b43b241ddbefd2a9a1d9aafaee6f50`;
- `phase564-clean-windows-evidence` — ID `10463420685`, digest `sha256:456ea3aa6a7b2c84a555c2c1e60c8f31086781172ce53d530d677abd29f019d5`.

The First Preview artifact remains an **unsigned portable ZIP**. Production Authenticode signing, public distribution hardening, installer/release policy and binary auto-update remain later release-readiness boundaries.

## Phase 5.10.5 — Usable Data Preview evidence

The final engineering acceptance run before PR creation is `Phase 5.10.5 Usable Data Preview` run `35253441607` on exact head `e5f76ef8f9bc8dad83b12387a7e7b9edfc6dd8a4` — **SUCCESS**.

Both jobs passed:

- `build exact-head usable data preview`;
- `clean Windows first-run Search Record Graph`.

Clean-Windows evidence verifies from the packaged bytes:

- package relocation and all security-significant payload bindings;
- desktop host bootstrap and verified first-run engineering pack activation;
- exact Windows Security Event ID `4688` search;
- Sysmon Event ID `1` search;
- canonical Record resolution;
- bounded Graph expansion;
- claim/source Provenance;
- deliberate signed TUF target tampering rejected fail-closed.

Artifacts:

- `phase5105-usable-data-preview` — ID `10512162655`, digest `sha256:65bc9987b9673c0c711e049813b8562b978f30192799f11397cff1113d450f62`;
- `phase5105-clean-windows-evidence` — ID `10511033598`, digest `sha256:7c7569437f6139a27cee3743e1e0e426a64f03f0dc20044526165c3068bcc60e`.

The previous `ATLAS_PACK_NOT_READY` usability gap is therefore closed on the verified exact-head package path. This is not equivalent to Public Preview authority; the PPR gate matrix remains fail-closed.

## Phase 5.10 — Public Preview Readiness

Phase 5.10 is **ACTIVE**. The machine-readable authority is `docs/releases/phase-5.10-public-preview-readiness.json`; the human-readable gate matrix is `docs/releases/phase-5.10-public-preview-readiness.md`.

Current mandatory gate state:

- First Preview engineering baseline — **PASS**;
- security disclosure/supported-state policy — **PASS**;
- first-party licensing decision — **BLOCKED**;
- third-party redistribution closure — **BLOCKED**;
- production code signing/key custody — **BLOCKED**;
- public packaging/distribution hardening — **BLOCKED**;
- accessibility release review — **PARTIAL**;
- source freshness/public-pack publication policy — **PASS**;
- release governance/launch criteria — **PASS**;
- supply-chain evidence — **PASS**;
- trademark/attribution controls — **PASS**.

New release-readiness policy controls:

- `docs/releases/source-freshness-and-publication-policy.md` — source classes, refresh objectives, maximum unattended age, fail-closed publication and per-release freshness evidence;
- `docs/releases/public-preview-launch-governance.md` — exact release authority, GO/NO-GO criteria, immutable release evidence, rollback and emergency revocation;
- `docs/releases/accessibility-release-review.md` — packaged Windows review contract covering keyboard, Narrator, high contrast, scaling, semantics and security-significant failure states;
- `docs/releases/phase-5.10.5-usable-data-preview.md` — exact-head usable-data acceptance evidence and post-merge criteria.

The lack of a first-party `LICENSE` remains an explicit blocker. No license family is selected by automation or documentation. Production signing provider, certificate lifecycle and HSM/KMS/key-custody design likewise remain explicit owner/business/security decisions rather than inferred defaults.

## Release-authority sequence

```text
FIRST PREVIEW READY — ENGINEERING READINESS       COMPLETE
        ↓
Phase 5.10.0 readiness baseline                  COMPLETE / MERGED
        ↓
Phase 5.10.5 usable-data packaged acceptance     COMPLETE / EXACT-HEAD VERIFIED
        ↓
Phase 5.10.4 policy/governance closure           IN PROGRESS
        ├─ PPR-08 freshness/publication           PASS
        ├─ PPR-09 launch/rollback governance      PASS
        └─ PPR-07 packaged accessibility review   PARTIAL
        ↓
Licensing / redistribution closure               BLOCKED
        ↓
Signing / key custody / artifact attestation     BLOCKED
        ↓
Public packaging / distribution hardening        BLOCKED
        ↓
STRICT PUBLIC PREVIEW RELEASE GATE               BLOCKED
```

There is no open Phase 5.6 engineering blocker. Public release remains intentionally unreleased until every mandatory Phase 5.10 release-readiness gate passes.

## Governance

Official changes remain branch → PR → CI → architecture/security review → exact-head verification → merge → post-merge verification. No mandatory gate may be bypassed and no failed security assertion may be relaxed merely to obtain a green run.
