# Cyber-Sentinel-Atlas — Current Authoritative Status

Status timestamp: 2026-09-26

## Control plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- Current `main` HEAD: `02f37e7efa8733b75800d6ffd7e1401b3f3c3646` — PR #138 merged the exact-package-bound accessibility preflight rehearsal; exact-head workflows `35883251314` (Foundation Hygiene), `35883250911` (Phase 5.10.4 Accessibility Readiness), and `35883250815` (Phase 5.6.4 Windows First Preview Package) completed **SUCCESS**.
- Latest corpus baseline: `a12bb5bb5b8ec111ba4c6a76b818373a88e93b87` — PR #130 completed the frozen Sysmon 15.22 denominator; machine-readable Sysmon coverage remains `30/30` with `0` remaining.
- PR #85 exact-head: `804aab8b1e9618d71965d78983235dbd7e20e9bf` — Foundation Hygiene run `35429390496`, Phase 5.3.4 Canaries run `35429390498`, and Phase 5.10.5 Usable Data Preview run `35429390479`: **SUCCESS**.
- Post-merge verification on `main@4bfe222eb708347ea0769da400c40dbdaf289b69`: **SUCCESS** — Foundation Hygiene `35429857708`, Phase 5.3.4 Canaries `35429857964`, and Phase 5.10.5 Usable Data Preview `35429857712` all completed successfully.
- PR #89 exact-head `34225caf471b215717c3a8b1dcaa01799b01abd7`: all applicable checks completed successfully, including Foundation Hygiene `35437483777`, Phase 5.3.4 Canaries `35437483740`, Production Go Architecture `35437483746`, Shared Core Architecture `35437483749`, Governance Hygiene `35437483754`, Supply Chain Closure `35437483745`, Redistribution Closure `35437483753`, First-Party License Readiness `35437483751`, and Public Preview Readiness `35437483747`; merged as `4ea088e455462e66115d6887a472237171a96c94`.
- PR #90 exact-head `c679a5c2746d6a2c9ea2b56c981574263092d77c`: Foundation Hygiene `35437451820` and branch push run `35437441519` completed successfully; merged as `d0e51c51c3e6c89fcce15ea834156bed26afd043`.
- Post-merge verification on `main@d0e51c51c3e6c89fcce15ea834156bed26afd043`: **SUCCESS** — Foundation Hygiene `35438946399` and Phase 5.3.4 Canaries `35438946394` completed successfully.
- First Preview package release baseline SHA: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- Phase 5.6 release vehicle: PR #39 — **MERGED**
- Phase 5.6 documentation closure: PR #41 — **MERGED**
- Phase 5.10 readiness baseline: PR #42 — **MERGED**
- Phase 5.10 README sync: PR #43 — **MERGED**
- Phase 5.10.4 governance/freshness closure: PR #44 — **MERGED**
- Phase 5.10.1 Tauri/Rust redistribution preflight: PR #54 — **MERGED**; exact-head run `35309913398` — **SUCCESS**; artifact `10533096533` / `sha256:ead00ebd410b7a5e715f1488847c7c066ec31dbed7196c1796c221f3dc75535d`
- Phase 5.10.6 release vehicle/accessibility hardening: PR #56 — **MERGED**; merge baseline `2c7788e08e0254f330cca1cbb0d1a8a9432291f5`
- Phase 5.10.7 Public Preview RC functional freeze: PR #57 — **MERGED**; target `v0.1.0-rc.1`; visual identity remains intentionally open
- Phase 5.10.8 PPR-04 deterministic notice/package binding: PR #58 — **MERGED**
- Phase 5.10.10 Sysmon semantic documentation refresh to 15.22: PR #67 — **MERGED / CI GREEN**
- Phase 5.10.10 approved production exemplars (Windows 4624 + Sysmon 3): PR #70 — **MERGED / CI GREEN**
- Phase 5.10.10 bounded encyclopedia Record Detail + hidden Windows sidecar: PR #72 — **MERGED / ALL APPLICABLE CI GREEN**
- Phase 5.10.10 product-family / corpus / UX authoritative sync: PR #75 — **MERGED**
- Phase 5.10.10 controlled Sysmon 15.22 reference-host collection: PR #76 — **MERGED**
- Phase 5.10.10 Sysmon 15.22 coverage snapshot: PR #78 — **MERGED**
- Phase 5.10.10 Windows Event 4688 encyclopedia-grade promotion: PR #79 — **MERGED**
- Phase 5.10.3 exact package-binding hardening: PR #80 — **MERGED**
- Phase 5.10.10 validated Sysmon 15.22 schema-baseline promotion: PR #81 — **MERGED**
- Phase 5.10.10 Sysmon schema-evidence binding fix: PR #83 — **MERGED**
- Phase 5.10.10 Sysmon Event 1 encyclopedia promotion + coverage ledger freeze: PR #85 — **MERGED / EXACT-HEAD CI GREEN**; stacked PR #87 integrated before final verification
- Project control-plane and durable agent workflow synchronization: PR #89 — **MERGED / EXACT-HEAD CI GREEN / POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 2 encyclopedia promotion: PR #90 — **MERGED / EXACT-HEAD CI GREEN / POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 4 encyclopedia promotion: PR #92 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 5 encyclopedia promotion: PR #94 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 6 encyclopedia promotion: PR #97 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 7 encyclopedia promotion: PR #99 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**
- Phase 5.10.10 Sysmon Event 8 encyclopedia promotion: PR #100 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**
- Phase 5.10.10 Sysmon Event 9 encyclopedia promotion: PR #103 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**
- Phase 5.10.10 Sysmon Event 10 encyclopedia promotion: PR #104 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**
- Phase 5.10.10 Event 10 control-plane synchronization: PR #105 — **MERGED**
- Phase 5.10.10 Sysmon Event 11 encyclopedia promotion: PR #106 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 12 encyclopedia promotion: PR #107 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**
- Phase 5.10.10 Sysmon Event 13 encyclopedia promotion: PR #108 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**
- Phase 5.10.10 Event 13 README/control-plane synchronization: PR #109 — **MERGED / ALL APPLICABLE CI GREEN**
- Phase 5.10.10 Sysmon Event 14 encyclopedia promotion: PR #110 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head run `35527030910`, merged as `5736de53cca784bad76914b9c573e031bff7cf71`.
- Phase 5.10.10 Sysmon Event 15 encyclopedia promotion: PR #111 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head run `35529385005`, merged as `ee2272d613396adac694deef906d94393c35cf57`.
- Phase 5.10.10 Event 15 README/control-plane synchronization: PR #112 — **MERGED / ALL APPLICABLE CI GREEN**; merged as `c33081fd822d3d630e04370e43f4c61bbe3e5ac2`.
- Phase 5.10.10 Sysmon Event 16 encyclopedia promotion: PR #113 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35535507063`; merged as `281cf5b13fbab5886fae7deb28e733cdc7e02772`.
- Phase 5.10.10 Sysmon Event 17 encyclopedia promotion: PR #114 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35537194647`; merged as `49d388340c33ec2a3379b56f6168f02257042dd0`.
- Phase 5.10.10 Sysmon Event 18 encyclopedia promotion: PR #115 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35558657618`; merged as `3f3c24fece3c00f3a2f24907f261e60cce101067`.
- Phase 5.10.10 Sysmon Event 19 encyclopedia promotion: PR #116 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35558997836`; merged as `3bff0af742aa90faac22f38803e4174d6b2b42d5`.
- Phase 5.10.10 Sysmon Event 20 encyclopedia promotion: PR #117 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35565142034`; merged as `294671a9f208a36f046dec75a23d3323a87c42d0`.
- Phase 5.10.10 Event 20 README/control-plane synchronization: PR #118 — **MERGED / ALL APPLICABLE CI GREEN**; merged as `845f62c6ddd4b260c63ca76d6c3df9c7433355dd`.
- Phase 5.10.10 Sysmon Event 21 encyclopedia promotion: PR #119 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35566014744`; merged as `c831025afeb949393d228e413122d1969e7853db`.
- Phase 5.10.10 Sysmon Event 22 encyclopedia promotion: PR #120 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE POST-MERGE VERIFIED**; exact-head Foundation Hygiene `35566703978`; merged as `937018196d86839b97ca6284b91d13b02293d20d`.
- Phase 5.10.10 Sysmon Event 23 encyclopedia promotion: PR #121 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35586836916`; merged as `f6fe2e5f9592f6df6c0d2733e285ddcfa4c63d0e`.
- Phase 5.10.10 Sysmon Event 24 encyclopedia promotion: PR #122 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35587347608`; merged as `5bc1c1c86fef9e2565d3af8bd7127045223053b5`.
- Phase 5.10.10 Sysmon Event 25 encyclopedia promotion: PR #123 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35587872458`; merged as `a27cc1dfc39397e1f1fe435684fceb5eca1ee4c2`.
- Phase 5.10.10 Sysmon Event 26 encyclopedia promotion: PR #124 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35588454106`; merged as `203c36024ee973c39cd8265bce3688f520cfd44c`.
- Phase 5.10.10 Sysmon Event 27 encyclopedia promotion: PR #125 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35589941442`; merged as `169edea3596abf4218a1cb3d1bd6558ad90b2098`.
- Phase 5.10.10 Sysmon Event 28 encyclopedia promotion: PR #126 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN**; exact-head Foundation Hygiene `35590322289`; merged as `330085bfcf131668a337c0a8a7cf32ca8afe03ee`.
- Phase 5.10.10 Sysmon Event 29 preparation: PR #127 and PR #128 — **CLOSED / SUPERSEDED / NOT MERGED** after stale test-invariant defects were identified and corrected.
- Phase 5.10.10 Sysmon Event 29 encyclopedia promotion: PR #129 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / CORRECTED TEST INVARIANTS**; exact-head Foundation Hygiene `35591771151`; merged as `f62819285e0235eac2062470399a901a70eebb9d`.
- Phase 5.10.10 Sysmon Event 255 encyclopedia promotion and frozen-denominator completion: PR #130 — **MERGED / EXACT-HEAD FOUNDATION HYGIENE GREEN / MACHINE-READABLE 30/30 VERIFIED**; exact-head Foundation Hygiene `35749656509`; merged as `a12bb5bb5b8ec111ba4c6a76b818373a88e93b87`.
- Control-plane documentation synchronization after Sysmon denominator completion: PR #131 — **MERGED**.
- PPR-04 freeze-evidence hardening: PR #132 — **MERGED** as `6fb6912536bf1ad529759f0b0a5c8fb56a037057`.
- Exact Go license-material preservation: PR #133 — **MERGED** as `a96e21ae9cf5d16badf427a610b5e0cfeb51f602`.
- Tauri asset redistribution-evidence hardening: PR #134 — **MERGED** as `ded39093401082b55ff2202d1182b941131701f0`.
- Windows portable ZIP safety hardening: PR #135 — **MERGED** as `7439822cba548281d177b2e38c22ba1b9c254f22`.
- Phase 5.6.4 package ZIP-safety enforcement: PR #136 — **MERGED** as `f268e3a477c8034e5e0191e1be87759584f0d9f0`.
- Phase 5.6.4 clean-Windows evidence exact-package binding: PR #137 — **MERGED** as `ca6c0238004d199726a493af47c59baa321aa2bf`.
- Phase 5.6.4 exact-package-bound accessibility preflight rehearsal: PR #138 — **MERGED / EXACT-HEAD CI GREEN** as `02f37e7efa8733b75800d6ffd7e1401b3f3c3646`; manual PPR-07 review remains explicitly required and unclaimed.
- Approved product family: Desktop (Windows/Linux/macOS), CLI (Windows/Linux/macOS), Web, PWA (iOS Safari), API, Native Mobile (iOS/Android)
- Repository visibility: **Public**
- Release state: **First Preview engineering readiness READY / public release Pre-preview / unreleased**
- Active phase: **Phase 5.10 — Public Preview Readiness**
- Baseline slice: **Phase 5.10.0 — COMPLETE / MERGED**
- Phase 5.10.4 — Accessibility / Freshness / Launch Governance: **CONTROL PLANE COMPLETE / PPR-07 PARTIAL**
- Phase 5.10.5 — Usable Data Preview: **COMPLETE / MERGED / POST-MERGE VERIFIED**
- Phase 5.10.6 — Release Vehicle / Accessibility Hardening: **COMPLETE / MERGED**
- Phase 5.10.7 — Public Preview RC Functional Freeze: **ACTIVE / RC EVIDENCE BLOCKED**
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

Project continuity is now explicitly repository-backed. [`AGENTS.md`](../AGENTS.md) defines the contributor/agent execution contract, [`docs/operations/agent-engineering-operating-model.md`](operations/agent-engineering-operating-model.md) defines interim and future multi-agent execution, and [`docs/operations/session-handoff-guide.md`](operations/session-handoff-guide.md) defines the minimum durable handoff state. CI runners remain verification infrastructure rather than autonomous development nodes.

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
- Phase 5.7 — Web / PWA: **APPROVED / DEFERRED UNTIL WINDOWS PUBLIC PREVIEW CLOSURE**
- Phase 5.8 — CLI & Broader API surfaces: **APPROVED / DEFERRED UNTIL WINDOWS PUBLIC PREVIEW CLOSURE**
- Phase 5.9 — Grounded AI: **DEFERRED BEYOND FIRST PREVIEW**
- Phase 5.10 — Public Preview Readiness: **ACTIVE**
- Phase 5.10.0 — Public Preview Readiness Baseline: **COMPLETE / MERGED**
- Phase 5.10.1 — Licensing / Redistribution Closure: **CONTROL PLANE + TAURI/RUST PREFLIGHT COMPLETE / PPR-03 & PPR-04 BLOCKED**
  - exact Windows-target Rust/Tauri dependency-license preflight: **PASS** (`258` third-party crates)
  - packaged frontend source-asset inventory: **PASS** (`3` assets; SHA-256 evidence; remote-reference fail-closed check)
  - final frozen payload/NOTICE/package binding: **OPEN / BLOCKING**
- Phase 5.10.2 — Production Signing / Key Custody / Attestation: **BLOCKED**
- Phase 5.10.3 — Public Packaging / Distribution Hardening: **BLOCKED**
- Phase 5.10.4 — Accessibility / Freshness / Launch Governance: **IN PROGRESS**
  - source freshness / public-pack publication policy: **PASS / POLICY CLOSED**
  - release governance / launch / rollback / revocation criteria: **PASS / POLICY CLOSED**
  - packaged accessibility release review: **PARTIAL / EXECUTABLE REVIEW REQUIRED**
- Phase 5.10.5 — Usable Data Preview: **COMPLETE / MERGED / POST-MERGE VERIFIED**
  - exact Windows Security Event ID `4688` search: **PASS**
  - Sysmon Event ID `1` search: **PASS**
  - packaged Record / Graph / Provenance flow: **PASS**
  - TUF target tamper rejection: **PASS / FAIL-CLOSED**
  - exact-head workflow run `35253441607`: **SUCCESS**
- Phase 5.10.6 — Release Vehicle / Accessibility Hardening: **COMPLETE / MERGED**
  - signed portable ZIP: **SELECTED**
  - GitHub Releases canonical channel: **SELECTED**
  - accessibility static/reflow preflight: **PASS on PR #56 exact head**
- Phase 5.10.7 — Public Preview RC Functional Freeze: **MERGED / RC EVIDENCE BLOCKED**
  - target candidate: `v0.1.0-rc.1`
  - freeze merge baseline: `main@3b37694abcd29919f1cf0a30ed430a8975245411`
  - visual identity: **OPEN BY DESIGN** for logo/banner/theme/non-behavioral polish
- Phase 5.10.8 — PPR-04 Notice / Package Binding Automation: **COMPLETE / MERGED**
- Phase 5.10.10 — Windows & Sysmon Knowledge Coverage Expansion: **ACTIVE / CONTROLLED COVERAGE EXPANSION**
  - Windows Security Auditing denominator: **FROZEN** to `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296`
  - Windows Security denominator: `423` unique Event IDs / `488` provider event-version definitions
  - Windows Security encyclopedia-grade: `2/423` — Event IDs `4624`, `4688`; remaining `421`
  - Sysmon semantic release: `15.22`; controlled structural schema: `4.91`
  - Sysmon denominator: `30`; encyclopedia-grade: `30/30` — Event IDs `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9`, `10`, `11`, `12`, `13`, `14`, `15`, `16`, `17`, `18`, `19`, `20`, `21`, `22`, `23`, `24`, `25`, `26`, `27`, `28`, `29`, `255`; remaining `0`
  - machine-readable coverage authority: `content/encyclopedia/coverage-manifest.json`
  - global Windows denominator: **NOT FROZEN**
  - global Windows completion percentage: **intentionally undefined**
  - remaining mandatory families without frozen denominators: PowerShell Operational, Windows Defender, AppLocker, WMI Activity, Task Scheduler Operational, RDP/Terminal Services, Windows Firewall/Filtering Platform, DNS, Service/persistence telemetry
  - Public Preview corpus authority: **NOT GRANTED**

The explicit Phase 5.5.2/5.5.3/5.5.4 lifecycle markers are retained because frozen architecture validators use them to prove lifecycle continuity across later phases.

## Approved Product Family

Authoritative product-surface plan: [`docs/product-surfaces.md`](product-surfaces.md).

```text
ATLAS
├── Desktop: Windows / Linux / macOS
├── CLI: Windows / Linux / macOS
├── Web
├── PWA: iOS Safari
├── API
└── Mobile: iOS / Android
```

Only Windows Desktop is currently engineering-ready. The other surfaces are approved future deliverables and must preserve the canonical/provenance/trust boundaries.

Current knowledge-content truth is separately governed by [`docs/windows-sysmon-coverage-plan.md`](windows-sysmon-coverage-plan.md). The current Usable Data Preview is a verified engineering-fixture pack, not the complete Windows/Sysmon corpus.

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

Post-merge verification run `35305516189` succeeded on engineering baseline `main@4d64b2fb402b280d00c01783f7990538a3b67484`. Both `build exact-head usable data preview` and `clean Windows first-run Search Record Graph` passed. The post-merge package artifact is `phase5105-usable-data-preview` (artifact `10530884223`, digest `sha256:174009a03ca99c5df83f3ab4489319f88ab9ff02a1c94343cecd066ac8b9f435`) and the clean-Windows evidence is `phase5105-clean-windows-evidence` (artifact `10532105635`, digest `sha256:efea2fd75a83f6300d7463217a7412c96324a5428e8eaf2ae08ac548039ee438`).

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
Phase 5.10.6 release vehicle/accessibility        COMPLETE / MERGED
        ↓
Phase 5.10.7 v0.1.0-rc.1 functional freeze       ACTIVE / RC EVIDENCE BLOCKED
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
