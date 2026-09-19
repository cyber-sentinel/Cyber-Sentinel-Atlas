# Cyber-Sentinel-Atlas Roadmap

This file is the current phase-level roadmap. Operational evidence and exact verified boundaries are maintained in [`docs/current-status.md`](current-status.md). Historical snapshots remain under `docs/history/`.

## Approved Product Family

The approved delivery family is broader than the current Windows release surface and is governed by [`docs/product-surfaces.md`](product-surfaces.md):

```text
ATLAS
│
├── ATLAS Desktop
│    ├── Windows       ← current release-critical surface
│    ├── Linux
│    └── macOS
│
├── ATLAS CLI
│    ├── Windows
│    ├── Linux
│    └── macOS
│
├── ATLAS Web
│
├── ATLAS PWA
│    └── iOS Safari
│
├── ATLAS API
│
└── ATLAS Mobile
     ├── iOS
     └── Android
```

Approval of the family does not imply that every surface is released. All surfaces must reuse the canonical/provenance contracts and must not create an alternate source of truth.

## Phase 5.1 — Product Foundation

Status: **COMPLETE**

Delivered product vision, personas, knowledge-graph foundation, provenance-first design, offline-first principles, search/AI boundaries, API/CLI direction, security architecture, UX and initial MVP scope.

## Stage 1 — Governance / Architecture Sync

Status: **COMPLETE**

Delivered project-state control, ecosystem ownership boundaries, canonical identifiers, shared-core/interface sequencing, telemetry taxonomy, coverage architecture, controlled publication and lifecycle preservation.

## Phase 5.2 — Canonical Data Model

Status: **COMPLETE / MERGED**

Delivered canonical schema v1.0.0 with exactly seven `AtlasRecord` families, native identifiers, claims/evidence, relationships, lifecycle/applicability, source/version/validation/coverage contracts and deterministic validation.

## Phase 5.3 — Source & Ingestion Core

Status: **COMPLETE / MERGED**

Delivered acquisition, parsing, normalization, lineage, inventory/diff, validation, review and `PACK_READY` promotion across ATT&CK, Windows Security, Sysmon, D3FEND, CAR and the controlled DefenseOps boundary.

## Phase 5.4 — Deterministic Search Core

Status: **COMPLETE / MERGED**

Delivered exact/scoped/alias resolution, SQLite + FTS5 lexical retrieval, filters/catalogs, deterministic ordering, corruption/staleness handling and bounded graph pivots. ADR-0022 remains authoritative.

## Phase 5.5 — Offline Pack Runtime / Shared Core

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**

Delivered TUF-based signed content-pack trust, secure `.atlaspack` extraction/verification, offline operation, trusted-time/highest-seen rollback guards, immutable generations, atomic activation/LKG behavior, production Go Shared Core, canonical/search/graph read models, stdio protocol, conformance, reproducibility and supply-chain closure.

ADR-0023, ADR-0024 and ADR-0025 remain authoritative. Later phases consume this boundary but may not redefine it.

### Phase 5.5.2 — Verified Pack Runtime

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Delivered verified-pack extraction, trust validation, immutable generation installation, activation/LKG recovery, trusted-time and highest-seen anti-rollback behavior. This historical lifecycle marker remains explicit because later architecture validators consume it as a compatibility invariant.

### Phase 5.5.3 — Production Shared Core Technology Spike + ADR-0024

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Completed the evidence-based Shared Core technology selection. ADR-0024 selected Go as the production implementation family while preserving Python as semantic/conformance oracle and preserving frozen serialization, hashing and canonical contracts.

### Phase 5.5.4 — Production Go Shared Core

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Delivered the production Go Shared Core, canonical/search/graph operations, pack trust/durable state, bounded stdio protocol, conformance closure and supply-chain evidence. ADR-0025 defines the accepted local child-process stdio boundary.

## Phase 5.6 — Windows Desktop MVP

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

First Preview engineering readiness: **READY**. Public release state remains **Pre-preview / unreleased**.

The Windows-first MVP remains offline-first, evidence-first and bounded by the frozen Shared Core.

### Phase 5.6.0 — Desktop Environment / Core Boundary

Status: **COMPLETE / VERIFIED**

Proved Windows toolchains, production `atlas-core.exe`, protocol `1.0.0` handshake/status, offline-capable behavior, no default network listener and canonical schema preservation.

### Phase 5.6.1 — Executable Desktop Candidate Builds

Status: **COMPLETE / VERIFIED**

Tauri 2.x, Electron and .NET 10/WPF were built as executable hosts around the same verified Shared Core. Electron uses a committed `package-lock.json`; Tauri uses committed/hash-guarded `Cargo.lock` and `--locked` build/metadata operations.

### Phase 5.6.2 — Hard Gates, Measurements & ADR-0026

Status: **COMPLETE / VERIFIED**

G-D1 through G-D9 are **PASS / VERIFIED** in the frozen selection evidence. Accepted Candidate Evidence run `35090304056` established the selection boundary. Final PR regression run `35112236628` completed successfully without weakening the network-posture policy.

ADR-0026: **ACCEPTED — Tauri 2.x selected**.

Historical multi-candidate observations remain preserved as evidence. They do not redefine the accepted selected-host boundary.

### Phase 5.6.3 — First Preview UI

Status: **COMPLETE / MERGED / VERIFIED**

Delivered Offline Global Search, Canonical Record / Entity Detail, bounded relationship navigation and graph pivots, claim/source provenance, Windows Event / Sysmon investigation context available in the active pack, verified pack state/update/rollback, diagnostics/recovery visibility, UTC/system-local/Tehran-Jalali presentation, and operational dark UI with accessibility/high-contrast controls.

The selected Tauri host exposes only the seven explicit First Preview application commands and retains CSP/no-plugin/no-generic-network/no-generic-method-bridge restrictions.

### Phase 5.6.4 — Windows Packaging / Smoke Closure

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Release-authority workflow `Phase 5.6.4 Windows First Preview Package`, run `35133827422`, completed successfully on First Preview package baseline `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`.

The post-merge workflow built one byte-bound portable Windows package and consumed the same immutable artifact on clean GitHub-hosted Windows. It verified package/payload SHA-256 and size binding, exact Shared Core commit binding, relocation to a path containing spaces, offline/no-default-listener behavior, deliberate corrupted-sidecar rejection, recovery, WebView2 prerequisite handling without ATLAS runtime bootstrap, GUI liveness, zero TCP listeners, and zero UDP endpoints owned by ATLAS or Shared Core.

Post-merge artifacts:

- `phase564-first-preview-package` — artifact `10462114843`, digest `sha256:57d9cce8a2ec85900bbc6b4fe250eefe53b43b241ddbefd2a9a1d9aafaee6f50`;
- `phase564-clean-windows-evidence` — artifact `10463420685`, digest `sha256:456ea3aa6a7b2c84a555c2c1e60c8f31086781172ce53d530d677abd29f019d5`.

The First Preview deliverable is an **unsigned portable ZIP**. Authenticode signing, installer/public distribution hardening and binary auto-update are later release-readiness boundaries.

### Phase 5.6 release closure

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

```text
Feature implementation + selected-host package/smoke evidence   COMPLETE
       ↓
PR #39 final regression CI                                      COMPLETE / ALL GREEN
       ↓
Merge to main                                                   COMPLETE
       ↓
Post-merge package verification                                 COMPLETE / VERIFIED
       ↓
FIRST PREVIEW READY — ENGINEERING READINESS
       ↓
Public release                                                  PRE-PREVIEW / UNRELEASED
```

`FIRST PREVIEW READY` is an engineering-readiness milestone and must not be interpreted as a signed GA release, public binary release, or universal enterprise deployment approval.

## Phase 5.7 — Web / PWA

Status: **APPROVED / DEFERRED UNTIL WINDOWS PUBLIC PREVIEW CLOSURE**

Deliver ATLAS Web plus the approved installable **iOS Safari PWA** for iPhone/iPad. Desktop and Android use the normal Web surface and are not separate PWA deliverables in the current roadmap. The Web/PWA product must reuse the same canonical model, provenance semantics and bounded service contracts without exposing a generic Shared Core bridge.

## Phase 5.8 — CLI & Broader API Surfaces

Status: **APPROVED / DEFERRED UNTIL WINDOWS PUBLIC PREVIEW CLOSURE**

### Phase 5.8A — ATLAS CLI

Approved targets: Windows, Linux and macOS. The official command remains `atlas`.

The CLI will expose bounded product operations such as search, record retrieval, graph expansion, source inspection and pack status/verification while preserving the same canonical contracts and fail-closed trust model.

### Phase 5.8B — ATLAS Public API

Approved as a versioned, authenticated and auditable read/search/graph/source/pack service boundary. The API must not become a generic pass-through to arbitrary Shared Core methods.

## Phase 5.9 — Grounded AI

Status: **DEFERRED BEYOND FIRST PREVIEW**

Only after deterministic retrieval/provenance and First Preview are mature: cited explanations, investigation pivots and optional offline model support. AI never becomes canonical truth.

## Phase 5.10 — Public Preview Readiness

Status: **ACTIVE**

Phase 5.10 closes the release-engineering, legal/redistribution, accessibility and publication boundaries required to move from an engineering-ready First Preview to a controlled Public Preview.

### Phase 5.10.0 — Public Preview Readiness Baseline

Status: **COMPLETE / MERGED**

Delivered:

- machine-readable readiness manifest at `docs/releases/phase-5.10-public-preview-readiness.json`;
- human-readable gate matrix at `docs/releases/phase-5.10-public-preview-readiness.md`;
- baseline validator plus separate strict `--release` mode;
- GitHub Actions readiness workflow;
- public-source/pre-preview security reporting policy alignment;
- explicit distinction between the control-plane `main` and the immutable First Preview package baseline.

Current mandatory gate state:

| Gate | State |
| --- | --- |
| First Preview engineering baseline | **PASS** |
| Security disclosure / supported-release policy | **PASS** |
| First-party licensing decision | **BLOCKED** |
| Third-party redistribution closure | **BLOCKED** |
| Production code signing / key custody | **BLOCKED** |
| Public packaging / distribution hardening | **BLOCKED** |
| Accessibility release review | **PARTIAL** |
| Source freshness / public-pack publication policy | **PASS** |
| Release governance / launch criteria | **PASS** |
| Supply-chain evidence | **PASS** |
| Trademark / attribution controls | **PASS** |

### Phase 5.10.1 — Licensing & Redistribution Closure

Status: **CONTROL PLANE COMPLETE / RELEASE GATES BLOCKED**

Requires an explicit first-party licensing decision plus exact third-party redistribution clearance for the public release payload. Automation will not choose a license on behalf of the project owner.

PR #54 adds fail-closed Windows-target Rust/Tauri redistribution preflight: exact Rust `1.95.0`, immutable Cargo lock verification, reachable third-party license metadata/license-file checks, frontend asset SHA-256 inventory, and remote-reference rejection. Exact-head run `35309913398` passed with 258 third-party crates and 3 frontend assets; artifact `10533096533` (`sha256:ead00ebd410b7a5e715f1488847c7c066ec31dbed7196c1796c221f3dc75535d`). This narrows PPR-04 but does not close it; the frozen release payload, final NOTICE bundle and exact package binding remain mandatory.

### Phase 5.10.2 — Production Signing & Artifact Attestation

Status: **CONTROL PLANE COMPLETE / PROVIDER DECISION BLOCKED**

Requires an accepted code-signing certificate/provider, certificate lifecycle, protected key custody (for example an accepted HSM/KMS model), signing workflow, verification policy and revocation/rotation procedure. No provider is selected by this roadmap.

### Phase 5.10.3 — Public Packaging & Distribution Hardening

Status: **CONTROL PLANE COMPLETE / FORMAT + CHANNEL SELECTED / SIGNED-CANDIDATE EVIDENCE BLOCKED**

Initial Public Preview distribution is selected as a **signed portable ZIP** through **GitHub Releases**. Remaining work is exact production signing, exact-package metadata/checksums, rollback/recovery acceptance, clean-Windows verification, accessibility binding, publication, and independent post-publication byte verification.

### Phase 5.10.4 — Accessibility, Freshness & Launch Governance

Status: **CONTROL PLANE COMPLETE / PPR-07 PARTIAL**

Delivered policy/governance controls:

- **PPR-08 PASS:** `docs/releases/source-freshness-and-publication-policy.md` defines source classes, refresh objectives, maximum unattended age, fail-closed staleness handling, Last Known Good behavior, public-pack acceptance criteria and per-release evidence requirements;
- **PPR-09 PASS:** `docs/releases/public-preview-launch-governance.md` defines release authority, exact GO/NO-GO criteria, immutable release evidence, rollback/withdrawal and emergency security revocation;
- **PPR-07 PARTIAL:** `docs/releases/accessibility-release-review.md` defines the packaged-app acceptance contract for keyboard navigation, Narrator, focus, semantics, high contrast, scaling, text reflow, error handling and localization resilience.

Remaining work in this slice is executable accessibility review on the exact packaged Public Preview candidate. PPR-07 must not move to PASS based only on source inspection or documentation.

### Phase 5.10.5 — Usable Data Preview

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Purpose: close the product-usability gap where the Windows desktop shell and IPC were healthy but no verified knowledge pack was active, causing search to return `ATLAS_PACK_NOT_READY`.

Exact-head engineering evidence:

- branch: `phase-5.10.5-usable-data-preview`;
- verified head: `e5f76ef8f9bc8dad83b12387a7e7b9edfc6dd8a4`;
- workflow run `35253441607`: **SUCCESS**;
- `build exact-head usable data preview`: **PASS**;
- `clean Windows first-run Search Record Graph`: **PASS**;
- exact Windows Security Event ID `4688`: **PASS**;
- Sysmon Event ID `1`: **PASS**;
- Search → Record → Graph → Provenance: **PASS**;
- deliberate TUF target tampering: **REJECTED FAIL-CLOSED / PASS**.

Artifacts:

- `phase5105-usable-data-preview` — artifact `10512162655`, digest `sha256:65bc9987b9673c0c711e049813b8562b978f30192799f11397cff1113d450f62`;
- `phase5105-clean-windows-evidence` — artifact `10511033598`, digest `sha256:7c7569437f6139a27cee3743e1e0e426a64f03f0dc20044526165c3068bcc60e`.

Post-merge artifacts:

- `phase5105-usable-data-preview` — artifact `10530884223`, digest `sha256:174009a03ca99c5df83f3ab4489319f88ab9ff02a1c94343cecd066ac8b9f435`;
- `phase5105-clean-windows-evidence` — artifact `10532105635`, digest `sha256:efea2fd75a83f6300d7463217a7412c96324a5428e8eaf2ae08ac548039ee438`.

PR #45 is merged. After PR #49 hardened the checksum-pinned Windows dependency transport without weakening integrity checks, post-merge `Phase 5.10.5 Usable Data Preview` run `35305516189` succeeded on `main@4d64b2fb402b280d00c01783f7990538a3b67484`, including clean-Windows Search/Record/Graph/Provenance acceptance and fail-closed TUF target tamper rejection.

This slice does not change the Public Preview PPR matrix. Licensing, redistribution, signing, distribution and executable accessibility remain independent release controls.

### Phase 5.10.6 — Release Vehicle & Accessibility Hardening

Status: **COMPLETE / MERGED**

PR #56 selected the initial Public Preview release vehicle as a signed portable ZIP published through GitHub Releases, preserved binary auto-update as disabled, removed fixed-width/reflow blockers from the selected Tauri UI, and added fail-closed accessibility source preflight.

All applicable exact-head PR #56 workflows completed successfully before merge. Merge baseline: `main@2c7788e08e0254f330cca1cbb0d1a8a9432291f5`.

This slice does not close PPR-03 through PPR-07 by itself.

### Phase 5.10.7 — Public Preview RC Functional Freeze

Status: **ACTIVE / RC EVIDENCE BLOCKED**

Target: `v0.1.0-rc.1`.

The product feature/security boundary is now frozen for Release Candidate preparation. Canonical schema, Shared Core, IPC, command allowlist, deterministic search, bounded graph, TUF trust/rollback, offline/no-listener posture, Tauri host, signed portable ZIP distribution, GitHub Releases channel and disabled binary auto-update are frozen.

Visual identity is deliberately outside the functional freeze. Logo, banner imagery, geographic/satellite artwork, CSS design tokens, ATLAS Blue / Tactical Dark Green themes, typography, spacing and non-behavioral presentation polish may continue, subject to applicable desktop/accessibility regression.

Strict RC mode remains fail-closed until every mandatory PPR gate is PASS and the same exact signed package SHA is bound to corpus, notices, SBOM, release notes, clean-Windows acceptance and accessibility evidence.

Authoritative controls:

- `docs/releases/public-preview-rc-contract.md`;
- `docs/releases/public-preview-rc-readiness.json`;
- `tools/release/validate_public_preview_rc.py`;
- `.github/workflows/phase5107-public-preview-rc.yml`.

### Public Preview strict release gate

Status: **BLOCKED**

`PUBLIC PREVIEW READY` may be declared only when every mandatory machine-readable gate is `PASS` and strict release validation succeeds with concrete release evidence.

### Phase 5.10.10 — Windows & Sysmon Knowledge Coverage Expansion

Status: **ACTIVE / CONTROLLED COVERAGE EXPANSION**

The Engineering Usable Data Preview proved the product path. Phase 5.10.10 now expands that path into a measured, provenance-bound knowledge corpus.

Current controlled coverage state:

- Windows Security Auditing denominator is frozen to `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296`;
- Windows Security denominator: **423 unique Event IDs** / **488 provider event-version definitions**;
- Windows Security encyclopedia-grade numerator: **2/423** — Event IDs `4624` and `4688`;
- Windows Security remaining: **421**;
- Sysmon semantic release: **15.22**;
- Sysmon controlled structural schema: **4.91**;
- Sysmon documented/current denominator: **30** Event IDs (`1..29` plus `255`);
- Sysmon encyclopedia-grade numerator: **5/30** — Event IDs `1`, `2`, `3`, `4`, and `5`;
- Sysmon remaining: **25**;
- global Windows denominator: **NOT FROZEN**;
- global Windows completion percentage: **intentionally undefined**;
- Public Preview corpus authority: **NOT GRANTED**.

Authoritative machine-readable state:

- `content/encyclopedia/coverage-manifest.json`;
- `content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json`;
- `content/encyclopedia/sysmon-15.22-coverage.snapshot.json`.

The next corpus work is not a single "fill every Event ID" batch. It is a controlled sequence:

1. materialize remaining identities to the encyclopedia-grade content contract;
2. preserve exact source/version/provenance evidence;
3. validate fields, semantics, collection prerequisites, correlations and defensive interpretation;
4. project approved records into deterministic search and pack paths;
5. acceptance-test Search → Record → Graph → Provenance;
6. update deterministic coverage snapshots;
7. freeze provider/channel/version denominators for the remaining mandatory Windows families.

Mandatory families still without frozen denominators include PowerShell Operational, Windows Defender, AppLocker, WMI Activity, Task Scheduler Operational, RDP/Terminal Services, Windows Firewall/Filtering Platform, DNS, and Service/persistence telemetry.

ATLAS will not publish an unqualified "all Windows" percentage while those denominators remain undefined.

Authoritative coverage plan: [`docs/windows-sysmon-coverage-plan.md`](windows-sysmon-coverage-plan.md).

## Phase 5.11 — Cross-Platform Desktop

Status: **APPROVED / FUTURE DELIVERY**

Deliver Linux Desktop and macOS Desktop surfaces after the Windows Public Preview, coverage expansion and shared CLI/API contracts are stable. Platform packaging, signing, sandboxing and native accessibility requirements are separate release gates.

## Phase 5.12 — Native Mobile

Status: **APPROVED / FUTURE DELIVERY**

Deliver native iOS and Android applications after a dedicated mobile-core/library boundary is reviewed. Native mobile is distinct from PWA delivery. The Windows child-process sidecar model must not be copied blindly to mobile platforms.

Native iOS requires Apple signing/provisioning, privacy declarations, App Store packaging/review and platform-appropriate storage/runtime controls. Native Android requires its own application signing, permission, packaging and distribution controls.

## Expansion After MVP

Beyond the approved product surfaces, the content architecture remains intended to expand to Microsoft 365/Exchange/SharePoint, Azure/Entra, AWS, Google Cloud, containers/Kubernetes/OpenShift, DevOps/CI-CD, SQL/NoSQL databases, LOLBAS/GTFOBins and broader DFIR/IR/deception content.

Architecture support does not imply First Preview or Public Preview ingestion/delivery of every domain.
