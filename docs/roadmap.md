# Cyber-Sentinel-Atlas Roadmap

This file is the current phase-level roadmap. Operational evidence and exact verified boundaries are maintained in [`docs/current-status.md`](current-status.md). Historical snapshots remain under `docs/history/`.

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

Status: **DEFERRED BEYOND FIRST PREVIEW**

Will reuse the same canonical model and shared contracts after the Windows critical path is complete.

## Phase 5.8 — Broader API Surfaces

Status: **DEFERRED BEYOND FIRST PREVIEW**

Broader read/search/graph/source/pack interfaces remain secondary to the Windows MVP. The official CLI command remains `atlas`.

## Phase 5.9 — Grounded AI

Status: **DEFERRED BEYOND FIRST PREVIEW**

Only after deterministic retrieval/provenance and First Preview are mature: cited explanations, investigation pivots and optional offline model support. AI never becomes canonical truth.

## Phase 5.10 — Public Preview Readiness

Status: **ACTIVE**

Phase 5.10 closes the release-engineering, legal/redistribution, accessibility and publication boundaries required to move from an engineering-ready First Preview to a controlled Public Preview.

### Phase 5.10.0 — Public Preview Readiness Baseline

Status: **ACTIVE**

Delivered or in progress:

- machine-readable readiness manifest at `docs/releases/phase-5.10-public-preview-readiness.json`;
- human-readable gate matrix at `docs/releases/phase-5.10-public-preview-readiness.md`;
- baseline validator plus separate strict `--release` mode;
- GitHub Actions readiness workflow;
- public-source/pre-preview security reporting policy alignment;
- explicit distinction between current control-plane `main` and the immutable First Preview package baseline.

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
| Source freshness / public-pack publication policy | **BLOCKED** |
| Release governance / launch criteria | **PARTIAL** |
| Supply-chain evidence | **PASS** |
| Trademark / attribution controls | **PASS** |

### Phase 5.10.1 — Licensing & Redistribution Closure

Status: **BLOCKED**

Requires an explicit first-party licensing decision plus exact third-party redistribution clearance for the public release payload. Automation will not choose a license on behalf of the project owner.

### Phase 5.10.2 — Production Signing & Artifact Attestation

Status: **BLOCKED**

Requires an accepted code-signing certificate/provider, certificate lifecycle, protected key custody (for example an accepted HSM/KMS model), signing workflow, verification policy and revocation/rotation procedure. No provider is selected by this roadmap.

### Phase 5.10.3 — Public Packaging & Distribution Hardening

Status: **BLOCKED**

Requires the signed installer or other approved distribution format, trusted publication channel, release metadata/checksums, rollback/recovery policy and public installation/update documentation.

### Phase 5.10.4 — Accessibility, Freshness & Launch Governance

Status: **PARTIAL**

Requires broader accessibility release review, source-freshness/public-pack acceptance policy, launch checklist, publication authority, incident/revocation process and explicit go/no-go criteria.

### Public Preview strict release gate

Status: **BLOCKED**

`PUBLIC PREVIEW READY` may be declared only when every mandatory machine-readable gate is `PASS` and strict release validation succeeds with concrete release evidence.

## Expansion After MVP

The architecture remains intended to expand beyond the Windows-first MVP to Linux/macOS, Microsoft 365/Exchange/SharePoint, Azure/Entra, AWS, Google Cloud, containers/Kubernetes/OpenShift, DevOps/CI-CD, SQL/NoSQL databases, LOLBAS/GTFOBins and broader DFIR/IR/deception content.

Architecture support does not imply First Preview or Public Preview ingestion/delivery of every domain.
