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

ADR-0023, ADR-0024 and ADR-0025 remain authoritative. Phase 5.6 consumes this boundary but may not redefine it.

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

Status: **FEATURE-BRANCH IMPLEMENTATION COMPLETE / PR RELEASE CLOSURE ACTIVE**

The Windows-first MVP remains offline-first, evidence-first and bounded by the frozen Shared Core.

### Phase 5.6.0 — Desktop Environment / Core Boundary

Status: **COMPLETE / VERIFIED**

Proved Windows toolchains, production `atlas-core.exe`, protocol `1.0.0` handshake/status, offline-capable behavior, no default network listener and canonical schema preservation.

### Phase 5.6.1 — Executable Desktop Candidate Builds

Status: **COMPLETE / VERIFIED**

Tauri 2.x, Electron and .NET 10/WPF were built as executable hosts around the same verified Shared Core. Electron uses a committed `package-lock.json`; Tauri uses committed/hash-guarded `Cargo.lock` and `--locked` build/metadata operations.

### Phase 5.6.2 — Hard Gates, Measurements & ADR-0026

Status: **COMPLETE / VERIFIED FOR ACCEPTED SELECTION EVIDENCE**

Mandatory selection-gate state from frozen evidence:

- G-D1 Clean Windows build: **PASS / VERIFIED**
- G-D2 stdio handshake/status: **PASS / VERIFIED**
- G-D3 Offline / TCP / UDP process-tree network posture: **PASS / VERIFIED**
- G-D4 Sidecar location/integrity/version: **PASS / VERIFIED**
- G-D5 Active verified pack → canonical/search/graph/provenance: **PASS / VERIFIED**
- G-D6 Verified pack update + safe manual rollback: **PASS / VERIFIED**
- G-D7 Desktop security surface: **PASS / VERIFIED**
- G-D8 Installer + portable feasibility: **PASS / VERIFIED FOR FEASIBILITY**
- G-D9 Startup / IPC / process / memory / package measurements: **PASS / VERIFIED**

Accepted Candidate Evidence run `35090304056` completed successfully. The accepted weighted review is stored in `benchmarks/desktop/phase56/weighted-review.json`.

ADR-0026: **ACCEPTED — Tauri 2.x selected**.

The historical multi-candidate workflow remains a release regression gate. On PR implementation head `8feb39a62a1b480428b180ad68cf6ab88340f513`, run `35100673553` failed during the common external measurement harness because the **Electron process tree opened a UDP endpoint**. Candidate security validation and all three candidate builds/probes had passed before that point. This regression does not automatically rewrite ADR-0026, but it blocks PR merge until the endpoint is attributed and the regression contract is closed without bypassing network-posture policy.

### Phase 5.6.3 — First Preview UI

Status: **COMPLETE / VERIFIED ON FEATURE BRANCH**

Delivered:

- Offline Global Search;
- Canonical Record / Entity Detail;
- bounded relationship navigation and graph pivots;
- claim/source provenance;
- Windows Event / Sysmon investigation context available in the active pack;
- verified pack state;
- pack update and safe rollback;
- diagnostics/recovery visibility;
- UTC, system-local and Tehran/Jalali presentation;
- operational dark UI with accessibility/high-contrast controls.

The selected Tauri host exposes only the seven explicit First Preview application commands and retains CSP/no-plugin/no-generic-network/no-generic-method-bridge restrictions.

### Phase 5.6.4 — Windows Packaging / Smoke Closure

Status: **COMPLETE / VERIFIED ON FEATURE BRANCH**

Latest verified PR implementation-head run `35100673319` at `8feb39a62a1b480428b180ad68cf6ab88340f513` completed successfully. Earlier acceptance run `35095383694` remains supporting evidence for the same packaging boundary.

One byte-bound portable Windows package was built once and consumed unchanged on a fresh GitHub-hosted Windows runner. The clean-machine gate verified:

- package ZIP SHA-256;
- host and Shared Core identity/integrity/size;
- adjacent sidecar manifest;
- portable relocation to a path containing spaces;
- exact Shared Core commit binding;
- packaged offline/no-default-listener status probe;
- deliberate corrupted-sidecar rejection;
- recovery after verified-byte restoration;
- WebView2 prerequisite handling without ATLAS runtime bootstrap;
- GUI launch/liveness;
- zero TCP listeners in the application process tree;
- zero UDP endpoints owned by ATLAS or Shared Core;
- explicit attribution/evidence for WebView2-runtime UDP when present.

The First Preview deliverable is an **unsigned portable ZIP**. Authenticode signing and public distribution hardening are later release-readiness boundaries. Binary auto-update remains disabled/not part of First Preview.

**FIRST PREVIEW READY may only be claimed after every PR regression gate passes, PR #39 merges to `main`, and post-merge verification succeeds.**

### Phase 5.6 release closure

Status: **ACTIVE — BLOCKED ON FINAL PR REGRESSION CLOSURE**

```text
Feature implementation + selected-host package/smoke evidence   COMPLETE
       ↓
README + authoritative documentation sync                       COMPLETE
       ↓
PR #39 final regression CI                                      ACTIVE
       ↓
Electron UDP measurement attribution / regression closure       ACTIVE BLOCKER
       ↓
Merge to main                                                   PENDING
       ↓
Post-merge package verification                                 PENDING
       ↓
FIRST PREVIEW READY
```

The remediation rule is evidence-first: identify which Electron-descendant process owns the UDP endpoint and why; do not generically allow UDP and do not weaken the selected-host network policy merely to obtain a green run.

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

Status: **PLANNED**

Includes final security review, third-party licensing/redistribution closure, accessibility, contributor workflow, source freshness, production signing, public release packaging/documentation and launch criteria.

## Expansion After MVP

The architecture remains intended to expand beyond the Windows-first MVP to Linux/macOS, Microsoft 365/Exchange/SharePoint, Azure/Entra, AWS, Google Cloud, containers/Kubernetes/OpenShift, DevOps/CI-CD, SQL/NoSQL databases, LOLBAS/GTFOBins and broader DFIR/IR/deception content.

Architecture support does not imply First Preview ingestion or delivery of every domain.
