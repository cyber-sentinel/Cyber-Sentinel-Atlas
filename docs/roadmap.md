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

ADR-0023, ADR-0024 and ADR-0025 remain authoritative. Phase 5.6 may integrate with this boundary but may not redefine it.

## Phase 5.6 — Windows Desktop MVP

Status: **IN PROGRESS**

First end-user Windows interface. The MVP remains Windows-first, offline-first, evidence-first and bounded by the frozen Shared Core.

### Phase 5.6.0 — Desktop Environment / Core Boundary

Status: **COMPLETE / VERIFIED**

Proved Windows toolchains, production `atlas-core.exe`, protocol `1.0.0` handshake/status, offline-capable behavior, no default network listener and canonical schema preservation.

### Phase 5.6.1 — Executable Desktop Candidate Builds

Status: **COMPLETE / VERIFIED**

Executable candidate hosts are available for:

- Tauri 2.x;
- Electron;
- .NET 10 Windows Desktop / WPF.

Each consumes the same verified production `atlas-core` sidecar and does not implement a parallel canonical/search/trust engine.

Dependency reproducibility is now explicit: Electron uses committed `package-lock.json`; Tauri uses a committed and SHA-256-guarded `Cargo.lock`, and Candidate CI builds/resolves metadata with `--locked` rather than regenerating dependency resolution.

### Phase 5.6.2 — Hard Gates, Measurements & ADR-0026

Status: **IN PROGRESS**

Mandatory gate state:

- G-D1 Clean Windows build: **PASS**
- G-D2 stdio handshake/status: **PASS**
- G-D3 Offline / TCP / UDP process-tree network posture: **PASS / VERIFIED**
- G-D4 Sidecar location/integrity/version: **PASS**
- G-D5 Active verified pack → canonical/search/graph/provenance: **PASS / VERIFIED**
- G-D6 Verified pack update + safe manual rollback: **PASS / VERIFIED**
- G-D7 Desktop security surface: **IMPLEMENTED / CI PENDING**
- G-D8 Installer + portable feasibility: **IMPLEMENTED / CI PENDING**
- G-D9 Startup / IPC / process / memory / package measurements and reproducibility closure: **PARTIAL**

G-D7 and G-D8 are now executable/machine-enforced gates rather than pending design work. G-D8 currently proves portable relocation feasibility and records packaging/signing prerequisites; it does not replace the real installer/signing/clean-machine work reserved for Phase 5.6.4.

Current execution sequence:

```text
G-D7 / G-D8  Exact-head Windows CI verification
       ↓
G-D9           Measurement closure
       ↓
ADR-0026       Accept one eligible Windows host
```

No Desktop framework may be selected before every mandatory gate is closed. Build success alone is not a selection signal.

### Phase 5.6.3 — First Preview UI

Status: **PLANNED — blocked on 5.6.2 selection**

Preview-critical surfaces:

- Offline Global Search;
- Canonical Record / Entity Detail;
- bounded relationship navigation and graph pivots;
- claim/source provenance;
- Windows Event / Sysmon investigation context available in the active pack;
- verified pack state;
- pack update;
- safe rollback and failure/recovery visibility;
- investigation time display in UTC plus system/user-selected time zone, with Tehran and Jalali presentation supported as UI formatting.

UX direction is an operational intelligence dark application rather than a promotional dashboard: dense technical surfaces, user-selectable theme tokens, stable security-state colors, restrained Iranian identity on Home, and validated geographic assets rather than generated maps.

### Phase 5.6.4 — Windows Packaging / Smoke Closure

Status: **PLANNED**

Deliver and verify:

- selected Windows package/installer boundary;
- sidecar identity/integrity packaging;
- portable-mode behavior;
- clean-machine launch;
- search, record/provenance and graph smoke paths;
- verified pack state/update;
- safe rollback;
- failure/recovery behavior.

**FIRST PREVIEW READY may only be claimed after this slice completes and verifies.**

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

Includes security review, third-party licensing/redistribution closure, accessibility, contributor workflow, source freshness, signed release process, public documentation and launch criteria.

## Expansion After MVP

The architecture remains intended to expand beyond the Windows-first MVP to Linux/macOS, Microsoft 365/Exchange/SharePoint, Azure/Entra, AWS, Google Cloud, containers/Kubernetes/OpenShift, DevOps/CI-CD, SQL/NoSQL databases, LOLBAS/GTFOBins and broader DFIR/IR/deception content.

Architecture support does not imply First Preview ingestion or delivery of every domain.
