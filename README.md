# Cyber-Sentinel-Atlas

**Provenance-First Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the **KNOW** layer of the Cyber-Sentinel ecosystem: an offline-first, analyst-first platform for connecting security telemetry, canonical records, adversary behavior, detections, hunts, DFIR artifacts, defensive context, investigation pivots and claim-level provenance into an inspectable knowledge system.

> **Development:** Active
> **Completed foundation:** Phases 5.1–5.5 COMPLETE / MERGED / VERIFIED
> **Windows Desktop:** Phase 5.6.0–5.6.4 COMPLETE / VERIFIED on the active feature branch
> **Desktop host:** Tauri 2.x — ADR-0026 Accepted
> **Hard gates:** G-D1 through G-D9 CLOSED / VERIFIED
> **Packaging gate:** Phase 5.6.4 exact-head package + clean-Windows smoke VERIFIED
> **Release state:** Pre-preview / unreleased — PR, merge and post-merge verification pending
> **Repository visibility:** Public

Foundation regression invariants: **Phase 5.1 — Product Foundation: COMPLETE**; **Stage 1 — Governance / Architecture Sync: COMPLETE**.

Public repository visibility does **not** imply public-release readiness. `main` remains release authority. `FIRST PREVIEW READY` is reserved for successful PR review, merge to `main`, and required post-merge verification.

Detailed implementation state is maintained in [Current Status](docs/current-status.md), [Project State](docs/project-state.md), and the [Roadmap](docs/roadmap.md).

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDR/XDR platforms, cloud environments, container runtimes, databases, vendor documentation, detection repositories, threat intelligence and incident-response references.

ATLAS connects those sources into deterministic, searchable investigation context while keeping technical claims bound to inspectable evidence.

**No technical claim without provenance.**

<p align="center">
  <img src="assets/satellite.png" alt="Cyber-Sentinel Atlas product thesis — telemetry, security knowledge, investigation, defensive action and provenance" width="100%" />
</p>

ATLAS is designed as a **Cyber Defense Knowledge Graph + Analyst Workbench + Offline Knowledge Platform**.

Within the Cyber-Sentinel ecosystem, ATLAS answers:

> **What do we know about what we are seeing?**

ATLAS is not an Event ID wiki, detection-rule dump, ATT&CK browser, SIEM-specific content portal or ungrounded AI chatbot. DefenseOps owns defensive engineering content; Skills owns reusable operating procedures. ATLAS owns governed knowledge, retrieval, provenance, relationships and investigation context.

## Current Architecture

<p align="center">
  <img src="assets/ATLAS-IR.png" alt="Cyber-Sentinel Atlas content pipeline and production architecture" width="100%" />
</p>

ATLAS is **offline-first**. Deterministic exact and lexical retrieval works without AI, and no UI, search index, upstream source or model response becomes canonical truth.

### Accepted architecture boundary

- **Canonical schema:** contract `1.0.0`, JSON Schema Draft 2020-12;
- **Canonical model:** exactly seven `AtlasRecord` families;
- **Search:** deterministic exact-before-lexical retrieval using SQLite + FTS5;
- **Content trust:** TUF-based verification, trusted-time and highest-seen rollback protection;
- **Pack runtime:** verified `.atlaspack`, immutable generations, durable state, health-gated activation and Last Known Good semantics;
- **Production Shared Core:** Go;
- **Conformance oracle:** Python;
- **Desktop host:** Tauri 2.x — ADR-0026;
- **Desktop/Core IPC:** `atlas-core --serve-stdio`, protocol `atlas-core/1.0.0`;
- **Framing:** bounded 4-byte unsigned big-endian length prefix + UTF-8 JSON;
- **Protocol behavior:** mandatory handshake, strict method allowlists, duplicate-key rejection and bounded payloads;
- **Network posture:** no default local HTTP/TCP/WebSocket listener and no hidden network fallback;
- **Official user-facing CLI command:** `atlas`.

The Desktop layer consumes Shared Core capabilities but does not duplicate or redefine canonical validation, search/graph semantics, TUF verification, durable trust state or rollback protection.

## Canonical Model

The authoritative schema contract remains **1.0.0** with exactly seven record families:

- `EntityRecord`
- `ClaimRecord`
- `RelationshipRecord`
- `SourceRecord`
- `ValidationRecord`
- `VersionRecord`
- `CoverageSnapshot`

Canonical schema URI base:

```text
https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/
```

The current `$id` / `$ref` namespace is part of the accepted v1 contract. Schema changes must be explicit and versioned; CI includes a canonical-schema drift guard.

## Source, Ingestion & Deterministic Search

```text
SourceRecord / source control
        ↓
SourceConnectorDefinition
        ↓
AcquisitionRun → RawSnapshot
        ↓
ParserRun → ParsedSourceRecord
        ↓
NormalizationRun + Lineage
        ↓
Canonical Candidate Corpus
        ↓
Inventory Diff → Validation → Human Review
        ↓
PACK_READY
```

`PACK_READY` is a validated promotion state; it is not equivalent to signed, installed or active content.

The deterministic search core provides exact identifier resolution before lexical retrieval, bounded ambiguity, deterministic ordering, catalog browsing, lifecycle-aware filters, bounded graph pivots, corruption/staleness checks and rebuildable derived indexes. Search artifacts never become canonical truth.

## Phase 5.5 — Verified Offline Packs & Shared Core

**COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN**

Delivered production capabilities include TUF content trust, secure `.atlaspack` extraction/verification, offline verification, exact artifact binding, trusted-time/highest-seen anti-rollback controls, immutable generations, atomic activation/LKG recovery, deterministic verified-pack building, production Go Shared Core, canonical/search/graph read models, durable pack trust state and bounded local stdio IPC.

Phase 5.5 is frozen. Desktop work consumes this boundary rather than redefining it.

## Phase 5.6 — Windows Desktop MVP

### 5.6.0 — Desktop Environment / Core Boundary

**COMPLETE / VERIFIED**

Windows toolchain, exact-head `atlas-core.exe`, stdio handshake/status, offline posture and no-default-listener behavior are verified.

### 5.6.1 — Executable Desktop Candidate Builds

**COMPLETE / VERIFIED**

Tauri 2.x, Electron and .NET 10/WPF were built and measured against the same production Shared Core. Electron uses committed `package-lock.json`; Tauri uses committed/hash-guarded `Cargo.lock` and locked build/metadata resolution.

### 5.6.2 — Hard Gates, Measurements & Desktop Selection

**COMPLETE / VERIFIED**

Exact-head Candidate Evidence run `35090304056` closed G-D1 through G-D9, including Windows build, bounded stdio, offline/no-listener posture, sidecar integrity, verified-pack read model/update/rollback, desktop security surface, portable feasibility and common startup/IPC/process/memory/package measurements.

| Gate | State |
| --- | --- |
| G-D1 Clean Windows build | **PASS / VERIFIED** |
| G-D2 Shared Core handshake/status | **PASS / VERIFIED** |
| G-D3 Offline/no-default-listener | **PASS / VERIFIED** |
| G-D4 Sidecar identity/integrity | **PASS / VERIFIED** |
| G-D5 Active verified pack read model | **PASS / VERIFIED** |
| G-D6 Verified update + safe rollback | **PASS / VERIFIED** |
| G-D7 Desktop security surface | **PASS / VERIFIED** |
| G-D8 Installer/portable feasibility | **PASS / VERIFIED FOR FEASIBILITY** |
| G-D9 Comparable measurements | **PASS / VERIFIED** |

The frozen weighted review is in `benchmarks/desktop/phase56/weighted-review.json`. ADR-0026 is accepted with **Tauri 2.x selected**.

### 5.6.3 — First Preview UI

**COMPLETE / VERIFIED ON FEATURE BRANCH**

The First Preview implements:

- Offline Global Search;
- Canonical Record / Entity Detail;
- bounded Relationship / Graph navigation;
- Claim / Source Provenance;
- Windows Event / Sysmon investigation context available in the pack;
- Verified Pack State;
- Pack Update;
- Safe Rollback / recovery visibility;
- diagnostics;
- UTC, system-local and Tehran/Jalali presentation;
- operational dark UI with accessibility/high-contrast controls.

The selected host exposes exactly seven application commands: `core_status`, `search_records`, `get_record`, `expand_graph`, `pack_status`, `pack_update`, and `pack_rollback`.

Security regression evidence enforces one main-window capability, explicit command ACLs, CSP `connect-src 'none'`, no Tauri plugins, no generic frontend-controlled Shared Core method bridge and no generic application network API.

### 5.6.4 — Windows Packaging / Clean-Machine Smoke

**COMPLETE / VERIFIED ON FEATURE BRANCH**

Exact-head workflow run `35095383694` at commit `2517ed5714dec2efc97db0df7789375c5aae50bb` completed successfully.

The workflow built one byte-bound portable Windows First Preview ZIP and consumed that same immutable artifact on a fresh GitHub-hosted Windows runner. Verified controls include:

- ZIP SHA-256 plus host/sidecar hash and size binding;
- exact Shared Core commit binding;
- relocation to a path containing spaces;
- packaged offline probe with `network_listener=false` and `offline_capable=true`;
- deliberate sidecar corruption rejected fail-closed;
- recovery after verified sidecar restoration;
- WebView2 prerequisite detection without ATLAS runtime download/bootstrap;
- GUI launch/liveness on clean Windows;
- zero TCP listeners in the packaged GUI process tree;
- zero UDP endpoints owned by ATLAS or Shared Core;
- runtime-owned WebView2 UDP, when present, explicitly attributed and recorded as evidence rather than silently ignored.

The First Preview artifact is intentionally an **unsigned portable ZIP**. Production Authenticode signing and public distribution hardening remain later release-readiness boundaries. Binary auto-update is not part of First Preview.

## Initial Product Domain

The initial usable domain is intentionally narrow:

- Windows Security Events;
- Sysmon;
- PowerShell;
- Active Directory;
- MITRE ATT&CK relationships;
- selected D3FEND/CAR relationships;
- DefenseOps validated detections and hunts;
- investigation pivots;
- official-source provenance;
- deterministic exact/lexical search;
- verified offline local datasets.

Architecture support for broader platforms does not imply initial ingestion or First Preview delivery for every domain.

## Cyber-Sentinel Ecosystem

ATLAS is the KNOW layer in the ecosystem operating loop:

<p align="center">
  <img src="assets/azadi-tower-atlas.png" alt="Cyber-Sentinel ecosystem operating loop — ATLAS KNOW, DefenseOps DEFEND, Skills APPLY, validate automate evolve" width="100%" />
</p>

```text
Cyber-Sentinel
├── ATLAS       — KNOW   → Connect • Search • Investigate • Explain
├── DefenseOps  — DEFEND → Detect • Hunt • Validate • Respond • Automate
└── Skills      — APPLY  → Execute • Review • Reuse • Govern
```

Controlled content flows between projects only through explicit provenance, validation, versioning and release boundaries.

## Release discipline

The feature branch has now closed the complete Phase 5.6 implementation and packaging/smoke gate. The remaining release-authority sequence is:

```text
Feature-branch evidence complete
        ↓
PR review + CI
        ↓
Merge to main
        ↓
Post-merge package verification
        ↓
FIRST PREVIEW READY
```

Until merge and post-merge verification complete, the correct state remains **First Preview candidate / pre-preview**.
