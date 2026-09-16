# Cyber-Sentinel ATLAS

**Provenance-First Cyber Defense Knowledge & Investigation Platform — KNOW**

Cyber-Sentinel ATLAS is the **KNOW** layer of the Cyber-Sentinel ecosystem: an offline-first analyst workbench that connects security telemetry, canonical records, adversary behavior, detections, hunts, DFIR artifacts, defensive context and claim-level provenance into an inspectable investigation system.

> **Release state:** FIRST PREVIEW READY / POST-MERGE VERIFIED  
> **Windows Desktop:** Phase 5.6 COMPLETE / MERGED / VERIFIED  
> **Desktop host:** Tauri 2.x — ADR-0026 Accepted  
> **Shared Core:** Go — `atlas-core/1.0.0`  
> **Authoritative baseline:** `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`  
> **Packaging:** portable Windows x64 ZIP; production signing is deferred to Public Preview readiness  
> **Repository visibility:** Public

`main` is the release authority. The First Preview declaration follows PR #39 merge and successful post-merge Windows package/clean-machine verification.

<p align="center">
  <img src="assets/satellite.png" alt="Cyber-Sentinel ATLAS product thesis" width="100%" />
</p>

## Product Thesis

Cyber-defense knowledge is fragmented across operating systems, SIEM/EDR platforms, cloud environments, detection repositories, threat intelligence, vendor documentation and incident-response references. ATLAS connects those sources into deterministic, searchable investigation context while keeping technical claims bound to inspectable evidence.

**No technical claim without provenance.**

ATLAS answers:

> **What do we know about what we are seeing?**

ATLAS is not an Event ID wiki, rule dump, ATT&CK browser, SIEM-specific portal or ungrounded AI chatbot. DefenseOps owns defensive engineering; Skills owns reusable operating procedures; ATLAS owns governed knowledge, retrieval, provenance, relationships and investigation context.

## First Preview

The Windows First Preview implements:

- Offline Global Search
- Canonical Record / Entity Detail
- bounded Relationship / Graph navigation
- Claim / Source Provenance
- Windows Event / Sysmon investigation context available in the active pack
- Verified Pack State, Pack Update and Safe Rollback
- diagnostics and recovery visibility
- UTC, system-local and Tehran/Jalali presentation
- operational dark UI with accessibility/high-contrast controls

The selected desktop host exposes only seven explicit application commands: `core_status`, `search_records`, `get_record`, `expand_graph`, `pack_status`, `pack_update`, and `pack_rollback`.

## Security & Architecture Boundary

- canonical schema contract `1.0.0`, JSON Schema Draft 2020-12
- exactly seven canonical `AtlasRecord` families
- deterministic exact-before-lexical retrieval using SQLite + FTS5
- TUF-based content-pack trust with trusted-time and anti-rollback state
- verified `.atlaspack` runtime with immutable generations and Last Known Good behavior
- production Go Shared Core; Python retained as semantic/conformance oracle
- bounded child-process stdio IPC via `atlas-core --serve-stdio`
- no default local HTTP/TCP/WebSocket listener or hidden network fallback
- CSP `connect-src 'none'`
- no generic frontend-controlled Shared Core method bridge
- adjacent SHA-256-bound `atlas-core.exe`
- fail-closed sidecar integrity verification

## Phase Status

| Phase | State |
| --- | --- |
| 5.1 Product Foundation | COMPLETE |
| 5.2 Canonical Data Model | COMPLETE / MERGED |
| 5.3 Source & Ingestion Core | COMPLETE / MERGED |
| 5.4 Deterministic Search Core | COMPLETE / MERGED |
| 5.5 Offline Pack Runtime / Shared Core | COMPLETE / MERGED / POST-MERGE VERIFIED / FROZEN |
| 5.6 Windows Desktop MVP | **COMPLETE / MERGED / POST-MERGE VERIFIED** |
| 5.7 Web / PWA | Deferred beyond First Preview |
| 5.8 Broader API Surfaces | Deferred beyond First Preview |
| 5.9 Grounded AI | Deferred beyond First Preview |
| 5.10 Public Preview Readiness | Planned |

Phase 5.6 hard gates G-D1 through G-D9 are closed from accepted evidence. ADR-0026 selects Tauri 2.x. Post-merge `Phase 5.6.4 Windows First Preview Package` run `35133827422` completed successfully on the authoritative merge commit.

Detailed closure evidence is recorded in `docs/releases/phase-5.6-first-preview-closure.md`.

## Current Architecture

<p align="center">
  <img src="assets/ATLAS-IR.png" alt="Cyber-Sentinel ATLAS architecture" width="100%" />
</p>

ATLAS remains **offline-first, evidence-first and fail-closed**. Search indexes, UI state, upstream sources and future model responses never become canonical truth by themselves.

## Cyber-Sentinel Ecosystem

<p align="center">
  <img src="assets/azadi-tower-atlas.png" alt="Cyber-Sentinel ecosystem operating loop" width="100%" />
</p>

```text
Cyber-Sentinel
├── ATLAS       — KNOW   → Connect • Search • Investigate • Explain
├── DefenseOps  — DEFEND → Detect • Hunt • Validate • Respond • Automate
└── Skills      — APPLY  → Execute • Review • Reuse • Govern
```

Controlled content crosses product boundaries only through explicit provenance, validation, versioning and release contracts.

## Release Discipline

The First Preview is a verified engineering preview, not yet the final Public Preview. Production Authenticode signing, public installer/distribution hardening, third-party licensing/redistribution closure, broader accessibility review, contributor/release workflow hardening, source freshness and launch criteria remain Phase 5.10 work.

Future changes follow branch → PR → CI → review → exact-head verification → merge → post-merge verification. Frozen architecture and security gates are not weakened merely to obtain green CI.

---

**Maintainer:** Ali RahimDabagh  
**Ecosystem role:** KNOW  
**Focus:** Cyber Defense Knowledge • Investigation • Provenance • Offline Security Engineering
