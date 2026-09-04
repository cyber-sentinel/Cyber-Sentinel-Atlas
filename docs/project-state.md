# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Phase 5.2 Working Branch: `architecture/phase-5.2-canonical-data-model`
- Phase 5.2 Pull Request: `#4 — Implement Phase 5.2 canonical data model`
- Current Product Version: `0.1.0-foundation.1`
- Canonical Schema Version Under Review: `1.0.0`
- Last Reviewed Main SHA: `47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Repository Visibility: Private during active development

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **IN PROGRESS — REVISION 2**

Architecture Authority requested remediation R-001 through R-012 on PR #4. Phase 5.2 remains non-authoritative on `main` until a second architecture review explicitly approves merge. Phase 5.3 is not started.

## Accepted Architecture

ADR-0001 through ADR-0010 remain unchanged. ADR-0011 through ADR-0015 remain the Phase 5.2 decision set and are updated only to record accepted Revision 2 invariants. Core principles remain offline-first, source-backed, vendor-neutral, analyst-first, exact-before-semantic, claim-level provenance, controlled releases, legacy preservation, universal architecture and narrow MVP.

## Phase 5.2 Revision 2 Remediation

- typed referential integrity and telemetry-spine endpoint typing;
- PRECEDES/FOLLOWS provenance requirement;
- extension registry enforcement across all record families;
- CoverageSnapshot `numerator_basis`;
- effective alias scope collision detection;
- native identifier primary/duplicate integrity;
- deterministic authoritative trust semantics;
- HTTPS-only canonical Source URLs;
- offset-aware datetime ordering;
- strict registry contract validation with independent registry versions;
- project-controlled canonical schema URI base;
- restoration of Product Foundation README context/navigation.

## MVP / Deferred Scope

MVP content remains Windows Security Events, Sysmon, PowerShell, Active Directory, MITRE ATT&CK, selected D3FEND/CAR, validated DefenseOps content, provenance and offline deterministic search. Linux/cloud/container/database records in Phase 5.2 are schema fixtures only. Production ingestion, Desktop/Web implementation, storage/search/graph selection, Detection IR, pack/signing/key-management design remain deferred/open.

## Open Implementation Decisions

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming/format
- Portable Windows packaging
- Exact DefenseOps → Atlas ingestion contract
- Code/pack signing and key-management implementation
- Exact deterministic/lexical search implementation

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Legacy / Migration Status

Phase 5.1 `schemas/atlas-node.schema.json` and `schemas/atlas-edge.schema.json` remain preserved. Explicit ID migration inventory is retained; Phase 5.1 `status=deprecated` is not auto-migrated.

## Architecture Sync

- Architecture Sync Status: **GREEN**
- Approved Phase 5.2 baseline: `main@47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Previous reviewed Phase 5.2 head: `10d222a01f320915a339e13dded572974b12e408`
- Architecture Review: **CHANGES REQUIRED — REMEDIATION IN PROGRESS**
- PR #4: OPEN / NOT MERGED
