# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Current Version: `0.1.0-foundation.1`
- Last Reviewed Main SHA: `835204e2eb24fe2297ef0238a9cce41452eebd39`
- Repository Visibility: Private during active development

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **IN REVIEW**
- Phase 5.2 — Canonical Data Model: **NOT STARTED**

Phase 5.2 must not begin until the Stage 1 architecture/governance synchronization is reviewed and merged.

## Product Definition

Cyber-Sentinel-Atlas is a universal cybersecurity telemetry, detection, and threat knowledge platform implemented as:

- a Cyber Defense Knowledge Graph;
- an Analyst Workbench;
- an Offline Knowledge Platform;
- a Detection Engineering Platform.

Atlas is not an Event-ID-only wiki. Event ID is one identifier type inside a universal telemetry model.

## Approved Core Principles

- Offline-first
- Source-backed
- Vendor-neutral
- Analyst-first
- Knowledge Graph based
- Exact search before semantic search
- Claim-level provenance
- No technical claim without source
- No AI answer without inspectable evidence
- No direct upstream-to-production content update
- Versioned content
- Signed/checksummed offline packs
- Rollback-safe updates
- Canonical identifiers
- Legacy + Current telemetry preservation
- Old Event IDs are preserved
- Modern/Legacy relationships are explicit
- Universal telemetry model, not Windows-only
- Event ID is only one identifier type
- Content completeness must be measurable
- Telemetry Coverage and Detection Coverage are separate metrics
- Universal architecture with an intentionally narrow MVP

## Accepted ADRs

- [ADR-0001 — Canonical Vendor-Neutral Model](adr/0001-canonical-vendor-neutral-model.md)
- [ADR-0002 — Claim-Level Provenance](adr/0002-claim-level-provenance.md)
- [ADR-0003 — Offline-first Core](adr/0003-offline-first.md)

Stage 1 introduces ADR-0004 through ADR-0010 for review. Full ADR content remains authoritative in `docs/adr/`; this file only summarizes project state.

## Current MVP Scope

Content focus:

- Windows Security Events
- Sysmon
- PowerShell
- Active Directory
- MITRE ATT&CK
- selected D3FEND/CAR relationships where authoritative mappings are defensible
- validated DefenseOps detections and hunts
- provenance
- deterministic offline search

Product focus:

- canonical local dataset;
- exact identifier resolution;
- lexical search;
- relationship navigation;
- provenance visibility;
- signed and rollback-safe content packs;
- Windows Desktop as the first full end-user interface;
- Web/PWA afterward using the same shared contracts.

## Deferred Scope

The architecture must support future Linux, Azure, AWS, GCP, Docker, Kubernetes, DevOps/CI-CD, databases, Exchange, SharePoint, Microsoft 365, LOLBAS, GTFOBins, broader DFIR/IR, and additional detection backends.

Broad content ingestion for those domains is deferred beyond the current MVP unless separately approved.

## Current Interface Sequence

```text
Canonical Data Model
        ↓
Source / Ingestion Core
        ↓
Deterministic Search Core
        ↓
Offline Pack Runtime / Shared Core
        ↓
Windows Desktop MVP
        ↓
Web / PWA
        ↓
API / CLI
        ↓
Grounded AI
```

The user-facing CLI command is `atlas`.

## Canonical Source Policy

Authoritative sources take precedence over secondary/community references.

Canonical sources include:

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- MITRE ATT&CK: official MITRE ATT&CK sources
- MITRE D3FEND: official MITRE D3FEND sources
- MITRE CAR: official MITRE CAR sources
- Other products/projects: official vendor documentation or official project repository

UltimateWindowsSecurity and similar sources may be used for research/reference but do not override authoritative upstream sources.

## Content Pack Status

Architecture requirement: versioned, schema-versioned, source-versioned, provenance-bearing, checksummed, signed, compatibility-aware, freshness-aware, coverage-aware, validation-aware, rollback-safe packs.

Exact final pack naming is **OPEN**.

Candidate families include core, Windows, Sysmon, MITRE ATT&CK/D3FEND/CAR, Linux, cloud, container, DevOps, database, LOLBAS, GTFOBins, and DefenseOps-derived content.

No production content packs have been released yet.

## Technology Decisions — Accepted

- Canonical security model is vendor-neutral.
- Material claims use claim-level provenance.
- Offline operation is first-class.
- Shared canonical contracts must serve all interfaces.
- Windows Desktop is the first full end-user interface.
- Web/PWA follows the shared core/Desktop MVP.
- Official Atlas CLI command: `atlas`.
- DefenseOps is the approved defensive engineering source for Atlas.
- Cyber-Sentinel-Forge is retired as an independent Atlas architecture/product component.
- Historical Forge material must not be deleted automatically.

## Technology Decisions — Open

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming convention
- Portable Windows packaging implementation
- Exact DefenseOps → Atlas ingestion contract
- Code signing / pack signing implementation and key management
- Exact search engine implementation

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No unresolved Stage 1 architecture conflict is known after the 2026-09-03 Architecture Sync handoff.

Implementation questions that require new architectural choices must be raised as `ARCHITECTURE ISSUE` before changing the accepted model.

## Data / Coverage Status

- Phase 5.2 production schemas: not started
- Source registry implementation: not started
- Telemetry Coverage snapshots: not implemented
- Detection Coverage snapshots: not implemented
- Production telemetry inventory: not ingested
- DefenseOps ingestion contract: open decision

Telemetry Coverage and Detection Coverage are separate first-class measurements and must declare scope, version, and denominator.

## Known Risks / Blockers

- Current Phase 5.1 JSON schemas are provisional foundation schemas and must not be treated as the final Phase 5.2 model.
- Exact storage/graph/search implementation is intentionally open.
- Pack-signing/key-management design is open.
- Existing provisional canonical ID examples must be inventoried before Phase 5.2 migration.
- Stale merged branches must not be used as implementation baselines.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-03
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- GitHub Engineering baseline reviewed: `main@835204e2eb24fe2297ef0238a9cce41452eebd39`
- Sync scope: A-001 through A-003 and G-001 through G-006
