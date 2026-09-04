# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Phase 5.2 Working Branch: `architecture/phase-5.2-canonical-data-model`
- Current Product Version: `0.1.0-foundation.1`
- Canonical Schema Version Under Review: `1.0.0`
- Last Reviewed Main SHA: `47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Repository Visibility: Private during active development

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **IN PROGRESS — ARCHITECTURE REVIEW REQUIRED**

Phase 5.2 is authorized for implementation on the feature branch but is not authoritative on `main` until Architecture Authority approves and the PR is merged.

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

Existing accepted baseline:

- ADR-0001 — Canonical Vendor-Neutral Model
- ADR-0002 — Claim-Level Provenance
- ADR-0003 — Offline-first Core
- ADR-0004 — Ecosystem Ownership: Atlas, DefenseOps and Forge
- ADR-0005 — Canonical Identifier Architecture
- ADR-0006 — Shared Core and Interface Sequencing
- ADR-0007 — Universal Telemetry Taxonomy
- ADR-0008 — Coverage Measurement Model
- ADR-0009 — Controlled Content Release Pipeline
- ADR-0010 — Telemetry Lifecycle and Legacy Preservation

Phase 5.2 decisions implemented on this branch:

- ADR-0011 — Canonical Record Families and Record Envelope
- ADR-0012 — Native Identifiers, Aliases and Controlled Registries
- ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation
- ADR-0014 — Claim, Evidence and Relationship Contracts
- ADR-0015 — Schema Versioning, Migration and Referential Integrity

Full ADR content remains authoritative in `docs/adr/`.

## Phase 5.2 Canonical Model Status

Implemented for architecture review:

- AtlasRecord root union;
- EntityRecord;
- ClaimRecord;
- RelationshipRecord;
- SourceRecord;
- ValidationRecord;
- VersionRecord;
- CoverageSnapshot;
- shared strict definitions;
- controlled registries;
- canonical ID component validation;
- structured native identifiers;
- structured aliases;
- lifecycle/curation separation;
- applicability/version contracts;
- namespaced extensions;
- deterministic Claim/Relationship identity;
- source/provenance evidence contracts;
- referential integrity validation;
- Phase 5.1 migration inventory;
- cross-domain architecture fixtures;
- exact-resolution tests.

Phase 5.1 schemas remain preserved and are not the v1 production contracts.

## Current MVP Scope

Content focus remains intentionally narrow:

- Windows Security Events
- Sysmon
- PowerShell
- Active Directory
- MITRE ATT&CK
- selected D3FEND/CAR relationships where authoritative mappings are defensible
- validated DefenseOps detections and hunts
- provenance
- deterministic offline search

Phase 5.2 cross-domain records are schema fixtures only and do not authorize production ingestion.

## Deferred Scope

Production ingestion remains deferred for:

- Linux
- Azure / Entra ID
- AWS
- GCP
- Docker
- Kubernetes / OpenShift
- DevOps / CI-CD
- databases
- Exchange
- SharePoint
- Microsoft 365
- LOLBAS / GTFOBins expansion

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

Canonical SourceRecord URLs must be credential-free.

## Content Pack Status

No production content pack is implemented in Phase 5.2.

Pack naming, format, signing algorithm, key management, and dependency implementation remain open.

## Technology Decisions — Accepted

- JSON-compatible canonical domain contracts
- JSON Schema Draft 2020-12
- Canonical schema version independent from product/source/record versions
- Controlled registries outside monolithic vendor enums
- Strict canonical root records with explicit namespaced extensions
- Deterministic Claim and Relationship semantic identity
- Explicit referential integrity validation
- Phase 5.1 schema preservation during migration review

## Technology Decisions — Open

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming convention
- Portable Windows packaging implementation
- Exact DefenseOps → Atlas ingestion contract
- Code signing / pack signing implementation and key management
- Exact deterministic/lexical search implementation

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No blocking Architecture Issue is currently identified.

Any implementation dependency that would force vendor-specific root fields, identity collisions, loss of native identifier fidelity, broken provenance/legacy preservation, storage coupling, or broken referential integrity must be returned to Architecture Authority before resolution.

## Data / Coverage Status

- Phase 5.2 production schema contracts: implemented on feature branch for review
- Source registry contract: implemented; production source ingestion not started
- Telemetry Coverage contract: implemented; production coverage not measured
- Detection Coverage contract: implemented; production coverage not measured
- Production telemetry inventory: not ingested
- DefenseOps ingestion contract: open decision

## Known Risks / Blockers

- Phase 5.2 is not authoritative until reviewed/merged.
- Existing Phase 5.1 `status=deprecated` values require explicit migration review.
- Pack dependency boundaries are not finalized.
- Storage/graph/search implementation remains intentionally open.
- Pack signing/key management remains open.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-04
- Architecture Authority Decision: **PHASE 5.2 APPROVED TO START**
- Approved baseline: `main@47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Phase 5.2 Architecture Review: **REQUIRED BEFORE MERGE**
- Architecture Sync Status: **GREEN**
