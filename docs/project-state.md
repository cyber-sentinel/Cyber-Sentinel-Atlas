# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Phase 5.2 Working Branch: `architecture/phase-5.2-canonical-data-model`
- Phase 5.2 Pull Request: `#4 — Implement Phase 5.2 canonical data model`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version Under Review: `1.0.0`
- Canonical Schema URI Base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`
- Last Reviewed Main SHA: `47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Repository Visibility: Private during active development

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **READY FOR ARCHITECTURE REVIEW — REVISION 2**
- Phase 5.3 — Source & Ingestion Core: **NOT STARTED**

Phase 5.2 remains non-authoritative on `main` until Architecture Authority explicitly approves PR #4 for merge. Phase 5.3 must not start before a separate authorization.

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
- [ADR-0004 — Ecosystem Ownership: Atlas, DefenseOps and Forge](adr/0004-ecosystem-ownership-atlas-defenseops-forge.md)
- [ADR-0005 — Canonical Identifier Architecture](adr/0005-canonical-identifier-architecture.md)
- [ADR-0006 — Shared Core and Interface Sequencing](adr/0006-shared-core-and-interface-sequencing.md)
- [ADR-0007 — Universal Telemetry Taxonomy](adr/0007-universal-telemetry-taxonomy.md)
- [ADR-0008 — Coverage Measurement Model](adr/0008-coverage-measurement-model.md)
- [ADR-0009 — Controlled Content Release Pipeline](adr/0009-controlled-content-release-pipeline.md)
- [ADR-0010 — Telemetry Lifecycle and Legacy Preservation](adr/0010-telemetry-lifecycle-and-legacy-preservation.md)
- [ADR-0011 — Canonical Record Families and Record Envelope](adr/0011-canonical-record-families-and-record-envelope.md)
- [ADR-0012 — Native Identifiers, Aliases and Controlled Registries](adr/0012-native-identifiers-aliases-and-controlled-registries.md)
- [ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation](adr/0013-applicability-versioning-and-curation-lifecycle-separation.md)
- [ADR-0014 — Claim, Evidence and Relationship Contracts](adr/0014-claim-evidence-and-relationship-contracts.md)
- [ADR-0015 — Schema Versioning, Migration and Referential Integrity](adr/0015-schema-versioning-migration-and-referential-integrity.md)

ADR-0001 through ADR-0010 remain unchanged. ADR-0011 through ADR-0015 define the accepted Phase 5.2 v1 architecture and review remediation invariants. Full ADR content remains authoritative in `docs/adr/`.

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

Phase 5.2 cross-domain records are sanitized schema/architecture fixtures only and are not production ingestion.

## Deferred Scope

The architecture must support future Linux, Azure, AWS, GCP, Docker, Kubernetes, DevOps/CI-CD, databases, Exchange, SharePoint, Microsoft 365, LOLBAS, GTFOBins, broader DFIR/IR, and additional detection backends.

Broad production content ingestion for those domains remains deferred beyond Phase 5.2 unless separately approved.

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

Exact final pack naming and implementation remain **OPEN**.

Candidate families include core, Windows, Sysmon, MITRE ATT&CK/D3FEND/CAR, Linux, cloud, container, DevOps, database, LOLBAS, GTFOBins, and DefenseOps-derived content.

No production content packs have been released or implemented in Phase 5.2.

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
- Phase 5.2 canonical records use JSON Schema Draft 2020-12.
- Schema v1 canonical URI base is the repository-controlled GitHub raw `/schemas/v1/` path.

## Technology Decisions — Open

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming convention and format
- Portable Windows packaging implementation
- Exact DefenseOps → Atlas ingestion contract
- Code signing / pack signing implementation and key management
- Exact search engine implementation

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No blocking architecture conflict is known. Architecture Authority remediation R-001 through R-012 and final consolidation are implemented on PR #4. Final Architecture Authority approval is pending.

Any new implementation issue requiring a change to accepted architecture must be raised as `ARCHITECTURE ISSUE` before changing the model.

## Data / Coverage Status

- Phase 5.2 schema v1.0.0: implemented on feature branch, pending final architecture approval
- Source registry production ingestion: not started
- Controlled registries for schema validation: implemented on feature branch
- Telemetry Coverage snapshots: schema/fixture implemented; production measurements not started
- Detection Coverage snapshots: schema supported; production measurements not started
- Production telemetry inventory: not ingested
- Cross-domain fixtures: Windows, Sysmon, Linux, AWS, Azure, GCP, Kubernetes, Docker, MongoDB, MITRE
- DefenseOps ingestion contract: open decision

Telemetry Coverage and Detection Coverage remain separate first-class measurements and must declare scope, version, and denominator.

## Phase 5.2 Validation State

Permanent validation source of truth:

- `tools/validate_phase52.py`

Permanent test suites:

- `tests/test_phase52_model.py`
- `tests/test_phase52_invariants.py`

Validation covers typed referential integrity, structural telemetry-spine typing, semantic relationship provenance, extensions, coverage numerator semantics, alias/native identifier integrity, authoritative trust, HTTPS source URLs, offset-aware time ordering, registry contracts, canonical schema URI policy, migration, legacy preservation, cross-domain fixtures, exact/native resolution, and vendor-neutral root constraints.

## Known Risks / Blockers

- Phase 5.2 remains unmerged and non-authoritative until final Architecture Authority approval.
- Phase 5.1 JSON schemas remain provisional/legacy foundation contracts and are preserved during migration review.
- Exact storage/graph/search implementation is intentionally open.
- Pack-signing/key-management design is open.
- Production ingestion has not started.
- Schema v1.0.0 must not be treated as released until PR #4 is approved and merged.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-04
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Stage 1 Decision: **APPROVED AND MERGED**
- Stage 1 baseline remains represented by ADR-0001 through ADR-0010.
- Architecture Sync Status: **GREEN**
- Approved Phase 5.2 baseline: `main@47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Previous reviewed Phase 5.2 head: `10d222a01f320915a339e13dded572974b12e408`
- Phase 5.2 Architecture Review: **PENDING FINAL ARCHITECTURE AUTHORITY APPROVAL**
- PR #4: **OPEN / NOT MERGED**
