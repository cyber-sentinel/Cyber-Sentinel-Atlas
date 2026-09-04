# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Phase 5.2 Source Branch: `architecture/phase-5.2-canonical-data-model` (retained after merge)
- Phase 5.2 Pull Request: `#4 — Implement Phase 5.2 canonical data model — MERGED`
- Phase 5.3.1 Feature Branch: `feature/phase-5.3.1-ingestion-foundation`
- Phase 5.3.1 Approved Baseline Main SHA: `095a33bc55bca92fff9d9004b91c82f64209529e`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version: `1.0.0`
- Canonical Schema URI Base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`
- Ingestion Contract Version: `1.0.0`
- Ingestion Schema URI Base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/ingestion/v1/`
- Last Reviewed Main SHA: `095a33bc55bca92fff9d9004b91c82f64209529e`
- Repository Visibility: Private during active development

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE**
- Phase 5.3 — Source & Ingestion Core: **IN PROGRESS**
- Phase 5.3.1 — Ingestion Foundation / Contracts: **IMPLEMENTATION COMPLETE — PENDING ARCHITECTURE REVIEW**
- Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary: **NOT STARTED**
- Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline: **NOT STARTED**
- Phase 5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates: **NOT STARTED**

Phase 5.2 schema v1.0.0 remains authoritative. Phase 5.3.1 adds a separate ingestion/control-plane schema stream and does not modify the Canonical Knowledge Model. Later Phase 5.3 slices require separate Architecture Authority authorization.

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
- [ADR-0016 — Source & Ingestion Control Plane Boundary](adr/0016-source-ingestion-control-plane-boundary.md)
- [ADR-0017 — Deterministic Acquisition, Parsing and Normalization](adr/0017-deterministic-acquisition-parsing-normalization.md)
- [ADR-0018 — Authoritative Inventory, Completeness and Change Safety](adr/0018-authoritative-inventory-completeness-change-safety.md)
- [ADR-0019 — Validation, Review and Pack-Ready Promotion](adr/0019-validation-review-pack-ready-promotion.md)
- [ADR-0020 — Encyclopedia Identifier Search/Browse Data Contract](adr/0020-encyclopedia-identifier-search-browse-data-contract.md)

ADR-0001 through ADR-0015 remain intact and authoritative for the foundation and Canonical Model. ADR-0016 through ADR-0020 define the accepted Phase 5.3 control-plane, deterministic transformation, inventory, promotion and Encyclopedia data-contract decisions without overriding the Canonical Model.

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

Phase 5.2 cross-domain records and Phase 5.3.1 ingestion records are sanitized architecture/test fixtures only. They are not production ingestion.

## Phase 5.3.1 Ingestion Foundation

The Phase 5.3.1 implementation establishes:

- `schemas/ingestion/v1/` as the independent ingestion-contract schema authority;
- SourceConnectorDefinition, AcquisitionRun and RawSnapshot contracts;
- ParserDefinition, ParserRun and ParsedSourceRecord/PSR contracts;
- NormalizerDefinition, NormalizationRun and NormalizationLineage contracts;
- AuthoritativeInventoryDefinition and three-layer InventoryDiff;
- BuildValidationReport for G1 through G15;
- digest-bound ReviewDecision and CanonicalBuildManifest;
- public-source fail-closed acquisition controls;
- parser/normalizer deterministic no-network/no-AI boundaries;
- cross-corpus source-snapshot resolution;
- exact candidate/review/diff digest binding;
- `PACK_READY` as the terminal successful Phase 5.3 boundary;
- synthetic, deterministic, non-secret fixtures;
- permanent validator `tools/ingestion/validate_ingestion_foundation.py`;
- permanent tests under `tests/phase53/`.

The ingestion artifact corpus is not part of the `AtlasRecord` union. The seven Phase 5.2 canonical families remain unchanged.

## Deferred Scope

The architecture must support future Linux, Azure, AWS, GCP, Docker, Kubernetes, DevOps/CI-CD, databases, Exchange, SharePoint, Microsoft 365, LOLBAS, GTFOBins, broader DFIR/IR, and additional detection backends.

Broad production content ingestion remains deferred. Phase 5.3.1 specifically does not authorize live ATT&CK, Windows, Sysmon, D3FEND, CAR or DefenseOps ingestion.

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

No production source registry is populated by Phase 5.3.1.

## Content Pack Status

Architecture requirement: versioned, schema-versioned, source-versioned, provenance-bearing, checksummed, signed, compatibility-aware, freshness-aware, coverage-aware, validation-aware, rollback-safe packs.

Phase 5.3 ends at `PACK_READY`; it does not implement the signed pack runtime. Exact final pack naming, archive format, signing implementation and key management remain **OPEN**.

No production content packs have been released or installed by Phase 5.3.1.

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
- Phase 5.3.1 ingestion contracts use an independent repository-controlled `/schemas/ingestion/v1/` path.
- Ingestion artifacts do not become canonical `AtlasRecord` records.
- Public ingestion is fail-closed and deterministic core transformation is network-free/AI-free.

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
- Exact parser sandbox technology
- Secret-provider implementation
- Reviewer identity/workflow implementation

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No blocking architecture conflict is known. Phase 5.3 architecture is approved and Slice 5.3.1 implementation is pending Architecture Authority PR review.

Any new implementation issue requiring a change to accepted architecture must be raised as `ARCHITECTURE ISSUE` before changing the model.

## Data / Coverage Status

- Phase 5.2 schema v1.0.0: authoritative on `main`
- Phase 5.3.1 ingestion contract v1.0.0: implementation complete on feature branch, pending review/merge
- Source registry production ingestion: not started
- Controlled registries for schema validation: implemented on `main`
- Telemetry Coverage snapshots: schema/fixture implemented; production measurements not started
- Detection Coverage snapshots: schema supported; production measurements not started
- Production telemetry inventory: not ingested
- Cross-domain Phase 5.2 fixtures: Windows, Sysmon, Linux, AWS, Azure, GCP, Kubernetes, Docker, MongoDB, MITRE
- Phase 5.3.1 fixtures: sanitized synthetic contract/search-readiness fixtures only
- DefenseOps ingestion contract: open decision / Phase 5.3.4 not started

Telemetry Coverage and Detection Coverage remain separate first-class measurements and must declare scope, version and denominator.

## Validation State

Phase 5.2 permanent validation source of truth:

- `tools/validate_phase52.py`
- `tests/test_phase52_model.py`
- `tests/test_phase52_invariants.py`

Phase 5.3.1 permanent validation source of truth:

- `tools/ingestion/validate_ingestion_foundation.py`
- `tests/phase53/test_contracts.py`
- `tests/phase53/test_security_invariants.py`

Phase 5.3.1 validation covers ingestion schema/URI authority, no-eighth-family protection, secrets/URI/SSRF/archive/Git controls, deterministic snapshot/PSR/lineage identities, mapping/registry/schema pinning, cross-corpus source-snapshot resolution, inventory guardrails, G1–G15 representation, review digest binding, PACK_READY promotion, Last Known Good preservation, numeric native-ID context preservation, legacy identity separation and fixture/repository hygiene.

## Known Risks / Blockers

- Phase 5.1 JSON schemas remain provisional/legacy foundation contracts and are preserved during migration review.
- Exact storage/graph/search implementation is intentionally open.
- Pack-signing/key-management design is open.
- Parser sandbox technology is open.
- Production ingestion has not started.
- Phase 5.3.2, 5.3.3 and 5.3.4 require separate Architecture Authority authorization.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-04
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Stage 1 Decision: **APPROVED AND MERGED**
- Stage 1 baseline remains represented by ADR-0001 through ADR-0010.
- Architecture Sync Status: **GREEN**
- Approved Phase 5.2 baseline: `main@47e3a2b70e337c477dbf395192cd9a4e84b6050a`
- Approved Phase 5.2 head: `99704f607f3a40bb783587e31c919eb86b29d9cd`
- Phase 5.2 Architecture Decision: **APPROVED AND MERGED**
- PR #4: **MERGED**
- Phase 5.2 merge commit: `89868a0bece363ba5d5a74d435880b4a1de03751`
- Phase 5.3 Architecture Decision: **APPROVED**
- Phase 5.3.1 Implementation Authorization Baseline: `main@095a33bc55bca92fff9d9004b91c82f64209529e`
- Phase 5.3.1 Status: **IMPLEMENTATION COMPLETE — PENDING ARCHITECTURE REVIEW**
