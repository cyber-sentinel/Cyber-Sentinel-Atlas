# Cyber-Sentinel-Atlas Project State

## Repository

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Current Main SHA: `baaf72a8f7596f701bb49af6cad02460064e416f`
- Last Architecture-Reviewed Main SHA: `baaf72a8f7596f701bb49af6cad02460064e416f`
- Phase 5.2 Pull Request: `#4 — Implement Phase 5.2 canonical data model — MERGED`
- Phase 5.3.1: **COMPLETE / MERGED**
- Phase 5.3.2 Pull Request: `#6 — Phase 5.3.2 — MITRE ATT&CK deterministic ingestion canary — MERGED`
- Phase 5.3.2 Merge Commit: `baaf72a8f7596f701bb49af6cad02460064e416f`
- Phase 5.3.2 Post-Merge Main CI: **GREEN** — Foundation Hygiene run `33943405943`
- Current Version: `0.1.0-foundation.1`
- Canonical Schema Version: `1.0.0`
- Canonical Schema URI Base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/`
- Ingestion Contract Version: `1.0.0`
- Ingestion Schema URI Base: `https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/ingestion/v1/`
- Repository Visibility: Private during active development
- Branch Protection: unavailable/not enabled on the current private-repository plan; procedural PR + CI + architecture-review gates remain mandatory.

## Current Phase

- Phase 5.1 — Product Foundation: **COMPLETE**
- Stage 1 — Governance / Architecture Sync: **COMPLETE**
- Phase 5.2 — Canonical Data Model: **COMPLETE**
- Phase 5.3 — Source & Ingestion Core: **IN PROGRESS**
- Phase 5.3.1 — Ingestion Foundation / Contracts: **COMPLETE / MERGED**
- Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary: **COMPLETE / MERGED**
- Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline: **NOT STARTED / NEXT**
- Phase 5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates: **NOT STARTED**

Phase 5.2 canonical schema v1.0.0 remains authoritative and unchanged. Phase 5.3 uses a separate ingestion/control-plane schema stream. Phase 5.3 terminates at `PACK_READY`; signed content-pack runtime, archive format, installation and rollback remain Phase 5.5 concerns.

## Product Definition

Cyber-Sentinel-Atlas is a universal cybersecurity telemetry, detection, and threat knowledge platform implemented as:

- a Cyber Defense Knowledge Graph;
- an Analyst Workbench;
- an Offline Knowledge Platform;
- a Detection Engineering Platform.

Atlas is not an Event-ID-only wiki. Event ID is one native identifier type inside a universal telemetry model.

## Approved Core Principles

- Offline-first
- Source-backed
- Vendor-neutral
- Analyst-first
- Knowledge Graph based
- Exact identifier lookup before lexical/semantic retrieval
- Claim-level provenance
- No technical claim without source
- No AI answer without inspectable evidence
- No direct upstream-to-production content update
- Versioned content
- Signed/checksummed offline packs in Phase 5.5
- Rollback-safe updates
- Canonical identifiers distinct from native identifiers
- Legacy + Current telemetry preservation
- Old Event IDs are preserved
- Modern/Legacy relationships are explicit and evidence-backed
- Universal telemetry model, not Windows-only
- Event ID is not globally unique
- Content completeness is scope/version/denominator-bound
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

ADR-0001 through ADR-0015 remain authoritative for the Canonical Model. ADR-0016 through ADR-0020 define the Phase 5.3 ingestion/control-plane, deterministic transformation, inventory, promotion and Encyclopedia contracts without adding an eighth `AtlasRecord` family.

## Phase 5.3.1 — Ingestion Foundation

Phase 5.3.1 is complete and merged. It established:

- `schemas/ingestion/v1/` as the independent Ingestion Contract schema authority;
- SourceConnectorDefinition, AcquisitionRun and RawSnapshot contracts;
- ParserDefinition, ParserRun and ParsedSourceRecord/PSR contracts;
- NormalizerDefinition, NormalizationRun and NormalizationLineage contracts;
- AuthoritativeInventoryDefinition and three-layer InventoryDiff;
- BuildValidationReport for G1 through G15;
- digest-bound ReviewDecision and CanonicalBuildManifest;
- public-source fail-closed acquisition controls;
- parser/normalizer deterministic no-network/no-AI boundaries;
- cross-corpus source-snapshot resolution;
- candidate/review/diff digest binding;
- `PACK_READY` as the terminal successful Phase 5.3 boundary;
- sanitized deterministic fixtures and permanent validation tests.

The ingestion artifact corpus is not part of the `AtlasRecord` union. The seven Phase 5.2 canonical families remain unchanged.

## Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary

Phase 5.3.2 is complete and merged through PR #6.

Pinned source contract:

- official repository: `mitre-attack/attack-stix-data`;
- domain: Enterprise ATT&CK;
- release: `19.2`;
- upstream commit: `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`;
- bundle: `enterprise-attack/enterprise-attack-19.2.json`;
- full upstream bundle is acquired transiently for the live CI canary and is not committed to Atlas.

Delivered controls:

- SourceRecord + release pin + exact HTTPS connector;
- phase-aware exact-path authorization for real connector/parser/normalizer implementations;
- deterministic STIX 2.1 parser into PSR;
- deterministic ATT&CK normalizer and versioned mapping profile;
- unknown structured fields preserved-and-reported;
- identity ambiguity quarantined;
- lifecycle mapping for explicit ATT&CK revoked/deprecated flags; absence never means removal;
- Tier-A origin does not auto-promote unreviewed claims to `authoritative`;
- PSR `record_digest` and `parsed_record_id` conform exactly to the merged Phase 5.3.1 executable contract;
- live RawSnapshot ID conforms exactly to the merged Phase 5.3.1 identity contract;
- offline canary tests plus full pinned live-source CI canary;
- no canonical `schemas/v1` changes.

Phase 5.3.2 is an ingestion-framework canary, not a released content pack and not a claim of global ATT&CK completeness.

## Phase 5.3.3 — Next Acceptance Domain

Next authorized implementation target is the Windows Security + Sysmon Encyclopedia pipeline. The slice must preserve these boundaries:

- Windows authoritative documentation and provider inventory are independent source dimensions;
- completeness is declared only against an authoritative provider/channel/product-version/build denominator;
- missing documentation is not missing telemetry;
- Event ID alone is never global identity;
- exact native identifier lookup for values such as `4688`, scoped lookup such as `sysmon 1`, legacy telemetry such as `592`, and provider collisions must remain representable;
- legacy/current telemetry is preserved; `NOT_OBSERVED != REMOVED`;
- Atlas core never downloads or executes Windows/Sysmon binaries to generate provider inventory;
- controlled out-of-band reference-host exports may be ingested only as immutable, hashed, provenance-bearing artifacts;
- Sysmon canonical documentation source is Microsoft Sysinternals;
- Phase 5.3 prepares search-ready metadata; actual deterministic resolver/index remains Phase 5.4.

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

## Content Pack Status

Architecture requirement: versioned, schema-versioned, source-versioned, provenance-bearing, checksummed, signed, compatibility-aware, freshness-aware, coverage-aware, validation-aware, rollback-safe packs.

Phase 5.3 ends at `PACK_READY`; it does not implement the signed pack runtime. Exact final pack naming, archive format, signing implementation and key management remain **OPEN**.

No production content pack has been released or installed by Phase 5.3.2.

## Technology Decisions — Open

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming convention and format
- Portable Windows packaging implementation
- Exact DefenseOps → Atlas ingestion contract details for Phase 5.3.4
- Code signing / pack signing implementation and key management
- Exact search engine implementation
- Exact parser sandbox technology
- Secret-provider implementation
- Reviewer identity/workflow implementation
- Formal cross-language canonical serialization/hashing profile if required beyond the current deterministic Python contract

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No blocking architecture conflict is known.

Known implementation/security consideration: the Phase 5.3.2 CI downloader validates the exact official host, TLS, zero redirects, pinned commit resource, size and Git blob identity. A stronger address-pinned transport may be evaluated for the future generic acquisition engine to eliminate DNS-resolution TOCTOU/rebinding edge cases.

Any implementation issue requiring a change to accepted architecture must be raised as `ARCHITECTURE ISSUE` before changing the model.

## Data / Coverage Status

- Phase 5.2 schema v1.0.0: authoritative on `main`
- Phase 5.3 ingestion contract v1.0.0: authoritative on `main`
- Phase 5.3.2 ATT&CK structured-source canary: complete
- ATT&CK full source corpus: tested transiently in CI; not released as an Atlas content pack
- Windows/Sysmon authoritative production-like Encyclopedia corpus: not started
- Controlled registries for schema validation: implemented
- Telemetry Coverage snapshots: schema/fixture implemented; production measurements not started
- Detection Coverage snapshots: schema supported; production measurements not started
- Production Windows telemetry inventory: not ingested
- DefenseOps ingestion contract: Phase 5.3.4 / not started

Telemetry Coverage and Detection Coverage remain separate first-class measurements and must declare scope, version and denominator.

## Validation State

Phase 5.2 permanent validation source of truth:

- `tools/validate_phase52.py`
- `tests/test_phase52_model.py`
- `tests/test_phase52_invariants.py`

Phase 5.3 foundation validation:

- `tools/ingestion/validate_ingestion_foundation.py`
- `tools/ingestion/validate_ingestion_authorization.py`
- `tests/phase53/test_contracts.py`
- `tests/phase53/test_security_invariants.py`
- `tests/phase53/test_ingestion_authorization.py`

Phase 5.3.2 ATT&CK validation:

- `tools/ingestion/validate_attack_canary.py`
- `tools/ingestion/run_attack_live_canary.py`
- `tests/phase53/test_attack_canary.py`

Post-merge `main@baaf72a8f7596f701bb49af6cad02460064e416f` passed Foundation Hygiene run `33943405943`, including the full pinned live ATT&CK canary.

## Known Risks / Blockers

- Branch protection is not enabled on the current private repository; procedural PR/CI/architecture gates are mandatory.
- Exact storage/graph/search implementation remains intentionally open.
- Pack-signing/key-management design remains open.
- Parser sandbox technology remains open.
- Formal cross-language canonical JSON/hash standard remains open if later runtime languages require it; do not assume RFC 8785/JCS today.
- Windows/Sysmon production-like Encyclopedia ingestion has not started.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-05
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Stage 1: **APPROVED AND MERGED**
- Phase 5.2: **APPROVED AND MERGED**
- Phase 5.3 Architecture: **APPROVED**
- Phase 5.3.1: **COMPLETE / MERGED**
- Phase 5.3.2: **COMPLETE / MERGED**
- Phase 5.3.2 PR: `#6`
- Phase 5.3.2 Merge Commit: `baaf72a8f7596f701bb49af6cad02460064e416f`
- Phase 5.3.2 Post-Merge CI: **GREEN**
- Next Slice: **Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline**
