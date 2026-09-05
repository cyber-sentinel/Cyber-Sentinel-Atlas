# Cyber-Sentinel-Atlas Project State

## Repository Control Plane

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Authoritative Branch: `main`
- Current Main SHA: `84d125c61051442c509a701c2d6bc6ffb85a9090`
- Last Reviewed Main SHA: `84d125c61051442c509a701c2d6bc6ffb85a9090`
- Last Architecture-Reviewed Main SHA: `84d125c61051442c509a701c2d6bc6ffb85a9090`
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
- Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline: **COMPLETE / MERGED**
- Phase 5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates: **NEXT**
- Phase 5.4 — Deterministic Search Core: **NOT STARTED**

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
- ADR-0011 — Canonical Record Families and Record Envelope
- ADR-0012 — Native Identifiers, Aliases and Controlled Registries
- ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation
- ADR-0014 — Claim, Evidence and Relationship Contracts
- ADR-0015 — Schema Versioning, Migration and Referential Integrity
- ADR-0016 — Source & Ingestion Control Plane Boundary
- ADR-0017 — Deterministic Acquisition, Parsing and Normalization
- ADR-0018 — Authoritative Inventory, Completeness and Change Safety
- ADR-0019 — Validation, Review and Pack-Ready Promotion
- ADR-0020 — Encyclopedia Identifier Search/Browse Data Contract

ADR-0001 through ADR-0015 remain authoritative for the Canonical Model. ADR-0016 through ADR-0020 define the Phase 5.3 ingestion/control-plane, deterministic transformation, inventory, promotion and Encyclopedia contracts without adding an eighth `AtlasRecord` family.

## Phase 5.3.1 — Ingestion Foundation

Status: **COMPLETE / MERGED**

Established:

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

Status: **COMPLETE / MERGED**

- Pull Request: `#6`
- Merge Commit: `baaf72a8f7596f701bb49af6cad02460064e416f`

Pinned source contract:

- official repository: `mitre-attack/attack-stix-data`;
- domain: Enterprise ATT&CK;
- release: `19.2`;
- upstream commit: `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`;
- full upstream bundle is acquired transiently for the live CI canary and is not committed to Atlas.

Delivered controls:

- SourceRecord + release pin + exact HTTPS connector;
- deterministic STIX 2.1 parser into PSR;
- deterministic ATT&CK normalizer and versioned mapping profile;
- unknown structured fields preserved-and-reported;
- identity ambiguity quarantined;
- lifecycle mapping for explicit ATT&CK revoked/deprecated flags; absence never means removal;
- Tier-A origin does not auto-promote unreviewed claims to `authoritative`;
- PSR `record_digest` and `parsed_record_id` conform to the Phase 5.3.1 executable contract;
- live RawSnapshot identity conforms to the Phase 5.3.1 identity contract;
- live-source CI canary;
- no canonical `schemas/v1` changes.

## Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline

Status: **COMPLETE / MERGED**

- Pull Request: `#8`
- Final Reviewed Head: `5cddae4e9a8343eee359cf114833ed0d93a23c1a`
- Reviewed Head CI: Foundation Hygiene run `33970038864` — **SUCCESS**
- Merge Commit: `84d125c61051442c509a701c2d6bc6ffb85a9090`
- Post-Merge Main CI: Foundation Hygiene run `33973584356` — **SUCCESS**

Delivered product-acceptance controls:

- controlled out-of-band `ReferenceExport` contract;
- Atlas core never downloads or executes Windows/Sysmon binaries to generate telemetry inventory;
- Windows documentation authority kept independent from provider inventory authority;
- Sysmon documentation authority kept independent from schema-export authority;
- official Microsoft Sysinternals Sysmon documentation source preserved as canonical Sysmon documentation source;
- real controlled Windows provider metadata export from Windows Server 2025 Datacenter 24H2 build `26100.33296`;
- Windows provider parser: 488 event/version definitions, 423 unique Event IDs;
- Event ID `4688` observed in that current provider scope;
- historical Event ID `592` not observed in that current build and therefore explicitly not removed or collapsed;
- real controlled Sysmon `15.21` schema export;
- 24 schema manifests, 587 parsed schema-event records, current schema `4.91`, 30 current Event IDs (`1`..`29`, `255`);
- historical Sysmon decimal `binaryversion` and hexadecimal Event IDs preserved losslessly in PSR;
- decimal/hex spelling cannot bypass duplicate numeric identity checks within a schema;
- deterministic Windows Provider and Sysmon Schema structural normalizers;
- structural normalizers create canonical Event identity shells and lineage but do not infer unsupported global lifecycle;
- documentation/provider/schema reconciliation with independent denominators;
- authoritative Windows and Sysmon telemetry inventory definitions for the declared real scopes;
- initial Raw / Parsed / Canonical InventoryDiff artifacts;
- production-like deterministic acceptance semantics for `atlas:event:microsoft.windows.security:4688`, independent legacy `atlas:event:microsoft.windows.security:592`, and `atlas:event:microsoft.sysmon:1`;
- exact Event ID remains provider/namespace scoped; bare numeric identifiers do not define global identity;
- `NOT_OBSERVED != REMOVED` enforced;
- canonical `schemas/v1` unchanged.

Reference-host provenance bindings retained from the reviewed real run:

Windows Security provider:

- provider: `Microsoft-Windows-Security-Auditing`;
- channel: `Security`;
- reference build: Windows Server 2025 Datacenter 24H2 `26100.33296`;
- raw artifact SHA-256: `sha256-06569f12a802f0d8a14ceeec23865520af23fa4f240c0421fff3117ccffd7d68`;
- PSR representation digest: `sha256-ef6bf952ef92518ce433f643a9666a50d7824c57b8ec6c5405475864845ac839`.

Sysmon:

- release: `15.21`;
- current schema: `4.91`;
- raw artifact SHA-256: `sha256-e77df2e8d893af1ce1fb3fe7560f2a94f2d0658e2c8f0ea34cd9dac1678fef46`;
- PSR representation digest: `sha256-c197671929ae30b6311b6d427a7c0f0248c6353944845ad87a977c8088347c22`.

Phase 5.3.3 validates a production-like Encyclopedia ingestion acceptance domain. It is not a signed content pack, does not implement search, and does not claim global Windows/Sysmon historical completeness.

## Phase 5.3.4 — Next Slice

Status: **NEXT / NOT YET MERGED**

Architecture baseline already approved for:

1. D3FEND official-source ingestion with strict snapshot/version/digest binding and fail-closed structural drift handling. The upstream D3FEND API is treated as change-prone/alpha; no floating source may silently modify canonical output.
2. MITRE CAR official structured repository ingestion, preferring structured YAML and explicit commit/release pinning.
3. DefenseOps explicit validated export contract. DefenseOps is an approved engineering source but its origin alone never makes content authoritative.
4. Final Phase 5.3 validation/review/promotion scenarios through G1–G15 and immutable `PACK_READY` promotion semantics.
5. Last Known Good preservation on FAILED / QUARANTINED / REJECTED paths.
6. Detection IR remains outside Phase 5.3 and open.

Minimum DefenseOps export metadata contract must include, as applicable:

- repository/commit SHA;
- content ID and content type;
- native backend / format;
- source/provenance references;
- validation/review status;
- applicability;
- telemetry requirements;
- licensing metadata.

## Search / Encyclopedia Boundary

Phase 5.3 preserves data required for Phase 5.4 but does not implement the search engine.

Required Phase 5.4 behavior remains:

- exact native identifier lookup first;
- bare numeric identifiers resolve within provider/namespace context and disambiguate collisions;
- scoped identifiers such as `sysmon 1` are first-class;
- legacy/retired telemetry remains searchable;
- numeric Event ID browse uses numeric ordering only where the identifier registry defines numeric semantics;
- documentation completeness remains independent from telemetry inventory completeness;
- user-facing search does not require knowledge of canonical IDs.

## Content Pack Status

Architecture requirement: versioned, schema-versioned, source-versioned, provenance-bearing, checksummed, signed, compatibility-aware, freshness-aware, coverage-aware, validation-aware, rollback-safe packs.

Phase 5.3 ends at `PACK_READY`; it does not implement the signed pack runtime. Exact final pack naming, archive format, signing implementation and key management remain **OPEN**.

No production content pack has been released or installed.

## Technology Decisions — Open

- Windows Desktop implementation stack
- Embedded local database/storage engine
- Graph persistence/index implementation
- Detection Intermediate Representation
- Exact content-pack naming convention and format
- Portable Windows packaging implementation
- Exact final DefenseOps → Atlas export implementation details within the approved Phase 5.3.4 contract
- Code signing / pack signing implementation and key management
- Exact search engine implementation
- Exact parser sandbox technology
- Secret-provider implementation
- Reviewer identity/workflow implementation
- Formal cross-language canonical serialization/hashing profile if required beyond the current deterministic Python contract

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

## Active Architecture Issues

No blocking architecture conflict is known at the completion of Phase 5.3.3.

Known implementation/security consideration: the acquisition implementation validates official hosts, TLS, redirect policy, pinned resources, size and content identity. A stronger address-pinned transport may be evaluated for the future generic acquisition engine to eliminate DNS-resolution TOCTOU/rebinding edge cases.

Any implementation issue requiring a change to accepted architecture must be raised as `ARCHITECTURE ISSUE` before changing the model.

## Data / Coverage Status

- Phase 5.2 schema v1.0.0: authoritative on `main`
- Phase 5.3 ingestion contract v1.0.0: authoritative on `main`
- ATT&CK structured-source canary: complete
- Windows/Sysmon product-acceptance ingestion pipeline: complete
- Windows current provider denominator for the declared reference scope: 423 unique Event IDs
- Sysmon current schema denominator for the declared 15.21 / schema 4.91 scope: 30 Event IDs
- Documentation Coverage and Telemetry Coverage remain independent
- Production Detection Coverage measurements: not started
- D3FEND/CAR ingestion: Phase 5.3.4 / next
- DefenseOps ingestion contract implementation: Phase 5.3.4 / next

Telemetry Coverage and Detection Coverage remain separate first-class measurements and must declare scope, version and denominator.

## Validation State

Permanent canonical validation:

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

Phase 5.3.3 Windows/Sysmon validation includes:

- real reference-host collection workflow and parser checks;
- Sysmon docs live canary;
- Windows 4688 docs live canary;
- Windows provider metadata parser tests;
- Sysmon schema parser and historical-format tests;
- Windows/Sysmon inventory reconciliation tests;
- structural normalizer tests;
- Encyclopedia acceptance tests;
- three-layer inventory diff tests.

Post-merge `main@84d125c61051442c509a701c2d6bc6ffb85a9090` passed Foundation Hygiene run `33973584356`.

## Known Risks / Blockers

- Branch protection is not enabled on the current private repository; procedural PR/CI/architecture gates are mandatory.
- Exact storage/graph/search implementation remains intentionally open.
- Pack-signing/key-management design remains open.
- Parser sandbox technology remains open.
- Formal cross-language canonical JSON/hash standard remains open if later runtime languages require it; do not assume RFC 8785/JCS today.
- Phase 5.3.4 still must complete D3FEND/CAR/DefenseOps ingestion and final promotion scenarios before Phase 5.3 can be declared complete.

## Last Architecture Sync

- Architecture Sync Date: 2026-09-05
- Architecture Authority: Atlas Architecture / Product / Data / Security Design workspace
- Architecture Sync Status: **GREEN**
- Stage 1: **APPROVED AND MERGED**
- Phase 5.2: **APPROVED AND MERGED**
- Phase 5.3 Architecture: **APPROVED**
- Phase 5.3.1: **COMPLETE / MERGED**
- Phase 5.3.2: **COMPLETE / MERGED**
- Phase 5.3.3: **COMPLETE / MERGED**
- Phase 5.3.3 PR: `#8`
- Phase 5.3.3 Merge Commit: `84d125c61051442c509a701c2d6bc6ffb85a9090`
- Phase 5.3.3 Post-Merge Main CI: **GREEN** — run `33973584356`
- Next Slice: **Phase 5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates**
