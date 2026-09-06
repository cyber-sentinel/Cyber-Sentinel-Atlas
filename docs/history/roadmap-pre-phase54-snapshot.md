# Cyber-Sentinel-Atlas Roadmap

## Phase 5.1 — Product Foundation

Status: **COMPLETE**

Completed foundation:

- product vision;
- positioning;
- personas;
- knowledge graph foundation;
- claim-level provenance;
- search architecture;
- AI/RAG boundaries;
- offline-first architecture;
- API/CLI direction;
- security architecture;
- UX;
- MVP scope;
- ADR foundation;
- foundation CI.

## Stage 1 — Governance / Architecture Sync

Status: **COMPLETE**

Completed synchronization:

- project-state control;
- Atlas / DefenseOps / Forge ownership;
- canonical identifier architecture;
- shared-core/interface sequencing;
- universal telemetry taxonomy;
- coverage architecture;
- controlled content release pipeline;
- legacy/current telemetry lifecycle;
- ADR-0004 through ADR-0010 accepted and merged.

## Phase 5.2 — Canonical Data Model

Status: **COMPLETE**

Phase 5.2 delivered:

- production JSON Schema Draft 2020-12 contracts;
- seven first-class Atlas record families;
- canonical identifier conventions;
- native identifier model;
- aliases and scoped search identifiers;
- telemetry provider/source/record taxonomy;
- claim and evidence model;
- relationship model and typed referential integrity;
- lifecycle/applicability model;
- SourceRecord / source registry schema basis;
- CoverageSnapshot model with explicit numerator basis;
- ValidationRecord and VersionRecord;
- controlled registries;
- schema versioning and migration strategy;
- explicit Phase 5.1 → v1 migration inventory;
- cross-domain schema fixtures;
- deterministic canonical validation and invariant tests.

Schema v1 canonical URI base:

```text
https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/
```

Phase 5.1 legacy schemas remain preserved. Phase 5.2 does not authorize implementation of Desktop/Web/storage/search/graph/Detection IR.

## Phase 5.3 — Source & Ingestion Core

Status: **COMPLETE / MERGED**

Phase 5.3 transforms controlled source acquisitions into reviewed canonical candidate builds and terminates at `PACK_READY`. It does not implement signed pack runtime, client installation, runtime rollback, final pack signing, archive-format or key-management decisions.

### Phase 5.3.1 — Ingestion Foundation / Contracts

Status: **COMPLETE / MERGED**

Delivered:

- independent Ingestion Contract Version 1.0.0 under `schemas/ingestion/v1/`;
- SourceConnectorDefinition and acquisition/run contracts;
- immutable RawSnapshot/content-addressing contract;
- ParserDefinition, ParserRun and ParsedSourceRecord/PSR contracts;
- NormalizerDefinition, NormalizationRun and NormalizationLineage contracts;
- authoritative inventory and three-layer diff contracts;
- G1–G15 BuildValidationReport contract;
- digest-bound ReviewDecision and CanonicalBuildManifest contracts;
- public-source acquisition security boundaries;
- synthetic deterministic fixtures;
- permanent ingestion validator and invariant/security tests;
- ADR-0016 through ADR-0020.

### Phase 5.3.2 — MITRE ATT&CK Structured-Source Canary

Status: **COMPLETE / MERGED**

PR: `#6`

Merge commit: `baaf72a8f7596f701bb49af6cad02460064e416f`

Delivered:

- official Enterprise ATT&CK release `19.2` pinned to upstream commit `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`;
- exact HTTPS source/release binding and fail-closed implementation authorization;
- deterministic STIX 2.1 parser and source-native PSR;
- deterministic normalizer and versioned mapping profile;
- unknown-field preservation and drift diagnostics;
- ambiguous identity quarantine;
- ATT&CK lifecycle mapping without disappearance-as-removal semantics;
- Phase 5.3.1-compatible PSR and RawSnapshot identities;
- small deterministic repository fixture;
- transient full-source live CI canary without committing the upstream corpus;
- canonical schema v1 preserved unchanged.

Phase 5.3.2 proves the ingestion architecture; it is not a released content pack and does not declare global ATT&CK completeness.

### Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline

Status: **COMPLETE / MERGED**

PR: `#8`

Merge commit: `84d125c61051442c509a701c2d6bc6ffb85a9090`

Post-merge main CI: Foundation Hygiene run `33973584356` — **SUCCESS**.

Delivered:

- separate Windows documentation and provider-inventory authority dimensions;
- separate Sysmon documentation and schema-export authority dimensions;
- controlled out-of-band ReferenceExport contract; Atlas core does not execute Windows/Sysmon binaries to generate inventory;
- real controlled Windows Server 2025 Datacenter 24H2 build `26100.33296` provider export;
- Windows provider inventory with 488 event/version definitions and 423 unique Event IDs;
- Event `4688` observed in the declared current provider scope; historical `592` not observed and explicitly preserved as an independent legacy identity;
- real Sysmon `15.21` `-s all` schema export with 24 schema manifests, 587 parsed event records, current schema `4.91`, and 30 current Event IDs (`1`..`29`, `255`);
- deterministic Windows provider and Sysmon schema parsers;
- deterministic structural normalizers producing canonical identity shells without inferring unsupported global lifecycle;
- lossless handling of historical Sysmon decimal binary versions and hexadecimal Event IDs;
- documentation/provider/schema reconciliation with independent completeness denominators;
- `NOT_OBSERVED != REMOVED` enforced;
- provider-scoped Event-ID identity and collision safety preserved;
- production-like deterministic acceptance cases for `4688`, independent legacy `592`, and `sysmon 1`;
- initial three-layer Raw / Parsed / Canonical inventory diffs for declared Windows/Sysmon scopes;
- live ATT&CK, Sysmon documentation and Windows 4688 documentation CI canaries all green;
- canonical `schemas/v1` preserved unchanged.

Phase 5.3.3 validates the Encyclopedia ingestion acceptance domain. It is not a released/signed content pack and does not claim global Windows/Sysmon historical completeness.

### Phase 5.3.4 — D3FEND/CAR + DefenseOps Contract + Final Promotion Gates

Status: **COMPLETE / MERGED**

PR: `#11`

Final reviewed head: `58b15b0e001427ea7ff8b67b20100f4f4d1e3eee`

Merge commit: `7270ba54dbcceb3460e922e82bb3fb20bf149f29`

Post-merge main validation:

- Foundation Hygiene run `33977610969` — **SUCCESS**;
- Phase 5.3.4 Canaries run `33977610961` — **SUCCESS**.

Delivered:

- D3FEND official-source connector and deterministic ingestion path pinned to ontology `1.6.0` and exact official SHA-256 `sha256-4909a5bb66b75d2c359624398848936fb56a6b246bcd5cfcd277977a1277753a`;
- bounded deterministic preservation of relevant RDF blank-node structures with cycle/size fail-closed behavior;
- D3FEND live canary over the pinned official source: 3,862,115 bytes, 272 PSR records, 544 canonical candidate records;
- CAR official structured repository canary pinned to commit `1b922fe1527d956e222a99473472e594f10f610b` and sample Git blob `b0f899e2875d4469ac58838dcb77db59e4feee96`;
- CAR live canary for `CAR-2016-03-001` producing two canonical candidate records;
- DefenseOps explicit validated engineering export schema/parser/normalizer contract pinned to commit `daa879b5eede5f09651468c16ed3acc50596b2fc` (`v0.1.0`);
- provenance, source-tier, validation, applicability, telemetry-requirement and licensing metadata boundary for DefenseOps-derived content;
- strict rule that DefenseOps origin does not automatically imply authoritative canonical truth;
- repository-level DefenseOps license state intentionally remains unknown, with G14 publication fail-closed;
- final deterministic G1–G15 validation and human-review promotion scenarios;
- immutable candidate/review/promotion digest bindings;
- high-risk four-eyes approval semantics;
- stale-review rejection;
- successful fixture-only Phase 5.3 terminal `PACK_READY` state without implementing signed pack runtime;
- failed/quarantined/rejected builds preserve Last Known Good;
- no Detection IR implementation;
- canonical `schemas/v1` preserved unchanged.

Phase 5.3 is complete. No upstream source directly mutates the production/public Atlas dataset, and no signed content pack has been released or installed.

## Phase 5.4 — Deterministic Search Core

Status: **NEXT / ARCHITECTURE GATE**

Architecture gate objectives:

- deterministic identifier parser/resolver contracts;
- exact native identifier lookup before lexical or semantic retrieval;
- provider/namespace-scoped collision disambiguation;
- scoped aliases after exact identifier resolution;
- lexical index and deterministic ranking;
- structured filters and provider catalogs;
- graph traversal/search pivots;
- legacy/current lifecycle browsing;
- numeric provider-scoped Event ID ordering where the registry declares numeric semantics;
- reproducible benchmarks and acceptance corpus;
- derived search projections kept separate from canonical knowledge records.

Required precedence:

```text
Exact Native Identifier
        ↓
Scoped Identifier
        ↓
Scoped Alias
        ↓
Lexical Match
        ↓
Semantic Retrieval (optional/later)
```

Examples that must be accepted by the product contract include `4688`, `sysmon 1`, `windows 4688`, `T1059`, `kubectl exec`, `CreateAccessKey`, `FileAccessed`, `EXECVE`, and `exec_start`.

A bare numeric query must never select an arbitrary provider when multiple namespaces collide. It must return a deterministic disambiguation set unless scope resolves the identity uniquely.

The search engine/storage/index implementation remains an open technology decision. No engine is frozen until the Phase 5.4 implementation spike and ADR compare candidates against deterministic behavior, offline deployment, performance, footprint, indexing, migration and portability requirements.

## Phase 5.5 — Offline Pack Runtime / Shared Core

Status: **NOT STARTED**

- pack manifest;
- signed/checksummed updates;
- schema/compatibility verification;
- embedded local data access;
- deterministic local search;
- last-known-good preservation;
- atomic installation;
- health checks;
- automatic rollback;
- shared contracts for Desktop, Web/PWA, API, and CLI.

Exact pack names remain an open decision.

## Phase 5.6 — Windows Desktop MVP

Status: **NOT STARTED**

First full end-user interface.

Requirements:

- fast offline lookup;
- exact identifier resolution;
- lexical search;
- local canonical dataset;
- relationship navigation;
- provenance visibility;
- no mandatory Internet connection;
- signed pack updates;
- safe rollback;
- portable Windows mode evaluation.

Technology stack selection requires an implementation spike and dedicated ADR.

## Phase 5.7 — Web / PWA

Status: **NOT STARTED**

Build on the same canonical model and shared runtime/contracts.

- global search;
- entity pages;
- relationship navigation;
- source/evidence panel;
- responsive dark/light UI;
- offline-capable experience where technically appropriate.

## Phase 5.8 — API / CLI

Status: **NOT STARTED**

- versioned read API;
- search;
- graph;
- sources;
- packs;
- official `atlas` CLI.

## Phase 5.9 — Grounded AI

Status: **NOT STARTED**

Only after deterministic retrieval and provenance are mature:

- entity-aware Q&A;
- evidence-grounded explanations;
- investigation pivots;
- cited summaries;
- optional offline model path later.

AI does not become the canonical source of truth.

## Phase 5.10 — Public Preview Readiness

Status: **NOT STARTED**

- security review;
- licensing/source redistribution review;
- performance;
- accessibility;
- contributor workflow;
- source freshness monitoring;
- signed release process;
- public documentation;
- launch criteria.

## Expansion After MVP

The universal model should support future:

- Linux;
- macOS;
- Exchange;
- SharePoint;
- Microsoft 365;
- Azure / Entra ID;
- AWS;
- Google Cloud;
- Docker / containerd / CRI-O;
- Kubernetes / OpenShift;
- DevOps / CI-CD;
- SQL Server;
- PostgreSQL / pgAudit;
- MySQL / MariaDB;
- MongoDB;
- Oracle;
- Redis;
- managed cloud databases;
- LOLBAS;
- GTFOBins;
- broader DFIR/IR/deception content.

Architecture support does not imply MVP ingestion of all domains.
