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

Feature-branch status: **READY FOR ARCHITECTURE REVIEW — REVISION 2**

Authoritative `main` status: **NOT STARTED / NOT MERGED**

Phase 5.2 scope:

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

Phase 5.1 legacy schemas remain preserved. Phase 5.2 does not authorize production ingestion or implementation of Desktop/Web/storage/search/graph/Detection IR.

## Phase 5.3 — Source & Ingestion Core

Status: **NOT STARTED**

Initial authoritative sources:

- Microsoft Windows event documentation;
- Microsoft Sysinternals Sysmon;
- MITRE ATT&CK;
- selected MITRE D3FEND/CAR relationships;
- DefenseOps validated content through an explicit ingestion contract.

Required controlled flow:

```text
Official Source
        ↓
Raw Snapshot
        ↓
Parser
        ↓
Normalizer
        ↓
Schema Validation
        ↓
Inventory Diff
        ↓
Tests
        ↓
Human Review
        ↓
Signed Content Pack
        ↓
Release
```

No upstream source may directly mutate the production/public Atlas dataset.

## Phase 5.4 — Deterministic Search Core

Status: **NOT STARTED**

- exact resolver;
- lexical index;
- structured filters;
- graph traversal;
- ranking;
- benchmarks;
- universal identifier resolution.

Exact identifier matches must precede semantic retrieval.

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
