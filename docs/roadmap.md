# Cyber-Sentinel-Atlas Roadmap

## Phase 5.1 — Product Foundation

Status: **COMPLETE**

## Stage 1 — Governance / Architecture Sync

Status: **COMPLETE**

Accepted architecture includes ADR-0001 through ADR-0010.

## Phase 5.2 — Canonical Data Model

Status on feature branch: **IN PROGRESS**

Implementation scope on the feature branch:

- production JSON Schema Draft 2020-12 contracts;
- AtlasRecord root union;
- EntityRecord / ClaimRecord / RelationshipRecord;
- SourceRecord / ValidationRecord / VersionRecord / CoverageSnapshot;
- common record envelope;
- canonical identifier component validation;
- native identifier and alias models;
- controlled registries;
- universal telemetry entity vocabulary;
- lifecycle/curation separation;
- applicability/version contracts;
- namespaced extensions;
- deterministic Claim/Relationship IDs;
- source/provenance evidence contracts;
- referential integrity;
- Phase 5.1 migration inventory;
- cross-domain model fixtures;
- exact-resolution tests;
- CI validation.

Phase 5.2 remains unmerged until Architecture Authority approval.

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

Only after deterministic retrieval and provenance are mature.

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

The universal model supports future schema representation for Linux, macOS, Microsoft 365, Azure, AWS, Google Cloud, containers, Kubernetes/OpenShift, DevOps/CI-CD, databases, LOLBAS, GTFOBins, and broader DFIR/IR/deception.

Architecture support does not authorize production ingestion during Phase 5.2.
